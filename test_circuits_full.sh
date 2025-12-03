#!/bin/bash

# Test script for Read-Verify-Rotate circuits
# This script compiles circuits, generates proofs, and verifies them

set -e

echo "=== read-verify-rotate circuit testing ==="
echo ""

# Check dependencies
check_deps() {
    echo "[1/6] checking dependencies..."
    
    if ! command -v circom &> /dev/null; then
        echo "   circom not found. install from: https://docs.circom.io/getting-started/installation/"
        exit 1
    fi
    
    if ! command -v snarkjs &> /dev/null; then
        echo "   snarkjs not found. run: npm install -g snarkjs"
        exit 1
    fi
    
    if [ ! -d "node_modules/circomlib" ]; then
        echo "   circomlib not found. run: npm install circomlib"
        exit 1
    fi
    
    echo "   all dependencies found"
}

# Compile circuits
compile_circuits() {
    echo ""
    echo "[2/6] compiling circuits..."
    
    # Compile rotation circuit
    echo "  compiling rotation.circom..."
    circom circuits/rotation.circom --r1cs --wasm --sym -o build/ 2>&1 | grep -E "(circuit|template|constraints|wires)" || true
    
    # Compile predicate circuit
    echo "  compiling predicate.circom..."
    circom circuits/predicate.circom --r1cs --wasm --sym -o build/ 2>&1 | grep -E "(circuit|template|constraints|wires)" || true
    
    echo "   circuits compiled"
}

# Setup phase (powers of tau)
setup_phase() {
    echo ""
    echo "[3/6] setting up trusted setup..."
    
    if [ ! -f "build/pot15_final.ptau" ]; then
        echo "  generating powers of tau (this may take a few minutes)..."
        
        # Start new ceremony (increased to 15 for larger circuits: 2^15 = 32768 constraints)
        snarkjs powersoftau new bn128 15 build/pot15_0000.ptau -v > /dev/null 2>&1
        
        # Contribute randomness
        echo "test contribution" | snarkjs powersoftau contribute build/pot15_0000.ptau build/pot15_0001.ptau --name="Test" -v > /dev/null 2>&1
        
        # Prepare phase 2
        snarkjs powersoftau prepare phase2 build/pot15_0001.ptau build/pot15_final.ptau -v > /dev/null 2>&1
        
        echo "   powers of tau ceremony complete"
    else
        echo "   using existing powers of tau"
    fi
    
    # Circuit-specific setup for rotation
    if [ ! -f "build/rotation_final.zkey" ]; then
        echo "  generating rotation circuit keys..."
        snarkjs groth16 setup build/rotation.r1cs build/pot15_final.ptau build/rotation_0000.zkey > /dev/null 2>&1
        echo "test contribution" | snarkjs zkey contribute build/rotation_0000.zkey build/rotation_final.zkey --name="Rotation" -v > /dev/null 2>&1
        snarkjs zkey export verificationkey build/rotation_final.zkey build/rotation_vkey.json > /dev/null 2>&1
        echo "  ✓ rotation keys generated"
    else
        echo "  ✓ using existing rotation keys"
    fi
    
    # Circuit-specific setup for predicate
    if [ ! -f "build/predicate_final.zkey" ]; then
        echo "  generating predicate circuit keys..."
        snarkjs groth16 setup build/predicate.r1cs build/pot15_final.ptau build/predicate_0000.zkey > /dev/null 2>&1
        echo "test contribution" | snarkjs zkey contribute build/predicate_0000.zkey build/predicate_final.zkey --name="Predicate" -v > /dev/null 2>&1
        snarkjs zkey export verificationkey build/predicate_final.zkey build/predicate_vkey.json > /dev/null 2>&1
        echo "  ✓ predicate keys generated"
    else
        echo "  ✓ using existing predicate keys"
    fi
}

# Generate witnesses
generate_witnesses() {
    echo ""
    echo "[4/6] generating witnesses..."
    
    # Rotation witness
    echo "  generating rotation witness..."
    node build/rotation_js/generate_witness.js \
        build/rotation_js/rotation.wasm \
        circuits/input_rotation.json \
        build/rotation_witness.wtns > /dev/null 2>&1
    echo "   rotation witness generated"
    
    # Predicate witness
    echo "  generating predicate witness..."
    node build/predicate_js/generate_witness.js \
        build/predicate_js/predicate.wasm \
        circuits/input_predicate.json \
        build/predicate_witness.wtns > /dev/null 2>&1
    echo "   predicate witness generated"
}

# Generate proofs
generate_proofs() {
    echo ""
    echo "[5/6] generating proofs..."
    
    # Rotation proof
    echo "  generating rotation proof..."
    start_time=$(date +%s%N)
    snarkjs groth16 prove \
        build/rotation_final.zkey \
        build/rotation_witness.wtns \
        build/rotation_proof.json \
        build/rotation_public.json > /dev/null 2>&1
    end_time=$(date +%s%N)
    rotation_time=$(( (end_time - start_time) / 1000000 ))
    echo "   rotation proof generated (${rotation_time}ms)"
    
    # Predicate proof
    echo "  generating predicate proof..."
    start_time=$(date +%s%N)
    snarkjs groth16 prove \
        build/predicate_final.zkey \
        build/predicate_witness.wtns \
        build/predicate_proof.json \
        build/predicate_public.json > /dev/null 2>&1
    end_time=$(date +%s%N)
    predicate_time=$(( (end_time - start_time) / 1000000 ))
    echo "   predicate proof generated (${predicate_time}ms)"
}

# Verify proofs
verify_proofs() {
    echo ""
    echo "[6/6] verifying proofs..."
    
    # Verify rotation
    echo "  verifying rotation proof..."
    if snarkjs groth16 verify \
        build/rotation_vkey.json \
        build/rotation_public.json \
        build/rotation_proof.json > /dev/null 2>&1; then
        echo "   rotation proof valid"
    else
        echo "   rotation proof invalid"
        exit 1
    fi
    
    # Verify predicate
    echo "  verifying predicate proof..."
    if snarkjs groth16 verify \
        build/predicate_vkey.json \
        build/predicate_public.json \
        build/predicate_proof.json > /dev/null 2>&1; then
        echo "   predicate proof valid"
    else
        echo "   predicate proof invalid"
        exit 1
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "=== test summary ==="
    echo ""
    
    # Circuit stats
    echo "circuit statistics:"
    if [ -f "build/rotation.r1cs" ]; then
        rotation_constraints=$(snarkjs r1cs info build/rotation.r1cs 2>&1 | grep "# of Constraints" | awk '{print $NF}')
        rotation_wires=$(snarkjs r1cs info build/rotation.r1cs 2>&1 | grep "# of Wires" | awk '{print $NF}')
        echo "  rotation circuit: ${rotation_constraints} constraints, ${rotation_wires} wires"
    fi
    
    if [ -f "build/predicate.r1cs" ]; then
        predicate_constraints=$(snarkjs r1cs info build/predicate.r1cs 2>&1 | grep "# of Constraints" | awk '{print $NF}')
        predicate_wires=$(snarkjs r1cs info build/predicate.r1cs 2>&1 | grep "# of Wires" | awk '{print $NF}')
        echo "  predicate circuit: ${predicate_constraints} constraints, ${predicate_wires} wires"
    fi
    
    echo ""
    echo "proof sizes:"
    if [ -f "build/rotation_proof.json" ]; then
        rotation_size=$(wc -c < build/rotation_proof.json)
        echo "  rotation proof: ${rotation_size} bytes"
    fi
    
    if [ -f "build/predicate_proof.json" ]; then
        predicate_size=$(wc -c < build/predicate_proof.json)
        echo "  predicate proof: ${predicate_size} bytes"
    fi
    
    echo ""
    echo " all tests passed"
}

# Main execution
mkdir -p build

check_deps
compile_circuits
setup_phase
generate_witnesses
generate_proofs
verify_proofs
print_summary
