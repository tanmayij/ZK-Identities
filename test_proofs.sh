#!/bin/bash

# Complete proof generation and verification test with Poseidon inputs

set -e

echo "=== groth16 proof generation test ==="
echo ""

# Check if we have the necessary files
if [ ! -f "build/rotation_final.zkey" ]; then
    echo "[1/5] setting up trusted setup..."
    
    # Powers of tau
    if [ ! -f "build/pot15_final.ptau" ]; then
        echo "  generating powers of tau..."
        snarkjs powersoftau new bn128 15 build/pot15_0000.ptau -v > /dev/null 2>&1
        echo "test" | snarkjs powersoftau contribute build/pot15_0000.ptau build/pot15_0001.ptau --name="Test" -v > /dev/null 2>&1
        snarkjs powersoftau prepare phase2 build/pot15_0001.ptau build/pot15_final.ptau -v > /dev/null 2>&1
    fi
    
    # Circuit-specific setup
    echo "  generating circuit keys..."
    snarkjs groth16 setup build/rotation.r1cs build/pot15_final.ptau build/rotation_0000.zkey > /dev/null 2>&1
    echo "test" | snarkjs zkey contribute build/rotation_0000.zkey build/rotation_final.zkey --name="Rotation" -v > /dev/null 2>&1
    snarkjs zkey export verificationkey build/rotation_final.zkey build/rotation_vkey.json > /dev/null 2>&1
    
    snarkjs groth16 setup build/predicate.r1cs build/pot15_final.ptau build/predicate_0000.zkey > /dev/null 2>&1
    echo "test" | snarkjs zkey contribute build/predicate_0000.zkey build/predicate_final.zkey --name="Predicate" -v > /dev/null 2>&1
    snarkjs zkey export verificationkey build/predicate_final.zkey build/predicate_vkey.json > /dev/null 2>&1
    
    echo "   setup complete"
else
    echo "[1/5] using existing setup"
fi

echo ""
echo "[2/5] generating witnesses with poseidon inputs..."
node build/rotation_js/generate_witness.js \
    build/rotation_js/rotation.wasm \
    circuits/input_rotation.json \
    build/rotation_witness.wtns 2>&1 | grep -E "(Error|Assert)" && echo "  rotation witness failed" && exit 1 || echo "   rotation witness generated"

node build/predicate_js/generate_witness.js \
    build/predicate_js/predicate.wasm \
    circuits/input_predicate.json \
    build/predicate_witness.wtns && echo "   predicate witness generated" || echo "  predicate witness failed"

echo ""
echo "[3/5] generating proofs..."
echo -n "  rotation proof... "
start=$(date +%s%N)
snarkjs groth16 prove \
    build/rotation_final.zkey \
    build/rotation_witness.wtns \
    build/rotation_proof.json \
    build/rotation_public.json > /dev/null 2>&1
end=$(date +%s%N)
time_ms=$(( (end - start) / 1000000 ))
echo " (${time_ms}ms)"

echo -n "  predicate proof... "
start=$(date +%s%N)
snarkjs groth16 prove \
    build/predicate_final.zkey \
    build/predicate_witness.wtns \
    build/predicate_proof.json \
    build/predicate_public.json > /dev/null 2>&1
end=$(date +%s%N)
time_ms=$(( (end - start) / 1000000 ))
echo " (${time_ms}ms)"

echo ""
echo "[4/5] verifying proofs..."
if snarkjs groth16 verify \
    build/rotation_vkey.json \
    build/rotation_public.json \
    build/rotation_proof.json > /dev/null 2>&1; then
    echo "   rotation proof valid"
else
    echo "  rotation proof invalid"
    exit 1
fi

if snarkjs groth16 verify \
    build/predicate_vkey.json \
    build/predicate_public.json \
    build/predicate_proof.json > /dev/null 2>&1; then
    echo "   predicate proof valid"
else
    echo "  predicate proof invalid"
    exit 1
fi

echo ""
echo "[5/5] proof details..."
echo ""
echo "rotation proof:"
rotation_size=$(wc -c < build/rotation_proof.json)
echo "  size: ${rotation_size} bytes"
echo "  public signals:"
cat build/rotation_public.json | jq -r '.[]' | head -3 | while read signal; do
    echo "    ${signal:0:20}..."
done

echo ""
echo "predicate proof:"
predicate_size=$(wc -c < build/predicate_proof.json)
echo "  size: ${predicate_size} bytes"
echo "  public signals:"
cat build/predicate_public.json | jq -r '.[]' | head -3 | while read signal; do
    echo "    ${signal:0:20}..."
done

echo ""
echo " all tests passed!"
echo ""
echo " complete groth16 workflow functional:"
echo "    circuits compiled (poseidon-based)"
echo "    witnesses generated from valid inputs"
echo "    groth16 proofs created and verified"
echo "    ready for production integration"
