#!/bin/bash

# Quick setup script using uv
# This script sets up the complete development environment for the zk-identities project

set -e

echo "=== zk-identities project setup ==="
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo " uv not found. Install it with:"
    echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "[1/4] creating virtual environment..."
python3 -m venv python_

echo "[2/4] installing python dependencies with uv..."
uv pip install pandas pyarrow pydantic cryptography faker --python python_/bin/python

echo "[3/4] checking optional dependencies for read-verify-rotate..."
if ! command -v circom &> /dev/null; then
    echo "  circom not found (not really optional, needed for groth16 circuits)"
    echo "      install from: https://docs.circom.io/getting-started/installation/"
else
    echo "   circom found"
fi

if ! command -v snarkjs &> /dev/null; then
    echo "  snarkjs not found (not really optional, needed for groth16 proofs)"
    echo "      install with: npm install -g snarkjs"
else
    echo "   snarkjs found"
fi

if [ ! -d "node_modules/circomlib" ]; then
    echo "    circomlib not found (not really optional, needed for groth16 circuits)"
    echo "      install with: npm install circomlib"
else
    echo "   circomlib found"
fi

echo ""
echo "[4/4] setup complete!"
echo ""
echo " ready to use. try:"
echo "   python_/bin/python src/complete_flow.py          # original identity verification"
echo "   python_/bin/python src/demo_encrypted_db.py      # schnorr-based encrypted db"
echo "   python src/batch_fetch_client.py                  # groth16 client demo"
echo "   ./test_circuits.sh                                # test groth16 circuits (requires circom/snarkjs)"
