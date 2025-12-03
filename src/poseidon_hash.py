"""
Poseidon Hash Integration for Python

Provides Poseidon hash computation by calling Node.js subprocess.
This bridges the gap between Python code and circomlibjs Poseidon implementation.
"""

import subprocess
import json
from typing import List, Tuple
from pathlib import Path

# path to the Node.js bridge script (in project root)
BRIDGE_SCRIPT = Path(__file__).parent.parent / "poseidon_bridge.js"


class PoseidonHash:
    """Poseidon hash implementation via Node.js bridge."""
    
    @staticmethod
    def _run_bridge(command: str, args: List[str]) -> str:
        """Run poseidon_bridge.js with given command and arguments."""
        cmd = ["node", str(BRIDGE_SCRIPT), command] + args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Poseidon bridge error: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Poseidon bridge timeout")
    
    @staticmethod
    def hash(*inputs: int) -> bytes:
        """
        Hash multiple inputs with Poseidon.
        
        Args:
            *inputs: Variable number of integer inputs
            
        Returns:
            32-byte hash digest
        """
        args = [str(x) for x in inputs]
        hex_result = PoseidonHash._run_bridge("hash", args)
        return bytes.fromhex(hex_result[2:])  # Remove '0x' prefix
    
    @staticmethod
    def compute_inner_root(attributes: List[int], salts: List[bytes]) -> bytes:
        """
        Compute inner Merkle root from attributes and salts.
        
        Args:
            attributes: List of 8 integer attributes
            salts: List of 8 salt values (32 bytes each)
            
        Returns:
            32-byte Merkle root
        """
        # Convert attributes and salts to hex strings
        attr_args = [str(attr) for attr in attributes]
        salt_args = ['0x' + salt.hex() for salt in salts]
        
        args = attr_args + salt_args
        hex_result = PoseidonHash._run_bridge("inner_root", args)
        return bytes.fromhex(hex_result[2:])
    
    @staticmethod
    def compute_nullifier(inner_root: bytes, salt: bytes) -> bytes:
        """
        Compute nullifier from inner root and salt.
        
        Args:
            inner_root: 32-byte inner Merkle root
            salt: 32-byte salt value
            
        Returns:
            32-byte nullifier
        """
        args = ['0x' + inner_root.hex(), '0x' + salt.hex()]
        hex_result = PoseidonHash._run_bridge("nullifier", args)
        return bytes.fromhex(hex_result[2:])
    
    @staticmethod
    def compute_merkle_root(leaves: List[bytes]) -> bytes:
        """
        Compute Merkle root from leaf hashes.
        
        Args:
            leaves: List of 32-byte leaf hashes
            
        Returns:
            32-byte Merkle root
        """
        args = ['0x' + leaf.hex() for leaf in leaves]
        hex_result = PoseidonHash._run_bridge("merkle_root", args)
        return bytes.fromhex(hex_result[2:])
    
    @staticmethod
    def compute_all_paths(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]], List[List[int]]]:
        """Compute root and authentication paths for all leaves."""
        args = ['0x' + leaf.hex() for leaf in leaves]
        json_result = PoseidonHash._run_bridge("merkle_paths", args)
        result = json.loads(json_result)

        root = bytes.fromhex(result["root"][2:])
        path_elements = [
            [bytes.fromhex(elem[2:]) for elem in leaf_path]
            for leaf_path in result["pathElements"]
        ]
        path_indices = result["pathIndices"]

        return root, path_elements, path_indices

    @staticmethod
    def get_merkle_path(leaf_index: int, leaves: List[bytes]) -> Tuple[bytes, List[bytes], List[int]]:
        """
        Get Merkle path for a specific leaf.
        
        Args:
            leaf_index: Index of the leaf
            leaves: List of all leaf hashes
            
        Returns:
            (root, path_elements, path_indices)
        """
        args = [str(leaf_index)] + ['0x' + leaf.hex() for leaf in leaves]
        json_result = PoseidonHash._run_bridge("merkle_path", args)
        
        result = json.loads(json_result)
        root = bytes.fromhex(result['root'][2:])
        path_elements = [bytes.fromhex(p[2:]) for p in result['pathElements']]
        path_indices = result['pathIndices']
        
        return root, path_elements, path_indices


# Convenience functions
def poseidon_hash(*inputs: int) -> bytes:
    """Compute Poseidon hash of inputs."""
    return PoseidonHash.hash(*inputs)


def compute_inner_merkle_root(attributes: List[int], salts: List[bytes]) -> bytes:
    """Compute inner Merkle root using Poseidon."""
    return PoseidonHash.compute_inner_root(attributes, salts)


def compute_poseidon_nullifier(inner_root: bytes, salt: bytes) -> bytes:
    """Compute nullifier using Poseidon."""
    return PoseidonHash.compute_nullifier(inner_root, salt)


if __name__ == "__main__":
    # Test the bridge
    print("Testing Poseidon bridge...")
    
    # Test 1: Simple hash
    print("\n1. Simple hash:")
    h = poseidon_hash(1, 2)
    print(f"   Poseidon(1, 2) = 0x{h.hex()}")
    
    # Test 2: Inner root
    print("\n2. Inner Merkle root:")
    import secrets
    attrs = [25, 1, 42, 100, 5, 999, 12345, 7]
    salts = [secrets.token_bytes(32) for _ in range(8)]
    root = compute_inner_merkle_root(attrs, salts)
    print(f"   Root = 0x{root.hex()[:32]}...")
    
    # Test 3: Nullifier
    print("\n3. Nullifier:")
    nullifier = compute_poseidon_nullifier(root, salts[0])
    print(f"   Nullifier = 0x{nullifier.hex()[:32]}...")
    
    print("\n All tests passed!")
