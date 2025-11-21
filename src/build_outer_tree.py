"""
Step 5: Build outer (global) Merkle tree from all user inner roots.

This script:
1. Reads all inner_roots from inner_roots.parquet
2. Builds a global Merkle tree (one leaf per user)
3. Generates issuer signing key (Ed25519)
4. Signs the global root
5. Outputs:
   - artifacts/global_root.json (root + metadata)
   - artifacts/issuer_key.pem (private key)
   - artifacts/issuer_public_key.pem (public key)
   - artifacts/issuer_root.sig (signature)
   - artifacts/outer_tree_paths.parquet (Merkle paths for each user)
"""

import pandas as pd
import json
from pathlib import Path
from datetime import datetime
import sys
sys.path.append(str(Path(__file__).parent))

from zkid.crypto import hash_leaf, hash_internal
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def next_power_of_2(n):
    """Return the smallest power of 2 >= n."""
    if n == 0:
        return 1
    power = 1
    while power < n:
        power *= 2
    return power

def build_merkle_tree(leaves):
    """
    Build a balanced Merkle tree from leaves, padding to power of 2.
    
    Returns:
        root: bytes (root hash)
        tree_levels: list of lists, where tree_levels[0] = leaves, tree_levels[-1] = [root]
    """
    if not leaves:
        raise ValueError("Cannot build tree from empty leaves")

    target_size = next_power_of_2(len(leaves))
    padded_leaves = leaves + [leaves[-1]] * (target_size - len(leaves))
    tree_levels = [padded_leaves]
    current_level = padded_leaves
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            parent = hash_internal(left, right)
            next_level.append(parent)
        tree_levels.append(next_level)
        current_level = next_level
    
    root = tree_levels[-1][0]
    return root, tree_levels

def get_auth_path(leaf_index, tree_levels):
    """
    Compute Merkle authentication path for a leaf.
    
    Returns list of (sibling_hash, is_right) tuples for path from leaf to root.
    """
    path = []
    index = leaf_index
    
    for level in tree_levels[:-1]:  
        if index % 2 == 0:
            #We're left child, sibling is right
            sibling_index = index + 1
            is_right = True
        else:
            #We're right child, sibling is left
            sibling_index = index - 1
            is_right = False
        
        sibling = level[sibling_index]
        path.append({
            "sibling": sibling.hex(),
            "is_right": is_right
        })
        
        #Move up to parent level
        index = index // 2
    
    return path

def generate_issuer_keypair():
    """
    Generate Ed25519 keypair for issuer signature.
    
    Returns (private_key, public_key)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def save_keypair(private_key, public_key, 
                 private_path="artifacts/issuer_key.pem",
                 public_path="artifacts/issuer_public_key.pem"):
    """Save keypair to PEM files."""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_path, 'wb') as f:
        f.write(private_pem)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, 'wb') as f:
        f.write(public_pem)
    
    print(f"Issuer private key saved to {private_path}")
    print(f"Issuer public key saved to {public_path}")

def main(input_parquet="artifacts/inner_roots.parquet",
         output_json="artifacts/global_root.json",
         output_sig="artifacts/issuer_root.sig",
         output_paths="artifacts/outer_tree_paths.parquet"):
    """
    Main function to build outer tree and sign global root.
    """
    print(f"Reading inner roots from {input_parquet}...")
    df = pd.read_parquet(input_parquet)
    user_roots = df[['ID', 'inner_root']].drop_duplicates().sort_values('ID')
    print(f"Loaded {len(user_roots)} unique users")
    
    #Build outer tree leaves: hash(user_id || inner_root)
    print("\nBuilding outer Merkle tree...")
    leaves_data = []
    leaves = []
    
    for idx, row in user_roots.iterrows():
        user_id = row['ID']
        inner_root_hex = row['inner_root']
        inner_root_bytes = bytes.fromhex(inner_root_hex)
       
        user_id_bytes = str(user_id).encode('utf-8')
        leaf_data = user_id_bytes + b"||" + inner_root_bytes
        leaf_hash = hash_leaf(leaf_data)
        
        leaves_data.append({
            'user_id': user_id,
            'inner_root': inner_root_hex,
            'leaf_hash': leaf_hash.hex()
        })
        leaves.append(leaf_hash)
    global_root, tree_levels = build_merkle_tree(leaves)
    print(f"Global root computed: {global_root.hex()}")
    print("\nComputing outer tree authentication paths...")
    for i, leaf_data in enumerate(leaves_data):
        auth_path = get_auth_path(i, tree_levels)
        leaf_data['outer_auth_path'] = json.dumps(auth_path)
    paths_df = pd.DataFrame(leaves_data)
    paths_df.to_parquet(output_paths, index=False)
    print(f"Outer tree paths saved to {output_paths}")
    print("\nGenerating issuer signing key...")
    private_key, public_key = generate_issuer_keypair()
    save_keypair(private_key, public_key)
    signature = private_key.sign(global_root)
    with open(output_sig, 'wb') as f:
        f.write(signature)
    print(f"Global root signature saved to {output_sig}")
    root_metadata = {
        "root": global_root.hex(),
        "n_users": len(user_roots),
        "hash_algorithm": "BLAKE2b-256",
        "tree_depth": len(tree_levels) - 1,
        "created_utc": datetime.utcnow().isoformat() + "Z",
        "signature_algorithm": "Ed25519"
    }
    
    with open(output_json, 'w') as f:
        json.dump(root_metadata, f, indent=2)
    print(f"Global root metadata saved to {output_json}")
    
    #Summary
    print("\n" + "="*60)
    print("OUTER TREE BUILD COMPLETE")
    print("="*60)
    print(f"Global root:     {global_root.hex()}")
    print(f"Number of users: {len(user_roots)}")
    print(f"Tree depth:      {len(tree_levels) - 1}")
    print(f"Leaves (padded): {len(tree_levels[0])}")
    print("="*60)

if __name__ == "__main__":
    main()
