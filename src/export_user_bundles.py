"""
Step 6: Export per-user credential bundles.

For each user, this script creates a JSON bundle containing:
- User ID
- Raw attribute values
- Salts and commitments for each attribute
- Inner tree authentication paths (attribute -> inner_root)
- Outer tree authentication path (inner_root -> global_root)
- Signed global root

These bundles are what users hold to generate proofs later.
Output: artifacts/user_bundles/{user_id}.json
"""

import pandas as pd
import json
from pathlib import Path

def load_global_root_data(
    global_root_path="artifacts/global_root.json",
    signature_path="artifacts/issuer_root.sig"
):
    """Load global root metadata and signature."""
    with open(global_root_path, 'r') as f:
        global_data = json.load(f)
    
    with open(signature_path, 'rb') as f:
        signature = f.read()
    
    global_data['signature'] = signature.hex()
    return global_data

def export_user_bundle(user_id, inner_df, outer_df, global_data, output_dir="artifacts/user_bundles"):
    """
    Export a single user's credential bundle.
    
    Args:
        user_id: User ID
        inner_df: DataFrame with user's attributes from inner_roots.parquet
        outer_df: DataFrame with user's outer path from outer_tree_paths.parquet
        global_data: Global root metadata + signature
        output_dir: Directory to save bundles
    """
    # Filter data for this user
    user_inner = inner_df[inner_df['ID'] == user_id]
    user_outer = outer_df[outer_df['user_id'] == user_id]
    
    if len(user_inner) == 0:
        raise ValueError(f"No inner tree data found for user {user_id}")
    if len(user_outer) == 0:
        raise ValueError(f"No outer tree path found for user {user_id}")
    inner_root = user_inner.iloc[0]['inner_root']

    attributes = []
    for _, row in user_inner.iterrows():
        attributes.append({
            "name": row['attr_name'],
            "value": row['attr_value'],
            "salt": row['salt'],
            "commitment": row['commitment'],
            "inner_auth_path": json.loads(row['auth_path'])
        })

    outer_auth_path = json.loads(user_outer.iloc[0]['outer_auth_path'])

    bundle = {
        "user_id": int(user_id),
        "inner_root": inner_root,
        "outer_auth_path": outer_auth_path,
        "attributes": attributes,
        "global_root": global_data['root'],
        "global_root_metadata": {
            "n_users": global_data['n_users'],
            "hash_algorithm": global_data['hash_algorithm'],
            "tree_depth": global_data['tree_depth'],
            "created_utc": global_data['created_utc'],
            "signature_algorithm": global_data['signature_algorithm']
        },
        "issuer_signature": global_data['signature']
    }
    output_path = Path(output_dir) / f"{user_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(bundle, f, indent=2)
    
    return output_path

def main(
    inner_roots_path="artifacts/inner_roots.parquet",
    outer_paths_path="artifacts/outer_tree_paths.parquet",
    global_root_path="artifacts/global_root.json",
    signature_path="artifacts/issuer_root.sig",
    output_dir="artifacts/user_bundles",
    sample_only=False,
    sample_count=10
):
    """
    Main function to export all user bundles.
    
    Args:
        sample_only: If True, only export first N users (for testing)
        sample_count: Number of users to export if sample_only=True
    """
    print("Loading data...")
    inner_df = pd.read_parquet(inner_roots_path)
    outer_df = pd.read_parquet(outer_paths_path)
    global_data = load_global_root_data(global_root_path, signature_path)
    user_ids = sorted(inner_df['ID'].unique())
    
    if sample_only:
        user_ids = user_ids[:sample_count]
        print(f"\nSAMPLE MODE: Exporting only {len(user_ids)} users")
    else:
        print(f"\nExporting bundles for {len(user_ids)} users...")
    exported = 0
    for user_id in user_ids:
        try:
            output_path = export_user_bundle(
                user_id, 
                inner_df, 
                outer_df, 
                global_data,
                output_dir
            )
            exported += 1
            
            if exported % 1000 == 0:
                print(f"Exported {exported}/{len(user_ids)} bundles...")
        except Exception as e:
            print(f"Failed to export bundle for user {user_id}: {e}")
    
    print(f"\nSuccessfully exported {exported} user bundles to {output_dir}/")

    if exported > 0:
        sample_id = user_ids[0]
        sample_path = Path(output_dir) / f"{sample_id}.json"
        with open(sample_path, 'r') as f:
            sample = json.load(f)
        
        print(f"\nSample bundle for user {sample_id}:")
        print(f"  - Inner root: {sample['inner_root'][:32]}...")
        print(f"  - Attributes: {len(sample['attributes'])}")
        print(f"  - Outer path length: {len(sample['outer_auth_path'])}")
        print(f"  - Global root: {sample['global_root'][:32]}...")
        print(f"  - File size: {sample_path.stat().st_size / 1024:.2f} KB")

if __name__ == "__main__":
    # set sample_only=True to test with just a few users first
    main(sample_only=False)
