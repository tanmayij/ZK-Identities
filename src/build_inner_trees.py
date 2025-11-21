"""
Step 4: Build inner (per-user) Merkle trees from normalized data.

For each user, this script:
1. Generates commitments to all attributes
2. Builds a balanced Merkle tree (padded to power of 2)
3. Computes authentication paths for each attribute
4. Outputs inner_roots.parquet with all commitment data
"""

import pandas as pd
import json
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent))

from zkid.crypto import derive_salt, commit_attr, hash_leaf, hash_internal

ATTRIBUTE_ORDER = [
    "First_Name",
    "Last_Name", 
    "Date_of_Birth",
    "Citizenship",
    "License_Class",
    "Status",
    "Issue_Date"
]

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
            #we're right child, sibling is left
            sibling_index = index - 1
            is_right = False
        
        sibling = level[sibling_index]
        path.append({
            "sibling": sibling.hex(),
            "is_right": is_right
        })
        
        index = index // 2
    
    return path

def build_user_inner_tree(user_row):
    """
    Build inner Merkle tree for a single user.
    
    Returns dict with:
        - user_id
        - inner_root
        - attributes: list of {name, value, salt, commitment, auth_path}
    """
    user_id = user_row["ID"]
    commitments_data = []
    leaves = []
    
    for attr_name in ATTRIBUTE_ORDER:
        value = user_row[attr_name]
        salt = derive_salt(user_id, attr_name)
        commitment = commit_attr(value, salt)
        leaf_data = attr_name.encode('utf-8') + b"||" + commitment
        leaf_hash = hash_leaf(leaf_data)
        
        commitments_data.append({
            "attr_name": attr_name,
            "value": value,
            "salt": salt.hex(),
            "commitment": commitment.hex()
        })
        leaves.append(leaf_hash)
    
    inner_root, tree_levels = build_merkle_tree(leaves)
    for i, data in enumerate(commitments_data):
        auth_path = get_auth_path(i, tree_levels)
        data["auth_path"] = json.dumps(auth_path)
    
    return {
        "user_id": user_id,
        "inner_root": inner_root.hex(),
        "attributes": commitments_data
    }

def main(input_parquet="artifacts/normalized.parquet", 
         output_parquet="artifacts/inner_roots.parquet"):
    """
    Main function to build inner trees for all users.
    """
    print(f"Reading normalized data from {input_parquet}...")
    df = pd.read_parquet(input_parquet)
    print(f"Loaded {len(df)} user records")
    
    all_records = []
    
    for idx, row in df.iterrows():
        user_data = build_user_inner_tree(row)
        for attr in user_data["attributes"]:
            all_records.append({
                "ID": user_data["user_id"],
                "inner_root": user_data["inner_root"],
                "attr_name": attr["attr_name"],
                "attr_value": attr["value"],
                "salt": attr["salt"],
                "commitment": attr["commitment"],
                "auth_path": attr["auth_path"]
            })
        
        if (idx + 1) % 100 == 0:
            print(f"Processed {idx + 1}/{len(df)} users...")
    
    # Save to parquet
    output_df = pd.DataFrame(all_records)
    output_df.to_parquet(output_parquet, index=False)
    print(f"\nInner trees built for {len(df)} users")
    print(f"Output written to {output_parquet}")
    print(f"Total records (user * attributes): {len(all_records)}")
    
    print("\nSample output (first user, first attribute):")
    print(output_df[output_df["ID"] == output_df["ID"].iloc[0]].head(1).to_string())

if __name__ == "__main__":
    main()
