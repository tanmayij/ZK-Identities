"""
database structure visualization for encrypted database system.

shows the internal organization of the encrypted database.
"""

def visualize_database_structure():
    """print ascii diagram of database structure."""
    
    print("\n" + "="*80)
    print("encrypted database structure")
    print("="*80)
    
    print("""
current implementation:

EncryptedDatabaseServer
├── db: Dict[uid, Dict[attr_name, DeterministicCiphertext]]
│   │
│   ├── "alice" -> {"age": CT("25"), "country": CT("usa"), "score": CT("85")}
│   ├── "bob" -> {"age": CT("30"), "country": CT("canada"), "score": CT("92")}
│   ├── "carol" -> {"age": CT("28"), "country": CT("usa"), "score": CT("78")}
│   └── "dave" -> {"age": CT("35"), "country": CT("uk"), "score": CT("88")}
│
├── user_keys: Dict[uid, pk_user]
│   │
│   ├── "alice" -> 0x1a2b3c... (32 bytes)
│   ├── "bob" -> 0x4d5e6f... (32 bytes)
│   └── ...
│
├── inner_trees: Dict[uid, MerkleTree]  (built per query)
│   │
│   ├── "alice" -> MerkleTree([leaf_age, leaf_country, leaf_score])
│   └── ...
│
└── outer_tree: MerkleTree  (global, persistent)
    │
    └── MerkleTree([outer_leaf_alice, outer_leaf_bob, ...])


DeterministicCiphertext structure:
├── ciphertext: bytes  (encrypted attribute value)
└── tag: bytes  (for equality checking)


example: encrypting "age: 25" for alice:

plaintext = b"25"
  ↓
DeterministicEncryption.encrypt(plaintext)
  ↓
ciphertext = plaintext XOR BLAKE2b(key || plaintext)
tag = BLAKE2b(key || "tag" || plaintext)
  ↓
DeterministicCiphertext(
    ciphertext=0x7f3a...,
    tag=0x9d2e...
)
  ↓
stored in: db["alice"]["age"]


merkle tree structure:

inner tree for alice:
                    root_alice
                   /          \\
           H(L1, L2)           H(L3, dup)
          /        \\           /        \\
      leaf_age  leaf_country  leaf_score  (dup)

where each leaf = H_leaf(H("leaf" || uid || pk || attr_name || ciphertext))


outer tree:
                    root_outer
                   /          \\
           H(O1, O2)          H(O3, O4)
          /        \\         /        \\
    outer_alice outer_bob outer_carol outer_dave

where each outer_leaf = H_outer_leaf(uid || inner_root)


query flow visualization:

1. verifier sends predicate: "country = usa AND age >= 25"
   ↓
2. server evaluates on encrypted db:
   db["alice"]["country"].tag == encrypt("usa").tag ? YES
   db["bob"]["country"].tag == encrypt("usa").tag ? NO
   db["carol"]["country"].tag == encrypt("usa").tag ? YES
   ↓
3. matching_users = ["alice", "carol"]
   ↓
4. build inner trees:
   inner_trees["alice"] = MerkleTree([age, country, score])
   inner_trees["carol"] = MerkleTree([age, country, score])
   ↓
5. update outer tree:
   outer_tree = MerkleTree([
       H(alice || root_alice),
       H(carol || root_carol)
   ])
   ↓
6. sign all leaves:
   for each attr in alice: sign(H(leaf || uid || pk || attr || ct))
   for each attr in carol: sign(H(leaf || uid || pk || attr || ct))
   ↓
7. shuffle leaves:
   inner_trees["alice"].shuffle()
   inner_trees["carol"].shuffle()
   outer_tree.shuffle()
   ↓
8. return to client:
   {
       "alice": {
           "age": {ciphertext, signature, inner_path},
           "country": {ciphertext, signature, inner_path},
           "score": {ciphertext, signature, inner_path}
       },
       "carol": {...},
       "outer_root": 0xabc123...,
       "outer_paths": {"alice": path, "carol": path}
   }


memory layout example (after loading 4 users):

db = {
    "alice": {
        "age": DeterministicCiphertext(ciphertext=b'\\x7f\\x3a...', tag=b'\\x9d\\x2e...'),
        "country": DeterministicCiphertext(ciphertext=b'\\x1b\\x4c...', tag=b'\\x5e\\x7f...'),
        "score": DeterministicCiphertext(ciphertext=b'\\xa2\\x8d...', tag=b'\\xc3\\x1a...')
    },
    "bob": {...},
    "carol": {...},
    "dave": {...}
}

user_keys = {
    "alice": b'\\x1a\\x2b\\x3c...' (32 bytes),
    "bob": b'\\x4d\\x5e\\x6f...' (32 bytes),
    ...
}

total memory:
- 4 users × 3 attrs × (ciphertext + tag) ≈ 4 × 3 × 64 bytes ≈ 768 bytes
- 4 user keys × 32 bytes = 128 bytes
- merkle trees (ephemeral, per query)
    """)
    
    print("="*80 + "\n")


if __name__ == "__main__":
    visualize_database_structure()
