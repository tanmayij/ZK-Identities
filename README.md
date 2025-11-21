# zk-identities: privacy-preserving identity verification

a prototype system for proving attributes from government-issued identities using zero-knowledge proofs and merkle commitments. includes encrypted database extension with attribute-agnostic merkle trees and schnorr signatures.

**author**: Tanmayi Jandhyala

## quick start

```bash
# clone repository
git clone https://github.com/tanmayij/ZK-Identities.git
cd ZK-Identities

# setup virtual environment with uv
python3 -m venv python_

# install dependencies using uv
uv pip install pandas pyarrow pydantic cryptography faker --python python_/bin/python

# run original identity verification demo
python_/bin/python src/complete_flow.py

# run encrypted database demo
python_/bin/python src/demo_encrypted_db.py

# run encrypted database benchmark
python_/bin/python src/benchmark_encrypted_db.py
```

## project status

### core functionality
- [x] data normalization with validation and quarantine
- [x] cryptographic primitives (blake2b-256, commitment schemes)
- [x] two-level merkle tree construction (inner per-user, outer global)
- [x] issuer key generation and root signing (ed25519)
- [x] user credential bundle export (10,000 users)
- [x] zero-knowledge proof generation (3 predicate types)
- [x] proof verification against signed global root
- [x] blind signature receipts for unlinkable attestation tokens

### encrypted database extension
- [x] deterministic aes-ecb encryption with per-column keys (cryptdb-style)
- [x] attribute-agnostic merkle trees (index-based, not name-based)
- [x] per-leaf randomizers for unique commitments
- [x] schnorr signatures over all leaves
- [x] leaf shuffling after queries (prevents positional linkage)
- [x] performance benchmarking (schnorr signing ~4.7ms per leaf) 
- [] design more realistic benchmarking

### additional work
- [ ] cli interface with click
- [ ] comprehensive test suite
- [ ] zk circuit integration for schnorr verification

## architecture overview

### original system model
- **issuer** (government/dmv): constructs merkle-committed datastore, signs global root
- **user** (citizen): holds credential bundle, generates zero-knowledge proofs
- **verifier** (relying party): validates proofs against signed root, optionally issues blind receipts

### encrypted database extension model
- **server**: untrusted database operator storing encrypted attributes with merkle commitments
- **client** (user): queries encrypted database, decrypts locally, generates zk proofs
- **verifier**: checks proofs against public merkle roots without learning attribute details

### data flow (encrypted db)
```
encrypted db → server evaluates predicate → inner trees (per user) → outer tree
                                                                          ↓
                                                         server signs all leaves (schnorr)
                                                                          ↓
                                                           client decrypts relevant attrs
                                                                          ↓
                                                          client proves predicate in zk
                                                                          ↓
                                                         verifier checks merkle + schnorr
```

### merkle structure
- **inner tree**: per-user tree binding all 7 attributes (first_name, last_name, dob, citizenship, license_class, status, issue_date)
- **outer tree**: global tree with one leaf per user (hash of user_id || inner_root)
- **tree properties**: balanced, padded to power of 2, domain-separated hashing

## implementation details

### cryptographic primitives

**original identity system:**
- **hash function**: blake2b-256
- **commitment scheme**: hash-based (binding but not hiding)
  - format: `commit(value, salt) = blake2b(value || salt)`
  - note: production should use pedersen commitments for computational hiding
- **salt derivation**: deterministic from `blake2b(user_id || attribute_name)`
  - note: production should use cryptographically random salts
- **merkle hashing**: domain-separated (0x00 for leaves, 0x01 for internal nodes)
- **signing**: ed25519 for issuer root signatures
- **blind signatures**: rsa blind signatures for unlinkable receipts

**encrypted database extension:**
- **deterministic encryption**: aes-128-ecb with per-column keys
  - column keys derived via `blake2b(master_key || "column_key" || attr_name)` → 16 bytes
  - pkcs7 padding, deterministic per column
  - equality filtering via ciphertext comparison
- **tags**: `blake2b(column_key || "tag" || plaintext)` for efficient equality proofs
- **leaf randomizers**: per-leaf via `blake2b(seed || uid || attr_index)` for unique commitments
- **schnorr signatures**: ecc-based signatures over attribute-agnostic leaf messages
  - message: `blake2b("leaf_message_v1" || ciphertext || tag || query_nonce || randomizer)`
  - no uid or attribute name in signed message (preserves privacy)
  - different leaves get different messages via randomizer derivation
- **merkle shuffling**: randomizes leaf positions after each query to prevent linkage

### zero-knowledge proofs
implemented three predicate types using simplified sigma protocols:

1. **equality proof**: prove `attribute == claimed_value`
   - use case: prove citizenship without revealing other attributes
   
2. **range proof**: prove `attribute >= threshold`
   - use case: prove age >= 18 without revealing exact birthdate
   
3. **set membership proof**: prove `attribute ∈ allowed_set`
   - use case: prove license_class is valid without revealing which one

note: uses fiat-shamir heuristic for non-interactive proofs. production should use proper zkp library like bulletproofs or zksk.

### blind signature receipts
after successful verification, verifier can issue unlinkable attestation token:
- user blinds message before sending to verifier
- verifier signs blinded message (without knowing content)
- user unblinds signature to get valid token
- token proves successful verification but cannot be linked back to session

**properties**: unlinkability, unforgeability, binding to predicates and nonce

## project structure

```
src/
  # original identity verification system
  generate_dataset.py          # synthetic data generation
  normalize_data.py            # step 1: validation and normalization
  build_inner_trees.py         # step 4: per-user merkle trees
  build_outer_tree.py          # step 5: global merkle tree + signing
  export_user_bundles.py       # step 6: credential bundle export
  complete_flow.py             # end-to-end demo with blind receipts
  
  # encrypted database extension
  encrypted_db_system.py       # core encrypted db with merkle + schnorr
  demo_encrypted_db.py         # encrypted db demonstration
  benchmark_encrypted_db.py    # performance benchmarking
  
  zkid/
    crypto.py                  # cryptographic primitives
    prover.py                  # user-side proof generation
    verifier.py                # verifier-side proof checking
    blind_signatures.py        # blind signature implementation
    schnorr.py                 # schnorr signatures with blind support

data/
  .gitkeep                     # csv files excluded from git

artifacts/
  .gitkeep                     # generated files excluded from git
  global_root.json             # signed global root (safe to commit)

docs/
  design_encrypted_db.tex      # original encrypted db design
  design_encrypted_db_extension.tex  # updated design with schnorr

tests/                         # test suite (todo)
```

## usage

### step-by-step execution

```bash
# 1. generate synthetic dataset (if needed)
python_/bin/python src/generate_dataset.py

# 2. normalize and validate data
python_/bin/python src/normalize_data.py

# 3. build per-user inner merkle trees
python_/bin/python src/build_inner_trees.py

# 4. build global outer merkle tree and sign
python_/bin/python src/build_outer_tree.py

# 5. export user credential bundles
python_/bin/python src/export_user_bundles.py

# 6. run complete verification flow with blind receipts
python_/bin/python src/complete_flow.py
```

### example: encrypted database query

```python
from encrypted_db_system import (
    EncryptedDatabaseServer, EncryptedDatabaseClient, EncryptedDatabaseVerifier
)

# server setup
server = EncryptedDatabaseServer(
    encryption_key=secrets.token_bytes(32),
    attribute_order=["age", "country", "score"]
)

# load encrypted data
server.load_user("alice", pk_alice, {
    "age": "25",
    "country": "usa", 
    "score": "850"
})

# client queries and proves
client = EncryptedDatabaseClient("alice", sk_alice, pk_alice, key)
predicate = lambda uid, attrs: attrs.get("country") == server.enc.encrypt(b"usa", "country")
proof = client.query_and_prove(server, predicate, "age")

# verifier checks proof
verifier = EncryptedDatabaseVerifier()
verifier.register_root(proof.outer_root)
result = verifier.verify_proof(proof)  # checks merkle paths + schnorr sig
```

## security considerations

### threat model (original system)
- **issuer**: honest-but-curious, correctly constructs commitments but should not learn which predicates are proven
- **verifier**: semi-honest, may attempt to correlate proofs across sessions (mitigated by blind signatures)
- **user**: may attempt to forge proofs (prevented by zk soundness)
- **storage**: untrusted, tampering breaks merkle consistency

### threat model (encrypted database extension)
- **server**: untrusted, sees encrypted data and query patterns but not attribute semantics
  - learns which users match predicates (no oram/pir hiding)
  - does not learn which attribute types are queried (via index-based leaves)
  - does not learn plaintext values (deterministic encryption)
- **client**: trusted to decrypt and prove correctly
- **verifier**: semi-honest, sees only merkle roots and zk proofs
  - cannot link proofs across time (shuffling breaks positional correlation)
  - cannot determine which attribute was proven (attribute-agnostic messages)

### encrypted database privacy properties
- **attribute-id hiding**: leaf messages contain no semantic attribute names or explicit indices
- **leaf-specific signatures**: schnorr signatures only verify at correct leaf position
  - different `(uid, attr_index)` → different randomizer → different message → signature fails
- **positional unlinkability**: shuffling after queries prevents tracking same attribute across roots
- **ciphertext determinism**: enables equality filtering but leaks frequency analysis

### limitations
- current commitment scheme (original system) is not computationally hiding
- simplified zkp implementation instead of production library
- deterministic salts instead of cryptographically random (original system)
- aes-ecb leaks frequency information (encrypted db)
- no oram/pir for hiding access patterns from server (encrypted db)
- schnorr verification currently done in clear (should move to zk circuit)
- no formal security proofs
- demonstration code, not production-ready

### production recommendations
- use pedersen commitments over elliptic curves
- implement proper zkp library (bulletproofs, zksnark, or zkstark)
- use cryptographically random salts stored in user bundles
- replace aes-ecb with order-preserving encryption or garbled circuits for range queries
- add oram/pir for hiding which users match predicates
- implement blind schnorr variant (client-side signing)
- move schnorr verification into zk circuit
- add formal verification and security audits
- implement proper key management and rotation
- add replay protection and nonce management

## datasets

currently uses synthetic driver's license data (10,000 records) with attributes:
- id, first_name, last_name, date_of_birth, citizenship, license_class, status, issue_date

synthetic data generated using faker library with realistic distributions.

## dependencies

```
pandas>=2.0.0
pyarrow>=14.0.0
pydantic>=2.0.0
cryptography>=41.0.0
faker>=20.0.0
```

install via: `uv pip install pandas pyarrow pydantic cryptography faker --python python_/bin/python`

note: uv is significantly faster than pip. install uv via `curl -LsSf https://astral.sh/uv/install.sh | sh`

## future work

- implement cli interface with click
- comprehensive test suite (unit, integration, property-based)
- performance benchmarking across dataset sizes
- blind schnorr signatures (client generates keypair, signs leaves)
- zk circuit for schnorr verification (move from cleartext to zk)
- oram/pir for hiding access patterns
- support for grouped user queries (multi-party proofs)
- policy-gated handshake for access control
- cross-dataset linkage proofs

## performance (encrypted database)

benchmark results (50 users, 5 attributes, 30% selectivity):
- throughput: 1.36 queries/sec
- mean latency: 733ms
- schnorr signing: 339ms (72 leaves, ~4.7ms per signature)
- predicate evaluation: 0.01ms
- merkle tree construction: 0.20ms
- shuffling: 0.05ms

see `src/benchmark_encrypted_db.py` for detailed benchmarks.

## references

- merkle trees for authentication
- sigma protocols and fiat-shamir heuristic
- blind signatures (chaum 1983)
- pedersen commitments
- zero-knowledge proofs
- cryptdb: processing queries on encrypted database (popa et al. 2011)
- schnorr signatures and their application to zk proofs
