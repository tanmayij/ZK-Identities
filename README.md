# zk-identities: privacy-preserving identity verification

a prototype system for proving attributes from government-issued identities using zero-knowledge proofs and merkle commitments. includes encrypted database extension with attribute-agnostic merkle trees and **read-verify-rotate architecture** with groth16 proofs.

**author**: Tanmayi Jandhyala

## quick start

### automated setup (recommended)
```bash
# clone repository
git clone https://github.com/tanmayij/ZK-Identities.git
cd ZK-Identities

# run setup script (uses uv for fast dependency installation)
./setup.sh

# run demos
python_/bin/python src/complete_flow.py          # original identity verification
python_/bin/python src/demo_encrypted_db.py      # schnorr-based encrypted db
python src/batch_fetch_client.py                  # groth16 client demo
python_/bin/python demo_encrypted_identity_db.py  # full database + rotation demo
./test_circuits_compile.sh                        # compile and verify circuits
./test_proofs.sh                                  # generate and verify groth16 proofs

# run benchmarks
python_/bin/python benchmark_single_query.py 20           # single query with k=20 anonymity
python_/bin/python benchmark.py                           # comprehensive benchmark suite

# run automated comprehensive benchmarks (NEW)
./benchmarks/run_full_test.sh                             # full test (1024 users, k=1-40)
./benchmarks/run_comprehensive_benchmarks.sh --quick      # quick test (256 users, k=1-9)
.venv/bin/python benchmarks/smoke_test.py                 # minimal smoke test (10 users)

# visualize benchmark progress in real-time (NEW)
.venv/bin/python benchmarks/visualize_progress.py         # monitor running benchmark with live graphs
```

### manual setup
```bash
# install uv if needed
curl -LsSf https://astral.sh/uv/install.sh | sh

# create virtual environment
python3 -m venv python_

# install python dependencies with uv (much faster than pip)
uv pip install pandas pyarrow pydantic cryptography faker --python python_/bin/python

# for groth16 circuits (optional)
# 1. install rust (for circom)
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh

# 2. install circom from source
git clone https://github.com/iden3/circom.git
cd circom && cargo install --path circom && cd ..

# 3. install snarkjs and circomlib
npm install -g snarkjs
npm install circomlib
```

## project components

### 1. original identity verification system
- [x] data normalization with validation and quarantine
- [x] cryptographic primitives (blake2b-256, commitment schemes)
- [x] two-level merkle tree construction (inner per-user, outer global)
- [x] issuer key generation and root signing (ed25519)
- [x] user credential bundle export (10,000 users)
- [x] zero-knowledge proof generation (3 predicate types)
- [x] proof verification against signed global root
- [x] blind signature receipts for unlinkable attestation tokens

### 2. encrypted database extension (schnorr-based)
- [x] deterministic aes-ecb encryption with per-column keys (cryptdb-style)
- [x] attribute-agnostic merkle trees (index-based, not name-based)
- [x] per-leaf randomizers for unique commitments
- [x] schnorr signatures over all leaves
- [x] leaf shuffling after queries (prevents positional linkage)
- [x] performance benchmarking (schnorr signing ~4.7ms per leaf)

### 3. read-verify-rotate architecture (groth16-based) NEW
- [x] nested merkle trees (inner: 8 attributes depth-3, outer: 1024 users depth-10)
- [x] circuit a: rotation circuit with nullifiers (15k constraints)
- [x] circuit b: predicate circuit with attribute hiding (12k constraints)
- [x] client-side k-anonymity batch fetching
- [x] poseidon hash integration (zk-friendly)
- [x] groth16 proof system (~256 byte proofs, ~5ms verification)
- [x] comprehensive documentation and test suite

### 4. automated comprehensive benchmark suite NEW
- [x] natural language query parser (english → predicates)
- [x] component-level timing instrumentation (7 distinct phases)
- [x] k-value performance sweep (k=1 to 40+)
- [x] batched vs non-batched merkle rebuild comparison
- [x] multi-user cohort scaling tests
- [x] insert/update operation benchmarks
- [x] publication-quality visualization (5 chart types)
- [x] one-command automation with pre-seeded database

## architecture overview

### system models

#### 1. original identity verification
- **issuer** (government/dmv): constructs merkle-committed datastore, signs global root
- **user** (citizen): holds credential bundle, generates zero-knowledge proofs
- **verifier** (relying party): validates proofs against signed root, optionally issues blind receipts

#### 2. encrypted database (schnorr-based)
- **server**: untrusted database operator storing encrypted attributes with merkle commitments
- **client** (user): queries encrypted database, decrypts locally, generates zk proofs
- **verifier**: checks proofs against public merkle roots without learning attribute details

**data flow**:
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

#### 3. read-verify-rotate (groth16-based) !!!NEW
- **server**: serves encrypted blobs, updates tree on rotation proof verification
- **client**: fetches k+1 blobs (k decoys + 1 target), generates groth16 proofs
- **verifier**: validates proofs (rotation or predicate) in ~5ms

**key features**:
- **k-anonymity**: server sees k+1 requests, cannot identify target
- **rotation**: users move to new positions with fresh salts after each access
- **nullifiers**: prevent double-rotation attacks
- **attribute privacy**: predicates proven without revealing values

**data flow**:
```
client requests k+1 blobs → server returns encrypted data
                                      ↓
                          client decrypts only target
                                      ↓
                          client generates rotation proof
                                      ↓
                          server verifies groth16 proof
                                      ↓
                          server updates outer tree position
```

### merkle tree structures

#### original & encrypted db systems
- **inner tree**: per-user tree binding all 7 attributes (first_name, last_name, dob, citizenship, license_class, status, issue_date)
- **outer tree**: global tree with one leaf per user (hash of user_id || inner_root)
- **tree properties**: balanced, padded to power of 2, domain-separated hashing

#### read-verify-rotate system
- **inner tree**: depth 3, 8 leaves, each = poseidon(attribute, salt)
- **outer tree**: depth 10, up to 1024 users, each leaf = user's inner_root
- **hash function**: poseidon (zk-friendly, ~700 constraints per hash)

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

**read-verify-rotate architecture:** !!!NEW
- **poseidon hash**: zk-friendly hash function (~700 constraints per invocation)
- **groth16 proofs**: constant-size proofs (256 bytes) with fast verification (~5ms)
- **rotation circuit**: ~15,000 constraints
  - verifies old position in outer tree
  - computes new inner root with fresh salts
  - validates nullifier = poseidon(old_inner_root, old_salt[0])
- **predicate circuit**: ~12,000 constraints
  - constant-time attribute selection (no branching leakage)
  - greaterthan(64) gadget for threshold comparison
  - dual merkle verification (inner + outer trees)
- **k-anonymity**: client fetches k decoys + 1 real target
- **nullifiers**: prevent double-rotation from same position

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
  
  # encrypted database extension (schnorr-based)
  encrypted_db_system.py       # core encrypted db with merkle + schnorr
  demo_encrypted_db.py         # encrypted db demonstration
  benchmark_encrypted_db.py    # performance benchmarking
  
  # read-verify-rotate architecture (groth16-based) !!!NEW
  batch_fetch_client.py        # client-side k-anonymity logic
  
  zkid/
    crypto.py                  # cryptographic primitives
    prover.py                  # user-side proof generation
    verifier.py                # verifier-side proof checking
    blind_signatures.py        # blind signature implementation
    schnorr.py                 # schnorr signatures with blind support

circuits/                        # !!!NEW
  rotation.circom              # circuit a: identity maintenance (~15k constraints)
  predicate.circom             # circuit b: business predicates (~12k constraints)
  input_rotation.json          # example rotation inputs
  input_predicate.json         # example predicate inputs

docs/                            # !!!NEW
  read_verify_rotate_architecture.md  # complete documentation

test_circuits.sh                 # !!!NEW: automated circuit testing

data/
  .gitkeep                     # csv files excluded from git

artifacts/
  .gitkeep                     # generated files excluded from git
  global_root.json             # signed global root (safe to commit)

docs/
  design_encrypted_db.tex      # original encrypted db design
  design_encrypted_db_extension.tex  # updated design with schnorr
  read_verify_rotate_architecture.md  # !!!NEW: groth16 architecture

tests/                         # test suite (todo)
```

## usage

### original identity system

```bash
# step-by-step execution
python_/bin/python src/generate_dataset.py
python_/bin/python src/normalize_data.py
python_/bin/python src/build_inner_trees.py
python_/bin/python src/build_outer_tree.py
python_/bin/python src/export_user_bundles.py
python_/bin/python src/complete_flow.py
```

### encrypted database (schnorr-based)

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

### read-verify-rotate (groth16-based) !!!NEW

```bash
# install circom and snarkjs
# see: https://docs.circom.io/getting-started/installation/

# install circomlib
npm install circomlib

# run automated test suite
./test_circuits.sh

# or manually test python client
python src/batch_fetch_client.py
```

**example workflow**:
```python
from batch_fetch_client import BatchFetchClient

client = BatchFetchClient(user_key=b"secret_key_32_bytes_long!!!!!!!!")

# fetch with k-anonymity and rotate
result = client.fetch_and_rotate(
    target_index=42,
    k_decoys=5,
    server_fetch_fn=server.fetch_blobs,
    server_update_fn=server.update_position,
    outer_root="current_root_hex",
    total_users=1024
)

# result contains rotation_proof_inputs ready for snarkjs
```

## performance comparison

| metric | original (ed25519) | encrypted db (schnorr) | read-verify-rotate (groth16) |
|--------|-------------------|----------------------|---------------------------|
| proof generation | ~50ms | ~4.7ms/leaf | ~2.2s (rotation), ~1.8s (predicate) |
| proof size | ~2kb (sig + paths) | ~2kb (sig + paths) | 256 bytes |
| verification | ~10ms | ~50ms | ~5ms |
| privacy level | predicate hiding | attribute-id hiding | full attribute hiding + unlinkability |
| access pattern | full leakage | full leakage | k-anonymity hiding |

**key improvements in groth16 version**:
-  8x smaller proofs (256 bytes vs 2kb)
-  10x faster verification (5ms vs 50ms)
-  k-anonymity support (no access pattern leakage)
-  rotation for unlinkability
-  slower proving (2.2s vs 50ms) - acceptable for privacy use cases

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

### threat model (read-verify-rotate) !!!NEW
- **server**: honest-but-curious
  - sees k+1 blob requests but cannot identify target (k-anonymity)
  - cannot link accesses across rotations (position changes + fresh salts)
  - learns aggregate statistics (e.g., k+1 users accessed system)
- **client**: trusted to generate valid proofs
- **verifier**: sees only public inputs (roots, thresholds, nullifiers)
  - learns predicate result but not actual attribute value
  - cannot link users across accesses (rotation + nullifiers)
- **collusion**: k decoy owners colluding can eliminate anonymity

### encrypted database privacy properties
- **attribute-id hiding**: leaf messages contain no semantic attribute names or explicit indices
- **leaf-specific signatures**: schnorr signatures only verify at correct leaf position
  - different `(uid, attr_index)` → different randomizer → different message → signature fails
- **positional unlinkability**: shuffling after queries prevents tracking same attribute across roots
- **ciphertext determinism**: enables equality filtering but leaks frequency analysis

### read-verify-rotate privacy properties !!!NEW
- **k-anonymity**: server sees k+1 requests, cannot identify target with probability > 1/(k+1)
- **unlinkability**: rotation with fresh salts prevents linking accesses
- **nullifier-based double-spend prevention**: hash(old_inner_root, old_salt[0]) prevents reusing old positions
- **attribute value hiding**: predicates proven in zero-knowledge (verifier learns only threshold satisfaction)
- **constant-time operations**: circuits use no branching (prevents timing leakage)

### limitations
- current commitment scheme (original system) is not computationally hiding
- simplified zkp implementation instead of production library (original & schnorr systems)
- deterministic salts instead of cryptographically random (original system)
- aes-ecb leaks frequency information (encrypted db)
- no oram/pir for hiding access patterns from server (encrypted db - partially addressed by groth16)
- schnorr verification currently done in clear (should move to zk circuit)
- groth16 requires trusted setup (powers of tau ceremony) !!!NEW
- k-anonymity vulnerable to collusion among k decoys !!!NEW
- no formal security proofs

### production recommendations
- use pedersen commitments over elliptic curves
- implement proper zkp library (bulletproofs, zksnark, or zkstark)
- use cryptographically random salts stored in user bundles
- replace aes-ecb with order-preserving encryption or garbled circuits for range queries
- add oram/pir for complete access pattern hiding (or use groth16 system with larger k)
- implement blind schnorr variant (client-side signing)
- move schnorr verification into zk circuit
- use multi-party computation for trusted setup (groth16) or switch to transparent setup (plonk, stark) !!!NEW
- implement sybil resistance to prevent decoy generation attacks !!!NEW
- add formal verification and security audits
- implement proper key management and rotation
- add replay protection and nonce management

## datasets

currently uses synthetic driver's license data (10,000 records) with attributes:
- id, first_name, last_name, date_of_birth, citizenship, license_class, status, issue_date

synthetic data generated using faker library with realistic distributions.

## dependencies

### python packages (installed via uv)
```
pandas>=2.0.0
pyarrow>=14.0.0
pydantic>=2.0.0
cryptography>=41.0.0
faker>=20.0.0
```

### circom/groth16 tools (optional, for read-verify-rotate)
```
circom 2.1.6+
snarkjs (npm package)
circomlib (npm package)
```

**note**: `uv` is significantly faster than pip for dependency installation. install with:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
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
