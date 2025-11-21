# zk-identities: privacy-preserving identity verification

a prototype system for proving attributes from government-issued identities (driver's licenses) using zero-knowledge proofs and merkle commitments, without revealing unnecessary information to verifiers.

**author**: Tanmayi Jandhyala

## quick start

```bash
# clone repository
git clone https://github.com/tanmayij/ZK-Identities.git
cd ZK-Identities

# setup virtual environment
python3 -m venv .venv
source .venv/bin/activate

# install dependencies
pip install pandas pyarrow pydantic cryptography faker
#you can also use uv, which is much faster

# run complete demonstration
python src/complete_flow.py
```

## project status

### core functionality (complete)
- [x] data normalization with validation and quarantine
- [x] cryptographic primitives (blake2b-256, commitment schemes)
- [x] two-level merkle tree construction (inner per-user, outer global)
- [x] issuer key generation and root signing (ed25519)
- [x] user credential bundle export (10,000 users)
- [x] zero-knowledge proof generation (3 predicate types)
- [x] proof verification against signed global root
- [x] blind signature receipts for unlinkable attestation tokens
- [x] complete end-to-end demonstration

### additional work
- [ ] cli interface with click
- [ ] comprehensive test suite
- [ ] performance benchmarking (1k, 10k, 100k records)
- [ ] documentation and examples

## architecture overview

### system model
- **issuer** (government/dmv): constructs merkle-committed datastore, signs global root
- **user** (citizen): holds credential bundle, generates zero-knowledge proofs
- **verifier** (relying party): validates proofs against signed root, optionally issues blind receipts

### data flow
```
raw csv → normalize → commitments → inner trees → outer tree → user bundles
                                                                     ↓
                                                          user generates zk proof
                                                                     ↓
                                                          verifier checks proof
                                                                     ↓
                                                    (optional) blind signature receipt
```

### merkle structure
- **inner tree**: per-user tree binding all 7 attributes (first_name, last_name, dob, citizenship, license_class, status, issue_date)
- **outer tree**: global tree with one leaf per user (hash of user_id || inner_root)
- **tree properties**: balanced, padded to power of 2, domain-separated hashing

## implementation details

### cryptographic primitives
- **hash function**: blake2b-256
- **commitment scheme**: hash-based (binding but not hiding)
  - format: `commit(value, salt) = blake2b(value || salt)`
  - note: production should use pedersen commitments for computational hiding
- **salt derivation**: deterministic from `blake2b(user_id || attribute_name)`
  - note: production should use cryptographically random salts
- **merkle hashing**: domain-separated (0x00 for leaves, 0x01 for internal nodes)
- **signing**: ed25519 for issuer root signatures
- **blind signatures**: rsa blind signatures for unlinkable receipts

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
  generate_dataset.py          # synthetic data generation
  normalize_data.py            # step 1: validation and normalization
  build_inner_trees.py         # step 4: per-user merkle trees
  build_outer_tree.py          # step 5: global merkle tree + signing
  export_user_bundles.py       # step 6: credential bundle export
  complete_flow.py             # end-to-end demo with blind receipts
  
  zkid/
    crypto.py                  # cryptographic primitives
    prover.py                  # user-side proof generation
    verifier.py                # verifier-side proof checking
    blind_signatures.py        # blind signature implementation

data/
  .gitkeep                     # csv files excluded from git

artifacts/
  .gitkeep                     # generated files excluded from git
  global_root.json             # signed global root (safe to commit)

tests/                         # test suite (todo)
docs/                          # documentation (todo)
```

## usage

### step-by-step execution

```bash
# 1. generate synthetic dataset (if needed)
python src/generate_dataset.py

# 2. normalize and validate data
python src/normalize_data.py

# 3. build per-user inner merkle trees
python src/build_inner_trees.py

# 4. build global outer merkle tree and sign
python src/build_outer_tree.py

# 5. export user credential bundles
python src/export_user_bundles.py

# 6. run complete verification flow with blind receipts
python src/complete_flow.py
```

### example: prove and verify

```python
from zkid.prover import generate_proof, save_proof
from zkid.verifier import verify_proof

# user generates proof
predicates = [
    {"type": "range", "attribute": "Date_of_Birth", "threshold": 18},
    {"type": "equality", "attribute": "Citizenship", "value": "Germany"}
]
proof = generate_proof(user_id=123, predicates=predicates)
save_proof(proof, "artifacts/proofs/123_proof.json")

# verifier checks proof
result = verify_proof(proof)
print(f"verification: {'valid' if result['valid'] else 'invalid'}")
```

## security considerations

### threat model
- **issuer**: honest-but-curious, correctly constructs commitments but should not learn which predicates are proven
- **verifier**: semi-honest, may attempt to correlate proofs across sessions (mitigated by blind signatures)
- **user**: may attempt to forge proofs (prevented by zk soundness)
- **storage**: untrusted, tampering breaks merkle consistency

### limitations
- current commitment scheme is not computationally hiding (brute-forceable for small value spaces)
- simplified zkp implementation instead of production library
- deterministic salts instead of cryptographically random
- no formal security proofs
- demonstration code, not production-ready

### production recommendations
- use pedersen commitments over elliptic curves
- implement proper zkp library (bulletproofs, zksnark, or zkstark)
- use cryptographically random salts stored in user bundles
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

install via: `pip install pandas pyarrow pydantic cryptography faker`

note: zksk library has installation issues, so simplified zkp implementation is used instead.

## future work

- implement cli interface with click
- comprehensive test suite (unit, integration, property-based)
- performance benchmarking across dataset sizes
- support for grouped user queries (multi-party proofs)
- policy-gated handshake for access control
- cross-dataset linkage proofs
- mobile wallet support?

## references

- merkle trees for authentication
- sigma protocols and fiat-shamir heuristic
- blind signatures (chaum 1983)
- pedersen commitments
- zero-knowledge proofs


---

- performance: measure commit time, tree build time, proof gen/verify time for datasets of varying size
- storage: measure proof size, user bundle size, merkle path lengths
- security: analyze commitment scheme, zkp soundness, replay resistance
