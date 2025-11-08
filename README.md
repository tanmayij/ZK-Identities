# zk-identities: privacy-preserving identity verification

a prototype system for proving attributes from government-issued identities (driver's licenses) using zero-knowledge proofs and merkle commitments, without revealing unnecessary information to verifiers.

## project status

### completed
- [x] project setup
- [x] canonical schema definition (pydantic models for driver license records)
- [x] data normalization pipeline (csv to parquet with validation)
- [x] quarantine file generation for invalid records
- [x] cryptographic primitives (blake2b-256 hash, salt derivation, commitment scheme)
- [x] merle leaf and internal node hashing with domain separation

### in progress
- [ ] inner (per-user) merkle tree construction
- [ ] outer (global) merkle tree construction
- [ ] issuer key generation and root signing

### planned
- [ ] user bundle export (per-user credentials + merkle paths)
- [ ] zk proof generation (equality, range, set-membership predicates)
- [ ] verifier implementation
- [ ] cli commands (ingest, commit, prove, verify)
- [ ] benchmarking suite (n=1k, 10k, 100k records)
- [ ] test suite (unit, property, golden tests)
- [ ] optional: blinded receipt tokens

## architecture overview

```
raw csv data
  -> normalize & validate (step 1)
  -> generate per-attribute commitments (step 3)
  -> build inner merkle trees (one per user) (step 4)
  -> build outer merkle tree (global root) (step 5)
  -> export user bundles with inclusion proofs (step 6)
  -> user generates zk proofs for predicates (step 8)
  -> verifier checks proofs against signed global root (step 8)
```

## current implementation

### data normalization
- input: synthetic driver license csv (10,000 records)
- output: `artifacts/normalized.parquet` + quarantine file for invalid rows
- schema: id, first_name, last_name, date_of_birth (iso 8601), citizenship, license_class, status, issue_date
- validation: type checking, date parsing, enum constraints via pydantic

### cryptographic primitives
- hash: blake2b-256
- commitment: hash-based (value || salt) - binding but not hiding
  - note: production version should use pedersen commitments for zk-friendliness
- salt generation: deterministic (hash of user_id + attribute_name) for reproducibility
  - note: production version should use cryptographically random salts stored per-user
- merkle tree: domain-separated hashing (0x00 for leaves, 0x01 for internal nodes)

## next steps

1. implement inner tree builder: read normalized.parquet, generate commitments for all attributes per user, build merkle tree, compute inner_root
2. implement outer tree builder: collect all inner_roots, build global merkle tree, sign root with issuer key
3. export user bundles: per-user json with attributes, salts, commitments, inner path, outer path, signed root
4. implement proof generation for three predicates: equality (citizenship == x), range (age >= 18), set-membership (license_class in {g, g2, m})
5. implement verifier: check issuer signature, verify merkle paths, verify zk proofs
6. wire up cli commands with click
7. write test suite and run benchmarks

## dependencies

- uv (package manager)
- pydantic (schema validation)
- pandas, pyarrow (data processing)
- cryptography (signing, key generation)
- zksk (zero-knowledge proof library)
- pymerkle (merkle tree utilities)

## usage (planned)

```bash
# normalize data
uv run zkid ingest --in data/drivers.csv --out artifacts/normalized.parquet

# build commitments and merkle trees
uv run zkid commit --in artifacts/normalized.parquet --out artifacts/inner_roots.parquet --root artifacts/global_root.json

# export user credentials
uv run zkid export-user --id 123 --out artifacts/user_bundles/123.json

# generate proof (user side)
uv run zkid prove --bundle artifacts/user_bundles/123.json --pred "age>=18 & citizenship==usa" --out artifacts/proofs/123.json

# verify proof (verifier side)
uv run zkid verify --proof artifacts/proofs/123.json --root artifacts/global_root.json --sig artifacts/issuer_root.sig
```

## project structure

```
src/zkid/           # main package
  crypto.py         # hash, commitment, merkle primitives
  
src/
  normalize_data.py # step 1: csv normalization
  
data/               # raw csv input
artifacts/          # generated outputs (parquet, roots, proofs)
tests/              # test suite
```

## evaluation goals

- correctness: verify merkle path recomputation, proof verification
- performance: measure commit time, tree build time, proof gen/verify time for datasets of varying size
- storage: measure proof size, user bundle size, merkle path lengths
- security: analyze commitment scheme, zkp soundness, replay resistance
