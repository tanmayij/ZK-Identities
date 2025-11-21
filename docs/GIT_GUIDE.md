# git commit and push guide

## files that will be committed (safe)

### source code
- `src/generate_dataset.py` - synthetic data generation
- `src/normalize_data.py` - data normalization
- `src/build_inner_trees.py` - per-user merkle trees
- `src/build_outer_tree.py` - global merkle tree
- `src/export_user_bundles.py` - user bundle export
- `src/complete_flow.py` - end-to-end demo
- `src/zkid/crypto.py` - cryptographic primitives
- `src/zkid/prover.py` - proof generation
- `src/zkid/verifier.py` - proof verification
- `src/zkid/blind_signatures.py` - blind signature implementation

### configuration and documentation
- `README.md` - project documentation
- `.gitignore` - git ignore rules
- `pyproject.toml` - project metadata
- `uv.lock` - dependency lock file

### directory structure
- `artifacts/.gitkeep` - preserves artifacts directory
- `data/.gitkeep` - preserves data directory
- `artifacts/global_root.json` - public metadata (no secrets)

## files excluded (by .gitignore)

### secrets and keys
- `artifacts/issuer_key.pem` - private signing key
- `artifacts/issuer_public_key.pem` - public key
- `artifacts/issuer_root.sig` - signature
- `artifacts/verifier_blind_key.pem` - blind signature key
- `artifacts/verifier_blind_public.pem` - blind signature public key

### large generated files
- `artifacts/normalized.parquet` - 10,000 user records
- `artifacts/inner_roots.parquet` - 70,000 commitment records
- `artifacts/outer_tree_paths.parquet` - merkle paths
- `artifacts/user_bundles/` - 10,000 individual files
- `artifacts/proofs/` - proof files
- `data/*.csv` - raw data files

### environment
- `.venv/`, `python_/` - virtual environments
- `__pycache__/`, `*.pyc` - python bytecode

## recommended commit workflow

```bash
# 1. check status
git status

# 2. add all safe files
git add .

# 3. verify what will be committed
git status

# 4. commit with descriptive message
git commit -m "complete zkp identity verification system with blind signatures"

# 5. push to github
git push origin main
```

## verify no secrets are committed

before pushing, double-check:

```bash
# should NOT show any .pem or .sig files
git diff --cached --name-only | grep -E '\.(pem|sig)$'

# should be empty output (no matches)
```

if you see any secrets, run:
```bash
git reset
git add .gitignore
git add src/
git add README.md
git add artifacts/.gitkeep artifacts/global_root.json
git add data/.gitkeep
```

## after pushing

anyone cloning your repo will need to:
1. generate their own data: `python src/generate_dataset.py`
2. run the pipeline: follow steps in README
3. keys will be auto-generated during execution

this keeps secrets out of version control while maintaining reproducibility.
