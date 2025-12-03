

 # Comprehensive Automated Benchmark Suite

This directory contains a complete automated testing and benchmarking framework for the Read-Verify-Rotate privacy-preserving identity system.

## Overview

The benchmark suite measures performance across multiple dimensions:

1. **Component-Level Timing**: Breakdown of every operation from query parsing to proof verification
2. **K-Anonymity Impact**: How the k parameter affects latency
3. **Merkle Batching**: Performance difference between batched and non-batched tree rebuilds
4. **Multi-User Cohorts**: Scaling behavior for grouped queries
5. **CRUD Operations**: Insert and update timings

## Quick Start

### Automated Execution

```bash
# Fast benchmarks (256 users, k=1-9, ~15-30 min)
./benchmarks/run_comprehensive_benchmarks.sh --quick

# Full benchmarks (1024 users, k=1-15, ~60-120 min)
./benchmarks/run_comprehensive_benchmarks.sh --full

# Custom configuration
export BENCH_USERS=512
export BENCH_K_VALUES="1 5 10 15 20"
export BENCH_COHORT_SIZES="10 20 30"
export BENCH_QUERY="users age greater than 25"
./benchmarks/run_comprehensive_benchmarks.sh --custom
```

### Manual Execution

```bash
# Run benchmarks
"/Users/tanjan/Desktop/Private Identity Verifier/.venv/bin/python" \
  benchmarks/comprehensive_benchmark.py \
  --total-users 512 \
  --k-values 1 3 5 7 9 11 13 15 \
  --cohort-sizes 5 10 20 \
  --natural-query "users over 21" \
  --clean

# Generate plots
"/Users/tanjan/Desktop/Private Identity Verifier/.venv/bin/python" \
  benchmarks/plot_comprehensive.py \
  --output-dir artifacts/metrics
```

## Architecture

### Components

#### 1. **Query Parser** (`query_parser.py`)
Translates natural language queries into structured predicate requests.

**Supported Patterns:**
- "users over 21" → `age >= 21`
- "active licenses" → `status >= 1`
- "fewer than 3 violations" → `violations < 3`
- "licenses expiring after 2025" → `expiry_year >= 2025`

**Example:**
```python
from query_parser import QueryParser

parser = QueryParser()
predicate = parser.build_predicate_request("users over 25")
# Returns: {"attribute_index": 0, "threshold": 25}
```

#### 2. **Comprehensive Benchmark** (`comprehensive_benchmark.py`)
Main benchmark harness with component-level timing instrumentation.

**Key Features:**
- Pre-seeded database fixture (excludes initialization overhead)
- Detailed timing for: query parse, decrypt, predicate proof, rotation proof, server verify, merkle rebuild
- Multiple scenarios: non-batched vs batched merkle, k-value sweeps, cohorts, CRUD

**Architecture:**
```
┌──────────────────────────────────────────────────┐
│          PRE-SEEDED DATABASE (1024 users)        │
│   Created once; reused across all benchmarks     │
└──────────────────────────────────────────────────┘
                      ↓
    ┌─────────────────┬─────────────────┬──────────────────┐
    │                 │                 │                  │
┌───▼────┐   ┌────────▼───────┐  ┌──────▼───────┐  ┌──────▼──────┐
│ K-Sweep│   │ K-Sweep        │  │ Insert/Update│  │ Multi-User  │
│ (Non-  │   │ (Batched       │  │ Operations   │  │ Cohort      │
│ Batched│   │ Merkle)        │  │              │  │ Queries     │
└────────┘   └────────────────┘  └──────────────┘  └─────────────┘
     │              │                   │                  │
     └──────────────┴───────────────────┴──────────────────┘
                           ↓
                 ┌─────────────────────┐
                 │   CSV Output Files  │
                 │  k_value_sweep.csv  │
                 │  insert_update.csv  │
                 │ multi_user_cohort.csv│
                 └─────────────────────┘
                           ↓
                 ┌─────────────────────┐
                 │    Plot Generator   │
                 └─────────────────────┘
                           ↓
     ┌─────────────────────┬─────────────────────┬──────────────────┐
┌────▼──────┐   ┌──────────▼────┐   ┌────────────▼──┐   ┌──────────▼────┐
│ K vs      │   │  Component     │   │  Batched vs   │   │  Cohort       │
│ Latency   │   │  Breakdown     │   │  Non-Batched  │   │  Scaling      │
│ (line)    │   │  (stacked bar) │   │  (bar chart)  │   │  (dual plot)  │
└───────────┘   └────────────────┘   └───────────────┘   └───────────────┘
```

#### 3. **Plot Generator** (`plot_comprehensive.py`)
Generates publication-quality visualizations.

**Output Plots:**
1. `k_sweep_total_latency.png` - Total latency vs k (line chart)
2. `k_sweep_component_breakdown.png` - Component breakdown (stacked bars)
3. `batched_vs_nonbatched_comparison.png` - Merkle batching comparison (grouped bars)
4. `cohort_scaling.png` - Multi-user scaling (dual plot)
5. `insert_update_operations.png` - CRUD timings (horizontal bars)

## Benchmark Scenarios

### 1. Single-Query K-Value Sweep (Non-Batched Merkle)

**Measures:** Impact of k-anonymity parameter on end-to-end latency without merkle batching.

**Component Breakdown:**
- **Query Parse**: Natural language → predicate structure (~0.1-0.5 ms)
- **Client Decrypt**: AES-GCM decryption + inner root verification (~10-50 ms)
- **Predicate Proof**: Groth16 witness generation + proof (~8,000-12,000 ms on first cold run, ~50-200 ms warm)
- **Rotation Proof**: Groth16 witness generation + proof (~8,000-12,000 ms on first cold run, ~50-200 ms warm)
- **Server Verify**: Groth16 verification + nullifier check + merkle rebuild (~200-500 ms)

**Expected Results:**
- K has minimal impact on latency (slight increase due to larger anonymity set shuffle)
- First proof generation is ~40x slower (cold circuit loading)
- Dominant cost: Groth16 proof generation (rotation + predicate)

### 2. Single-Query K-Value Sweep (Batched Merkle)

**Measures:** Same as #1 but with merkle rebuild deferred (batching).

**Expected Results:**
- 20-40% faster than non-batched for single queries
- Merkle rebuild cost amortized when processing multiple updates in batch

### 3. Insert and Update Operations

**Measures:** Time to insert new user and update existing attribute.

**Operations:**
- **Insert New User**: Register + encrypt + merkle rebuild
- **Update Attribute (Rotation)**: Full rotation flow with k=3

**Expected Results:**
- Insert: ~300-500 ms (dominated by Poseidon hash bridge calls)
- Update: ~10,000-12,000 ms (first rotation proof), ~200-500 ms (subsequent)

### 4. Multi-User Cohort Queries

**Measures:** Performance when querying multiple users simultaneously (e.g., "give me 10 users over 25").

**Parameters:**
- Cohort sizes: 5, 10, 20, 30
- Higher k values (k=15) for stronger privacy

**Expected Results:**
- Total time scales linearly with cohort size
- Avg per-user time decreases slightly (amortization of setup costs)

## CSV Schemas

All benchmark results are automatically saved to CSV files in `artifacts/metrics/`. These files contain all the data needed to generate comprehensive plots and analysis.

### `k_value_sweep.csv`

**Contains:** Component-level timing breakdown for each k value, both batched and non-batched

```csv
scenario,k_value,total_duration_ms,query_parse_ms,client_decrypt_ms,predicate_proof_ms,rotation_proof_ms,server_verify_ms,merkle_rebuild_ms,notes
non_batched_merkle,1,12345.67,0.123,45.6,8765.4,3210.5,324.0,0.0,success=True
batched_merkle,1,10234.56,0.098,43.2,8654.3,3100.2,236.8,0.0,success=True
non_batched_merkle,3,12567.89,0.115,47.8,8890.1,3320.4,329.5,0.0,success=True
```

**Use for:** K-anonymity vs performance tradeoff analysis, component breakdown charts

### `insert_update.csv`

**Contains:** CRUD operation timings

```csv
operation,duration_ms,notes
Insert New User,456.78,user_index=1024
Insert New User,0.0,skipped (at max capacity 1024/1024)
Update Attribute (Rotation),10234.56,user_index=512
```

**Use for:** Database mutation performance, insert vs update comparison

### `multi_user_cohort.csv`

**Contains:** Multi-user grouped query performance

```csv
scenario,cohort_size,k_value,total_duration_ms,avg_per_user_ms,notes
multi_user_cohort,5,15,52345.67,10469.13,query='users over 21'
multi_user_cohort,10,15,102345.67,10234.57,query='users over 21'
multi_user_cohort,20,15,205678.90,10283.95,query='users over 21'
```

**Use for:** Scaling analysis, batch processing efficiency

**Note:** All three CSVs are generated by every benchmark run. Use `--clean` flag to start fresh.

## Performance Expectations

### Hardware Context
- **Target:** MacBook Air M1/M2, 8-16GB RAM
- **Database:** SQLite in-memory (for benchmarks), Postgres for production
- **Circuits:** Pre-compiled Groth16 circuits (rotation.circom, predicate.circom)

### Timing Estimates

| Operation | First Run (Cold) | Subsequent (Warm) | Notes |
|-----------|-----------------|-------------------|-------|
| Query Parse | 0.1-0.5 ms | 0.1-0.5 ms | Regex matching |
| Client Decrypt | 10-50 ms | 10-50 ms | AES-GCM + verification |
| Predicate Proof | 8,000-12,000 ms | 50-200 ms | Circuit witness + snarkjs |
| Rotation Proof | 8,000-12,000 ms | 50-200 ms | Circuit witness + snarkjs |
| Server Verify | 200-500 ms | 200-500 ms | Groth16 verify + merkle |
| **Total (k=5)** | **~20,000-30,000 ms** | **~500-1,000 ms** | End-to-end single query |

### Optimization Notes

1. **Cold Start:** First Groth16 proof is ~40x slower (circuit loading, Node.js JIT warmup)
2. **Batching:** Process multiple updates before merkle rebuild (20-40% speedup)
3. **K Value:** Minimal impact on latency (k=1 vs k=15: <5% difference)
4. **Poseidon Bridge:** Node subprocess overhead ~10-20ms per call; consider native implementation for production

## Interpreting Results

### Key Metrics

1. **End-to-End Latency**: Total time from query submission to verified proof
   - **Target:** <1 second (warm), <30 seconds (cold first query)
   
2. **Component Breakdown**: Identify bottlenecks
   - **Expected:** 80-90% time in Groth16 proof generation
   
3. **K-Anonymity Impact**: Privacy vs performance tradeoff
   - **Expected:** Logarithmic scaling with k (minimal impact)
   
4. **Batching Benefit**: Throughput improvement
   - **Expected:** 20-40% reduction in per-query latency for batches

### Red Flags

- ⚠️ **Predicate/Rotation Proof > 30s (warm):** Circuit compilation issue or Node.js not warmed
- ⚠️ **Server Verify > 1s:** Merkle tree depth too large or inefficient implementation
- ⚠️ **K scaling non-linear:** Shuffle or anonymity set generation bug
- ⚠️ **Insert > 1s:** Poseidon bridge overhead; consider caching or native implementation

## Extending the Suite

### Adding New Queries

Edit `query_parser.py`:

```python
# In QueryParser.parse():
match = re.search(r"custom pattern (\d+)", query_lower)
if match:
    threshold = int(match.group(1))
    return {
        "attribute_index": self.attribute_map["custom_field"],
        "threshold": threshold,
        "operator": ">=",
        "description": f"custom_field >= {threshold}",
    }
```

### Adding New Benchmark Scenarios

Edit `comprehensive_benchmark.py`:

```python
def benchmark_custom_scenario(...):
    timer = ComponentTimer()
    timer.start("custom_component")
    # ... your benchmark logic ...
    timer.stop("custom_component")
    return {"timings": timer.timings}

# In main():
if not args.skip_custom:
    print("\n[X/Y] Custom scenario")
    rows = benchmark_custom_scenario(...)
    append_rows(CUSTOM_CSV, CUSTOM_HEADER, rows)
```

### Adding New Plots

Edit `plot_comprehensive.py`:

```python
def plot_custom_metric(df: pd.DataFrame, output_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(10, 6))
    # ... your plot logic ...
    output_path = output_dir / "custom_metric.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"wrote {output_path}")

# In main():
custom = load_csv(args.metrics_dir / "custom.csv")
if custom is not None:
    plot_custom_metric(custom, args.output_dir)
```

## Troubleshooting

### Issue: "Groth16 proof generation failed"
**Cause:** Circuit files missing or incompatible
**Fix:** Run `./test_circuits_full.sh` to rebuild circuits

### Issue: "Nullifier already used"
**Cause:** Reusing same database without clearing nullifiers
**Fix:** Pass `--clean` flag or restart with fresh database

### Issue: "Benchmarks extremely slow (>1 hour)"
**Cause:** Running with --total-users > 512 or cold circuits
**Fix:** Start with `--quick` mode; ensure circuits pre-compiled

### Issue: "Plots show unexpected spikes"
**Cause:** Cold start on first k value
**Fix:** Expected behavior; warm runs smooth out after first iteration

### Issue: "Assert Failed in PredicateCircuit (batched mode)"
**Cause:** Outer tree not updated after batched rotation, stale merkle root
**Fix:** Benchmark now manually rebuilds outer tree after each batched test
**Technical Detail:** When `batch_merkle_rebuild=True`, the server defers tree updates. Sequential tests need fresh roots for predicate proofs, so we call `_update_outer_state()` after each k-value test.

### Issue: "Too many values for outer_path_elements"
**Cause:** Inserting user beyond max capacity (1025+ users in depth-10 tree)
**Fix:** Benchmark now skips insert when at max capacity (1024 users)
**Technical Detail:** Depth-10 outer tree supports max 1024 users (2^10). Circuits are compiled with fixed depth, so exceeding capacity causes input size mismatch.

### Issue: "Assert Failed in PredicateCircuit (cohort test)"
**Cause:** Outer tree not updated between cohort users, each rotation makes tree stale
**Fix:** Benchmark now calls `verify_rotation_proof()` with `batch_merkle_rebuild=False` after each cohort user
**Technical Detail:** Multi-user cohorts process users sequentially. Each rotation changes the outer tree, so subsequent users need the updated tree for valid merkle paths in their predicate proofs.

## References

- **Circuit Implementations:** `circuits/rotation.circom`, `circuits/predicate.circom`
- **ZK Proof Library:** snarkjs (Groth16 backend)
- **Merkle Tree:** Poseidon hash (via Node.js bridge)
- **Database:** SQLAlchemy ORM (Postgres/SQLite compatible)

## Contact

For questions or issues with the benchmark suite, open an issue in the repository.
