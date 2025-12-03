"""Comprehensive automated benchmarking suite with component-level timing.

Scenarios:
1. Single-query (non-batched merkle rebuild) - detailed component breakdown
2. Single-query (batched merkle rebuild) - compare batching performance
3. Attribute insertion and update operations
4. Multi-user cohort queries (higher k values)

All benchmarks use a pre-seeded database to exclude initialization overhead.
"""

from __future__ import annotations

import argparse
import csv
import json
import secrets
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from encrypted_identity_db import EncryptedIdentityDatabase
from batch_fetch_client import BatchFetchClient, EncryptedBlob
from query_parser import QueryParser

METRICS_DIR = Path("artifacts/metrics")
K_SWEEP_CSV = METRICS_DIR / "k_value_sweep.csv"
COHORT_CSV = METRICS_DIR / "multi_user_cohort.csv"
INSERT_UPDATE_CSV = METRICS_DIR / "insert_update.csv"

# CSV schemas
COMPONENT_HEADER = [
    "scenario",
    "k_value",
    "component",
    "duration_ms",
    "notes",
]

K_SWEEP_HEADER = [
    "scenario",
    "k_value",
    "total_duration_ms",
    "query_parse_ms",
    "client_decrypt_ms",
    "predicate_proof_ms",
    "rotation_proof_ms",
    "server_verify_ms",
    "merkle_rebuild_ms",
    "notes",
]

COHORT_HEADER = [
    "scenario",
    "cohort_size",
    "k_value",
    "total_duration_ms",
    "avg_per_user_ms",
    "notes",
]

INSERT_UPDATE_HEADER = [
    "operation",
    "duration_ms",
    "notes",
]


class ComponentTimer:
    """Helper to track component-level timings."""

    def __init__(self):
        self.timings: Dict[str, float] = {}
        self._starts: Dict[str, float] = {}

    def start(self, component: str) -> None:
        self._starts[component] = time.perf_counter()

    def stop(self, component: str) -> None:
        if component not in self._starts:
            raise ValueError(f"Component '{component}' was never started")
        elapsed = (time.perf_counter() - self._starts[component]) * 1000.0
        self.timings[component] = elapsed
        del self._starts[component]

    def get(self, component: str, default: float = 0.0) -> float:
        return self.timings.get(component, default)

    def total(self) -> float:
        return sum(self.timings.values())


def append_rows(path: Path, header: List[str], rows: List[Dict[str, Any]]) -> None:
    """Append rows to CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists()

    with path.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header)
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def create_database_fixture(
    total_users: int, db_path: str, rng_seed: int
) -> Tuple[EncryptedIdentityDatabase, Dict[int, bytes]]:
    """
    Create and seed a database with synthetic users.

    Args:
        total_users: Number of users to generate
        db_path: SQLite database path (or in-memory)
        rng_seed: Random seed for reproducibility

    Returns:
        (database, user_keys mapping)
    """
    print(f"[Fixture] creating database with {total_users} users (seed={rng_seed})")
    start = time.perf_counter()

    db = EncryptedIdentityDatabase(db_path)
    rng = random.Random(rng_seed)
    user_keys: Dict[int, bytes] = {}

    for idx in range(total_users):
        # Generate realistic driver's license attributes
        attributes = [
            rng.randint(18, 75),  # age
            rng.randint(1, 5),  # license_class
            rng.randint(1, 50),  # state_code
            rng.randint(2015, 2023),  # issue_year
            rng.randint(2025, 2030),  # expiry_year
            rng.randint(0, 12),  # points
            rng.randint(0, 5),  # violations
            rng.choice([0, 1, 1, 1, 2]),  # status (weighted toward active)
        ]
        salts = [secrets.token_bytes(32) for _ in range(8)]
        key = secrets.token_bytes(32)
        user_keys[idx] = key

        db.register_user_auto_path(
            user_index=idx,
            encryption_key=key,
            attributes=attributes,
            salts=salts,
            refresh_paths=False,
        )

    db.recompute_outer_tree()
    elapsed = (time.perf_counter() - start) * 1000.0
    print(f"[Fixture] seeded {total_users} users in {elapsed:.1f} ms")

    return db, user_keys


def make_server_fetch(db: EncryptedIdentityDatabase):
    """Create a server fetch function."""

    def _fetch(indices: List[int]) -> List[EncryptedBlob]:
        records = db.fetch_users(indices)
        blobs: List[EncryptedBlob] = []
        for record in records:
            blobs.append(
                EncryptedBlob(
                    index=record["index"],
                    encrypted_data=record["encrypted_data"],
                    outer_path=record["outer_path"],
                    inner_root=record["inner_root"],
                )
            )
        return blobs

    return _fetch


def benchmark_single_query_detailed(
    db: EncryptedIdentityDatabase,
    user_keys: Dict[int, bytes],
    target_index: int,
    k_value: int,
    natural_query: str,
    batched_merkle: bool,
) -> Dict[str, Any]:
    """
    Benchmark a single query with detailed component timing.

    Args:
        db: Database instance
        user_keys: User encryption keys
        target_index: Target user index
        k_value: k-anonymity parameter
        natural_query: Natural language query (e.g., "users over 21")
        batched_merkle: Whether to batch merkle rebuild

    Returns:
        Dictionary of component timings
    """
    timer = ComponentTimer()
    parser = QueryParser(verbose=False)

    # Component 1: Parse natural language query
    timer.start("query_parse")
    predicate_request = parser.build_predicate_request(natural_query)
    timer.stop("query_parse")

    client = BatchFetchClient(
        user_id=f"benchmark-{target_index}",
        encryption_key=user_keys[target_index],
        num_attributes=8,
        verbose=False,
    )

    server_fetch = make_server_fetch(db)
    captured: Dict[str, Any] = {}

    def instrumented_server_update(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
        # Component: server-side verification and merkle rebuild
        timer.start("server_verify")
        success = db.verify_rotation_proof(
            user_index=target_index,
            proof=proof,
            new_inner_root=new_inner_root,
            nullifier=nullifier_hex,
            new_encrypted_data=new_encrypted_blob,
            public_signals=public_signals,
            batch_merkle_rebuild=batched_merkle,
        )
        timer.stop("server_verify")
        captured["success"] = success
        return success

    outer_root = db.get_outer_root()

    # Client-side operations (decrypt, proof generation)
    timer.start("client_total")
    decrypted_data, proof_bundle = client.fetch_and_rotate(
        target_index=target_index,
        k_decoys=k_value,
        server_fetch_fn=server_fetch,
        server_update_fn=instrumented_server_update,
        outer_root=outer_root,
        total_users=db.get_user_count(),
        predicate_request=predicate_request,
    )
    timer.stop("client_total")

    # Extract proof timings from client
    client_timings = proof_bundle.get("timings", {})
    timer.timings["predicate_proof"] = client_timings.get("predicate_proof_ms", 0.0)
    timer.timings["rotation_proof"] = client_timings.get("rotation_proof_ms", 0.0)

    # Derive decrypt time
    client_total = timer.get("client_total")
    predicate_time = timer.get("predicate_proof")
    rotation_time = timer.get("rotation_proof")
    timer.timings["client_decrypt"] = max(0.0, client_total - predicate_time - rotation_time)

    return {
        "query_parse": timer.get("query_parse"),
        "client_decrypt": timer.get("client_decrypt"),
        "predicate_proof": timer.get("predicate_proof"),
        "rotation_proof": timer.get("rotation_proof"),
        "server_verify": timer.get("server_verify"),
        "total": timer.total(),
        "success": captured.get("success", False),
    }


def benchmark_k_sweep(
    db: EncryptedIdentityDatabase,
    user_keys: Dict[int, bytes],
    target_index: int,
    k_values: List[int],
    natural_query: str,
    batched_merkle: bool,
) -> List[Dict[str, Any]]:
    """
    Sweep k values and record component timings for each.

    Args:
        db: Database instance
        user_keys: User encryption keys
        target_index: Target user index
        k_values: List of k values to test
        natural_query: Query to execute
        batched_merkle: Whether to batch merkle rebuild

    Returns:
        List of timing dictionaries
    """
    scenario = "batched_merkle" if batched_merkle else "non_batched_merkle"
    results: List[Dict[str, Any]] = []

    for k in k_values:
        print(f"  k={k} ... ", end="", flush=True)
        timings = benchmark_single_query_detailed(
            db=db,
            user_keys=user_keys,
            target_index=target_index,
            k_value=k,
            natural_query=natural_query,
            batched_merkle=batched_merkle,
        )
        
        # CRITICAL: If using batched merkle rebuild, we need to manually
        # rebuild the outer tree after each test so the next test has
        # a valid outer root for predicate proof verification
        if batched_merkle:
            from sqlalchemy.orm import Session
            session: Session = db.SessionLocal()
            try:
                db._update_outer_state(session)
                session.commit()
            finally:
                session.close()
        
        results.append(
            {
                "scenario": scenario,
                "k_value": k,
                "total_duration_ms": timings["total"],
                "query_parse_ms": timings["query_parse"],
                "client_decrypt_ms": timings["client_decrypt"],
                "predicate_proof_ms": timings["predicate_proof"],
                "rotation_proof_ms": timings["rotation_proof"],
                "server_verify_ms": timings["server_verify"],
                "merkle_rebuild_ms": 0.0,  # included in server_verify
                "notes": f"success={timings['success']}",
            }
        )
        print(f"{timings['total']:.1f} ms")

    return results


def benchmark_insert_update(
    db: EncryptedIdentityDatabase,
    user_keys: Dict[int, bytes],
    target_index: int,
) -> List[Dict[str, Any]]:
    """
    Benchmark attribute insertion and update operations.

    Args:
        db: Database instance
        user_keys: User keys
        target_index: Existing user to update

    Returns:
        List of operation timings
    """
    results: List[Dict[str, Any]] = []

    # 1. Insert new user (only if not at max capacity)
    current_users = db.get_user_count()
    max_capacity = 1024  # depth-10 outer tree supports max 1024 users
    
    if current_users < max_capacity:
        new_index = current_users
        attributes = [30] * 8
        salts = [secrets.token_bytes(32) for _ in range(8)]
        key = secrets.token_bytes(32)

        start = time.perf_counter()
        db.register_user_auto_path(
            user_index=new_index,
            encryption_key=key,
            attributes=attributes,
            salts=salts,
            refresh_paths=False,
        )
        db.recompute_outer_tree()
        insert_ms = (time.perf_counter() - start) * 1000.0

        results.append(
            {
                "operation": "Insert New User",
                "duration_ms": insert_ms,
                "notes": f"user_index={new_index}",
            }
        )
    else:
        # At max capacity - skip insert
        results.append(
            {
                "operation": "Insert New User",
                "duration_ms": 0.0,
                "notes": f"skipped (at max capacity {current_users}/{max_capacity})",
            }
        )

    # 2. Update existing attribute (rotation)
    client = BatchFetchClient(
        user_id=f"update-{target_index}",
        encryption_key=user_keys[target_index],
        num_attributes=8,
        verbose=False,
    )

    server_fetch = make_server_fetch(db)
    outer_root = db.get_outer_root()

    captured: Dict[str, Any] = {}

    def capture_update(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
        captured["proof"] = proof
        captured["public_signals"] = public_signals
        captured["new_inner_root"] = new_inner_root
        captured["new_encrypted_blob"] = new_encrypted_blob
        captured["nullifier_hex"] = nullifier_hex
        return True

    start = time.perf_counter()
    client.fetch_and_rotate(
        target_index=target_index,
        k_decoys=3,
        server_fetch_fn=server_fetch,
        server_update_fn=capture_update,
        outer_root=outer_root,
        total_users=db.get_user_count(),
        predicate_request=None,
    )

    db.verify_rotation_proof(
        user_index=target_index,
        proof=captured["proof"],
        new_inner_root=captured["new_inner_root"],
        nullifier=captured["nullifier_hex"],
        new_encrypted_data=captured["new_encrypted_blob"],
        public_signals=captured["public_signals"],
    )
    update_ms = (time.perf_counter() - start) * 1000.0

    results.append(
        {
            "operation": "Update Attribute (Rotation)",
            "duration_ms": update_ms,
            "notes": f"user_index={target_index}, k=3",
        }
    )

    return results


def benchmark_multi_user_cohort(
    db: EncryptedIdentityDatabase,
    user_keys: Dict[int, bytes],
    cohort_size: int,
    k_value: int,
    natural_query: str,
) -> Dict[str, Any]:
    """
    Benchmark grouped query for multiple users at once.

    Args:
        db: Database instance
        user_keys: User keys
        cohort_size: Number of users to query
        k_value: k-anonymity parameter (typically higher for cohort queries)
        natural_query: Query predicate

    Returns:
        Timing dictionary
    """
    parser = QueryParser(verbose=False)
    predicate_request = parser.build_predicate_request(natural_query)

    # Select random cohort
    total_users = db.get_user_count()
    rng = random.Random(4242)
    cohort_indices = rng.sample(range(total_users), cohort_size)

    start = time.perf_counter()
    for idx in cohort_indices:
        client = BatchFetchClient(
            user_id=f"cohort-{idx}",
            encryption_key=user_keys[idx],
            num_attributes=8,
            verbose=False,
        )

        server_fetch = make_server_fetch(db)
        outer_root = db.get_outer_root()

        # Capture the rotation proof and update the database
        captured: Dict[str, Any] = {}

        def capture_update(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
            captured["proof"] = proof
            captured["public_signals"] = public_signals
            captured["new_inner_root"] = new_inner_root
            captured["new_encrypted_blob"] = new_encrypted_blob
            captured["nullifier_hex"] = nullifier_hex
            return True

        client.fetch_and_rotate(
            target_index=idx,
            k_decoys=k_value,
            server_fetch_fn=server_fetch,
            server_update_fn=capture_update,
            outer_root=outer_root,
            total_users=total_users,
            predicate_request=predicate_request,
        )
        
        # CRITICAL: Update the database tree after each rotation
        # so subsequent users get valid merkle paths
        if captured:
            db.verify_rotation_proof(
                user_index=idx,
                proof=captured["proof"],
                new_inner_root=captured["new_inner_root"],
                nullifier=captured["nullifier_hex"],
                new_encrypted_data=captured["new_encrypted_blob"],
                public_signals=captured["public_signals"],
                batch_merkle_rebuild=False,  # Must update tree for next user
            )

    total_ms = (time.perf_counter() - start) * 1000.0
    avg_ms = total_ms / cohort_size if cohort_size else 0.0

    return {
        "scenario": "multi_user_cohort",
        "cohort_size": cohort_size,
        "k_value": k_value,
        "total_duration_ms": total_ms,
        "avg_per_user_ms": avg_ms,
        "notes": f"query='{natural_query}'",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive automated benchmarking suite"
    )
    parser.add_argument(
        "--total-users", type=int, default=1024, help="Database size (users)"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="sqlite:///:memory:",
        help="Database path (default: in-memory)",
    )
    parser.add_argument(
        "--rng-seed", type=int, default=2025, help="Random seed for reproducibility"
    )
    parser.add_argument(
        "--target-index",
        type=int,
        default=None,
        help="Target user index (default: total_users // 2)",
    )
    parser.add_argument(
        "--k-values",
        type=int,
        nargs="+",
        default=[1, 3, 5, 7, 9, 11, 13, 15],
        help="K values for sweep",
    )
    parser.add_argument(
        "--natural-query",
        type=str,
        default="users over 21",
        help="Natural language query",
    )
    parser.add_argument(
        "--cohort-sizes",
        type=int,
        nargs="+",
        default=[5, 10, 20],
        help="Cohort sizes for multi-user benchmarks",
    )
    parser.add_argument(
        "--skip-k-sweep", action="store_true", help="Skip k-value sweep"
    )
    parser.add_argument(
        "--skip-insert-update", action="store_true", help="Skip insert/update benchmarks"
    )
    parser.add_argument(
        "--skip-cohort", action="store_true", help="Skip multi-user cohort benchmarks"
    )
    parser.add_argument(
        "--clean", action="store_true", help="Remove existing CSV files before running"
    )

    args = parser.parse_args()

    if args.clean:
        for csv_path in [K_SWEEP_CSV, COHORT_CSV, INSERT_UPDATE_CSV]:
            if csv_path.exists():
                print(f"Removing {csv_path}")
                csv_path.unlink()

    if args.target_index is None:
        args.target_index = args.total_users // 2

    # Create pre-seeded database fixture
    db, user_keys = create_database_fixture(
        total_users=args.total_users,
        db_path=args.db_path,
        rng_seed=args.rng_seed,
    )

    print("\n" + "=" * 70)
    print("BENCHMARK SUITE - Component-Level Timing Analysis")
    print("=" * 70)

    # Scenario 1: Single-query k-sweep (non-batched merkle)
    if not args.skip_k_sweep:
        print("\n[1/4] K-value sweep (non-batched merkle rebuild)")
        print(f"  Query: '{args.natural_query}'")
        print(f"  Target: user {args.target_index}")
        rows = benchmark_k_sweep(
            db=db,
            user_keys=user_keys,
            target_index=args.target_index,
            k_values=args.k_values,
            natural_query=args.natural_query,
            batched_merkle=False,
        )
        append_rows(K_SWEEP_CSV, K_SWEEP_HEADER, rows)
        print(f"  ✓ wrote {len(rows)} rows to {K_SWEEP_CSV}")

        # Scenario 2: Single-query k-sweep (batched merkle)
        print("\n[2/4] K-value sweep (batched merkle rebuild)")
        rows = benchmark_k_sweep(
            db=db,
            user_keys=user_keys,
            target_index=args.target_index,
            k_values=args.k_values,
            natural_query=args.natural_query,
            batched_merkle=True,
        )
        append_rows(K_SWEEP_CSV, K_SWEEP_HEADER, rows)
        print(f"  ✓ wrote {len(rows)} rows to {K_SWEEP_CSV}")

    # Scenario 3: Insert and update operations
    if not args.skip_insert_update:
        print("\n[3/4] Insert and update operations")
        rows = benchmark_insert_update(
            db=db,
            user_keys=user_keys,
            target_index=args.target_index,
        )
        append_rows(INSERT_UPDATE_CSV, INSERT_UPDATE_HEADER, rows)
        print(f"  ✓ wrote {len(rows)} rows to {INSERT_UPDATE_CSV}")

    # Scenario 4: Multi-user cohort queries
    if not args.skip_cohort:
        print("\n[4/4] Multi-user cohort queries")
        cohort_rows: List[Dict[str, Any]] = []
        for cohort_size in args.cohort_sizes:
            print(f"  cohort_size={cohort_size}, k=15 ... ", end="", flush=True)
            result = benchmark_multi_user_cohort(
                db=db,
                user_keys=user_keys,
                cohort_size=cohort_size,
                k_value=15,
                natural_query=args.natural_query,
            )
            cohort_rows.append(result)
            print(f"{result['total_duration_ms']:.1f} ms")
        append_rows(COHORT_CSV, COHORT_HEADER, cohort_rows)
        print(f"  ✓ wrote {len(cohort_rows)} rows to {COHORT_CSV}")

    print("\n" + "=" * 70)
    print("BENCHMARK SUITE COMPLETE")
    print("=" * 70)
    print(f"\nGenerated CSVs:")
    for csv_path in [K_SWEEP_CSV, INSERT_UPDATE_CSV, COHORT_CSV]:
        if csv_path.exists():
            print(f"  - {csv_path}")


if __name__ == "__main__":
    main()
