"""Benchmark harness for cold and warm end-to-end flows.

This script seeds a fresh database, triggers Groth16 rotation and predicate
proofs, and stores detailed timing data for each phase. Results are appended to
CSV files under artifacts/metrics.
"""

from __future__ import annotations

import argparse
import csv
import time
import secrets
import random
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from encrypted_identity_db import EncryptedIdentityDatabase
from batch_fetch_client import BatchFetchClient, EncryptedBlob
from poseidon_hash import PoseidonHash


METRICS_DIR = Path("artifacts/metrics")
END_TO_END_CSV = METRICS_DIR / "end_to_end.csv"
WARM_CSV = METRICS_DIR / "warm_hysteresis.csv"

END_TO_END_HEADER = ["scenario", "iteration", "phase", "duration_ms", "notes"]
WARM_HEADER = [
    "scenario",
    "iteration",
    "idle_seconds",
    "phase",
    "duration_ms",
    "notes",
]


def append_rows(path: Path, header: List[str], rows: Iterable[Dict[str, object]]) -> None:
    """Append rows to a CSV file, creating it with headers when missing."""

    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists()

    with path.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header)
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def seed_database(total_users: int, target_index: int, rng_seed: int) -> Tuple[
    EncryptedIdentityDatabase,
    Dict[int, bytes],
    float,
]:
    """Create a fresh database populated with synthetic users."""

    db = EncryptedIdentityDatabase("sqlite:///:memory:")
    rng = random.Random(rng_seed)

    start = time.perf_counter()
    user_keys: Dict[int, bytes] = {}

    for idx in range(total_users):
        attributes = [rng.randint(18, 80) for _ in range(8)]
        if idx == target_index:
            attributes[0] = max(30, attributes[0])
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
    init_ms = (time.perf_counter() - start) * 1000.0

    return db, user_keys, init_ms


def make_server_fetch(db: EncryptedIdentityDatabase):
    """Return a callable that converts DB rows into EncryptedBlob objects."""

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


def measure_poseidon_boot() -> float:
    """Trigger the first Poseidon call to account for bridge startup."""

    leaves = [b"\x00" * 32 for _ in range(2)]
    start = time.perf_counter()
    PoseidonHash.compute_merkle_root(leaves)
    return (time.perf_counter() - start) * 1000.0


def run_cold_start(
    total_users: int,
    target_index: int,
    k_decoys: int,
    rng_seed: int,
) -> Tuple[EncryptedIdentityDatabase, BatchFetchClient, List[Dict[str, object]]]:
    """Execute the cold start measurement suite."""

    rows: List[Dict[str, object]] = []
    db, user_keys, init_ms = seed_database(total_users, target_index, rng_seed)

    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "database_init_seed",
            "duration_ms": round(init_ms, 3),
            "notes": f"total_users={total_users}",
        }
    )

    poseidon_ms = measure_poseidon_boot()
    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "poseidon_bridge_boot",
            "duration_ms": round(poseidon_ms, 3),
            "notes": "first merkle call",
        }
    )

    client = BatchFetchClient(
        user_id="benchmark-user",
        encryption_key=user_keys[target_index],
        num_attributes=8,
        verbose=False,
    )

    server_timing: Dict[str, float] = {}
    server_fetch = make_server_fetch(db)

    def server_update_wrapper(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
        start = time.perf_counter()
        success = db.verify_rotation_proof(
            user_index=target_index,
            proof=proof,
            new_inner_root=new_inner_root,
            nullifier=nullifier_hex,
            new_encrypted_data=new_encrypted_blob,
            public_signals=public_signals,
        )
        server_timing["server_verification_ms"] = (
            time.perf_counter() - start
        ) * 1000.0
        return success

    predicate_request = {"attribute_index": 0, "threshold": 21}

    outer_root = db.get_outer_root()
    _decrypted, proof_bundle = client.fetch_and_rotate(
        target_index=target_index,
        k_decoys=k_decoys,
        server_fetch_fn=server_fetch,
        server_update_fn=server_update_wrapper,
        outer_root=outer_root,
        total_users=db.get_user_count(),
        predicate_request=predicate_request,
    )

    timings = proof_bundle.get("timings", {})
    rotation_ms = timings.get("rotation_proof_ms", 0.0)
    predicate_ms = timings.get("predicate_proof_ms", 0.0)
    total_ms = timings.get("total_fetch_and_rotate_ms", 0.0)

    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "fetch_and_rotate_total",
            "duration_ms": round(total_ms, 3),
            "notes": f"k={k_decoys}",
        }
    )
    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "rotation_proof",
            "duration_ms": round(rotation_ms, 3),
            "notes": "groth16",
        }
    )
    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "predicate_proof",
            "duration_ms": round(predicate_ms, 3),
            "notes": "groth16",
        }
    )

    server_ms = server_timing.get("server_verification_ms", 0.0)
    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "server_verification",
            "duration_ms": round(server_ms, 3),
            "notes": "verify_rotation_proof",
        }
    )

    predicate_bundle = proof_bundle.get("predicate")
    ext_start = time.perf_counter()
    predicate_valid = False
    if predicate_bundle:
        predicate_valid = db._verify_groth16_proof(  # pylint: disable=protected-access
            predicate_bundle["proof"],
            predicate_bundle["public_signals"],
            "predicate",
        )
    external_ms = (time.perf_counter() - ext_start) * 1000.0
    rows.append(
        {
            "scenario": "cold_boot",
            "iteration": 1,
            "phase": "external_verification",
            "duration_ms": round(external_ms, 3),
            "notes": f"predicate_valid={predicate_valid}",
        }
    )

    return db, user_keys, rows


def run_warm_cycles(
    db: EncryptedIdentityDatabase,
    encryption_key: bytes,
    target_index: int,
    k_decoys: int,
    idle_values: List[int],
    iterations: int,
    sleep_cap: int,
) -> List[Dict[str, object]]:
    """Measure warm fetch-and-rotate cycles with optional idle gaps."""

    rows: List[Dict[str, object]] = []
    server_fetch = make_server_fetch(db)

    for idle_seconds in idle_values:
        for iteration in range(1, iterations + 1):
            # Create fresh client for each iteration to avoid nullifier reuse
            fresh_client = BatchFetchClient(
                user_id=f"user_{target_index}",
                encryption_key=encryption_key,
                num_attributes=8,
                verbose=False,
            )
            
            sleep_time = idle_seconds
            if sleep_cap > 0:
                sleep_time = min(idle_seconds, sleep_cap)
            if sleep_time > 0:
                time.sleep(sleep_time)

            server_timing: Dict[str, float] = {}

            def server_update_wrapper(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
                start = time.perf_counter()
                success = db.verify_rotation_proof(
                    user_index=target_index,
                    proof=proof,
                    new_inner_root=new_inner_root,
                    nullifier=nullifier_hex,
                    new_encrypted_data=new_encrypted_blob,
                    public_signals=public_signals,
                )
                server_timing["server_verification_ms"] = (
                    time.perf_counter() - start
                ) * 1000.0
                return success

            outer_root = db.get_outer_root()
            _decrypted, proof_bundle = fresh_client.fetch_and_rotate(
                target_index=target_index,
                k_decoys=k_decoys,
                server_fetch_fn=server_fetch,
                server_update_fn=server_update_wrapper,
                outer_root=outer_root,
                total_users=db.get_user_count(),
                predicate_request=None,  # skip predicate for warm cycles
            )

            timings = proof_bundle.get("timings", {})
            predicate_bundle = proof_bundle.get("predicate")

            external_ms = 0.0
            predicate_valid = None
            if predicate_bundle:
                ext_start = time.perf_counter()
                predicate_valid = db._verify_groth16_proof(  # pylint: disable=protected-access
                    predicate_bundle["proof"],
                    predicate_bundle["public_signals"],
                    "predicate",
                )
                external_ms = (time.perf_counter() - ext_start) * 1000.0

            rows.extend(
                [
                    {
                        "scenario": "warm_cycle",
                        "iteration": iteration,
                        "idle_seconds": idle_seconds,
                        "phase": "fetch_and_rotate_total",
                        "duration_ms": round(
                            timings.get("total_fetch_and_rotate_ms", 0.0), 3
                        ),
                        "notes": f"k={k_decoys};sleep={sleep_time}",
                    },
                    {
                        "scenario": "warm_cycle",
                        "iteration": iteration,
                        "idle_seconds": idle_seconds,
                        "phase": "rotation_proof",
                        "duration_ms": round(
                            timings.get("rotation_proof_ms", 0.0), 3
                        ),
                        "notes": f"groth16;sleep={sleep_time}",
                    },
                    {
                        "scenario": "warm_cycle",
                        "iteration": iteration,
                        "idle_seconds": idle_seconds,
                        "phase": "predicate_proof",
                        "duration_ms": round(
                            timings.get("predicate_proof_ms", 0.0), 3
                        ),
                        "notes": f"groth16;sleep={sleep_time}" if predicate_bundle else f"skipped;sleep={sleep_time}",
                    },
                    {
                        "scenario": "warm_cycle",
                        "iteration": iteration,
                        "idle_seconds": idle_seconds,
                        "phase": "server_verification",
                        "duration_ms": round(
                            server_timing.get("server_verification_ms", 0.0), 3
                        ),
                        "notes": f"verify_rotation_proof;sleep={sleep_time}",
                    },
                    {
                        "scenario": "warm_cycle",
                        "iteration": iteration,
                        "idle_seconds": idle_seconds,
                        "phase": "external_verification",
                        "duration_ms": round(external_ms, 3),
                        "notes": f"predicate_valid={predicate_valid};sleep={sleep_time}" if predicate_bundle else f"skipped;sleep={sleep_time}",
                    },
                ]
            )

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end benchmarking harness")
    parser.add_argument("--total-users", type=int, default=128, help="Number of users to seed")
    parser.add_argument("--target-index", type=int, default=10, help="Target user index")
    parser.add_argument("--k-decoys", type=int, default=5, help="Number of decoys for k-anonymity")
    parser.add_argument(
        "--warm-iterations",
        type=int,
        default=3,
        help="Warm invocation repetitions per idle window",
    )
    parser.add_argument(
        "--warm-idle-seconds",
        type=int,
        nargs="*",
        default=[0, 60, 300],
        help="Idle gaps to test between warm invocations",
    )
    parser.add_argument(
        "--sleep-cap",
        type=int,
        default=0,
        help="Maximum seconds to sleep per warm iteration (0 disables sleeping)",
    )
    parser.add_argument("--rng-seed", type=int, default=1337, help="Seed for synthetic data")

    args = parser.parse_args()

    db, user_keys, cold_rows = run_cold_start(
        total_users=args.total_users,
        target_index=args.target_index,
        k_decoys=args.k_decoys,
        rng_seed=args.rng_seed,
    )

    warm_rows = run_warm_cycles(
        db=db,
        encryption_key=user_keys[args.target_index],
        target_index=args.target_index,
        k_decoys=args.k_decoys,
        idle_values=args.warm_idle_seconds,
        iterations=args.warm_iterations,
        sleep_cap=args.sleep_cap,
    )

    append_rows(END_TO_END_CSV, END_TO_END_HEADER, cold_rows)
    append_rows(WARM_CSV, WARM_HEADER, warm_rows)

    print(f"wrote {len(cold_rows)} rows to {END_TO_END_CSV}")
    print(f"wrote {len(warm_rows)} rows to {WARM_CSV}")


if __name__ == "__main__":
    main()
