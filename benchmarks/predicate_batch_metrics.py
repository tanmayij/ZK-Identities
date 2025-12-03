"""Grouped predicate benchmarking script.

Runs the client pipeline for varying cohort sizes and records timing data for
age, citizenship, and license category policy checks. Each cohort is processed
on a fresh database snapshot to keep measurements independent.
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


METRICS_DIR = Path("artifacts/metrics")
PREDICATE_CSV = METRICS_DIR / "predicate_batch.csv"

CSV_HEADER = [
    "scenario",
    "cohort_size",
    "user_index",
    "phase",
    "duration_ms",
    "notes",
]


def append_rows(path: Path, header: List[str], rows: Iterable[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists()

    with path.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header)
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def seed_database(total_users: int, rng_seed: int) -> Tuple[
    EncryptedIdentityDatabase,
    Dict[int, bytes],
    Dict[int, List[int]],
]:
    db = EncryptedIdentityDatabase("sqlite:///:memory:")
    rng = random.Random(rng_seed)
    user_keys: Dict[int, bytes] = {}
    attributes_map: Dict[int, List[int]] = {}

    for idx in range(total_users):
        attributes = [0] * 8
        attributes[0] = rng.randint(18, 70)
        if idx % 3 == 0:
            attributes[0] = max(30, attributes[0])
            attributes[1] = 1  # citizenship code for CA
            attributes[2] = rng.choice([1, 2])  # license class G or G2
        else:
            attributes[1] = rng.choice([0, 2, 3])
            attributes[2] = rng.choice([0, 3, 4])
        for position in range(3, 8):
            attributes[position] = rng.randint(0, 9999)

        salts = [secrets.token_bytes(32) for _ in range(8)]
        key = secrets.token_bytes(32)
        user_keys[idx] = key
        attributes_map[idx] = attributes

        db.register_user_auto_path(
            user_index=idx,
            encryption_key=key,
            attributes=attributes,
            salts=salts,
            refresh_paths=False,
        )

    db.recompute_outer_tree()
    return db, user_keys, attributes_map


def make_server_fetch(db: EncryptedIdentityDatabase):
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


def matches_policy(attributes: List[int]) -> bool:
    return (
        attributes[0] >= 18
        and attributes[1] == 1
        and attributes[2] in (1, 2)
    )


def process_cohort(
    cohort_size: int,
    total_users: int,
    rng_seed: int,
    k_decoys: int,
) -> List[Dict[str, object]]:
    db, user_keys, attributes_map = seed_database(total_users, rng_seed)
    matching_indices = [idx for idx, attrs in attributes_map.items() if matches_policy(attrs)]

    if len(matching_indices) < cohort_size:
        raise RuntimeError(
            f"not enough matching users for cohort size {cohort_size} (found {len(matching_indices)})"
        )

    rows: List[Dict[str, object]] = []
    server_fetch = make_server_fetch(db)

    total_cohort_time = 0.0

    for position, user_index in enumerate(matching_indices[:cohort_size]):
        client = BatchFetchClient(
            user_id=f"predicate-user-{user_index}",
            encryption_key=user_keys[user_index],
            num_attributes=8,
            verbose=False,
        )

        server_timing: Dict[str, float] = {}

        def server_update_wrapper(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
            start = time.perf_counter()
            success = db.verify_rotation_proof(
                user_index=user_index,
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
        _decrypted, proof_bundle = client.fetch_and_rotate(
            target_index=user_index,
            k_decoys=k_decoys,
            server_fetch_fn=server_fetch,
            server_update_fn=server_update_wrapper,
            outer_root=outer_root,
            total_users=db.get_user_count(),
            predicate_request={"attribute_index": 0, "threshold": 21},
        )

        timings = proof_bundle.get("timings", {})
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

        total_time = timings.get("total_fetch_and_rotate_ms", 0.0) + external_ms
        total_cohort_time += total_time

        rows.extend(
            [
                {
                    "scenario": "grouped_predicate",
                    "cohort_size": cohort_size,
                    "user_index": user_index,
                    "phase": "fetch_and_rotate_total",
                    "duration_ms": round(
                        timings.get("total_fetch_and_rotate_ms", 0.0), 3
                    ),
                    "notes": f"position={position}",
                },
                {
                    "scenario": "grouped_predicate",
                    "cohort_size": cohort_size,
                    "user_index": user_index,
                    "phase": "rotation_proof",
                    "duration_ms": round(
                        timings.get("rotation_proof_ms", 0.0), 3
                    ),
                    "notes": "groth16",
                },
                {
                    "scenario": "grouped_predicate",
                    "cohort_size": cohort_size,
                    "user_index": user_index,
                    "phase": "predicate_proof",
                    "duration_ms": round(
                        timings.get("predicate_proof_ms", 0.0), 3
                    ),
                    "notes": "groth16",
                },
                {
                    "scenario": "grouped_predicate",
                    "cohort_size": cohort_size,
                    "user_index": user_index,
                    "phase": "server_verification",
                    "duration_ms": round(
                        server_timing.get("server_verification_ms", 0.0), 3
                    ),
                    "notes": "verify_rotation_proof",
                },
                {
                    "scenario": "grouped_predicate",
                    "cohort_size": cohort_size,
                    "user_index": user_index,
                    "phase": "external_verification",
                    "duration_ms": round(external_ms, 3),
                    "notes": f"predicate_valid={predicate_valid}",
                },
            ]
        )

    rows.append(
        {
            "scenario": "grouped_predicate",
            "cohort_size": cohort_size,
            "user_index": -1,
            "phase": "cohort_total",
            "duration_ms": round(total_cohort_time, 3),
            "notes": "sum_of_users",
        }
    )

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Grouped predicate benchmarks")
    parser.add_argument("--total-users", type=int, default=180, help="Users per scenario")
    parser.add_argument(
        "--cohort-sizes",
        type=int,
        nargs="*",
        default=[1, 5, 10],
        help="Cohort sizes to benchmark",
    )
    parser.add_argument("--k-decoys", type=int, default=5, help="k-anonymity decoys")
    parser.add_argument("--rng-seed", type=int, default=5150, help="Seed for synthetic data")

    args = parser.parse_args()

    all_rows: List[Dict[str, object]] = []

    for cohort_size in args.cohort_sizes:
        seed = args.rng_seed + cohort_size
        rows = process_cohort(
            cohort_size=cohort_size,
            total_users=args.total_users,
            rng_seed=seed,
            k_decoys=args.k_decoys,
        )
        all_rows.extend(rows)

    append_rows(PREDICATE_CSV, CSV_HEADER, all_rows)
    print(f"wrote {len(all_rows)} rows to {PREDICATE_CSV}")


if __name__ == "__main__":
    main()
