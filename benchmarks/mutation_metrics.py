"""Attribute mutation benchmarking utility.

Measures the cost of registering users, recomputing the outer Merkle tree,
and verifying rotation proofs for single and batched updates.
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
MUTATION_CSV = METRICS_DIR / "attribute_mutation.csv"

# Expanded schema to keep parameter context with each row for richer plotting
CSV_HEADER = [
    "scenario",
    "operation",
    "total_users",
    "batch_size",
    "k_decoys",
    "duration_ms",
    "seed",
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


def seed_database(total_users: int, rng_seed: int, target_index: int) -> Tuple[
    EncryptedIdentityDatabase,
    Dict[int, bytes],
]:
    db = EncryptedIdentityDatabase("sqlite:///:memory:")
    rng = random.Random(rng_seed)
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
    return db, user_keys


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


def measure_single_insert(
    db: EncryptedIdentityDatabase, *, total_users: int, seed: int
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    new_index = db.get_user_count()
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
    register_ms = (time.perf_counter() - start) * 1000.0

    start = time.perf_counter()
    db.recompute_outer_tree()
    recompute_ms = (time.perf_counter() - start) * 1000.0

    rows.append(
        {
            "scenario": "single_insert",
            "operation": "Insert One User",
            "total_users": total_users,
            "batch_size": 1,
            "k_decoys": 0,
            "duration_ms": register_ms,
            "seed": seed,
            "notes": f"user_index={new_index}",
        }
    )
    rows.append(
        {
            "scenario": "single_insert",
            "operation": "Rebuild Merkle Tree (single)",
            "total_users": total_users,
            "batch_size": 1,
            "k_decoys": 0,
            "duration_ms": recompute_ms,
            "seed": seed,
            "notes": "post_insert",
        }
    )

    return rows


def measure_batch_insert(
    db: EncryptedIdentityDatabase,
    batch_size: int,
    rng_seed: int,
    *,
    total_users: int,
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    start_index = db.get_user_count()
    rng = random.Random(rng_seed)

    start = time.perf_counter()
    for offset in range(batch_size):
        user_index = start_index + offset
        attributes = [rng.randint(18, 80) for _ in range(8)]
        salts = [secrets.token_bytes(32) for _ in range(8)]
        key = secrets.token_bytes(32)

        db.register_user_auto_path(
            user_index=user_index,
            encryption_key=key,
            attributes=attributes,
            salts=salts,
            refresh_paths=False,
        )
    batch_register_ms = (time.perf_counter() - start) * 1000.0

    start = time.perf_counter()
    db.recompute_outer_tree()
    batch_recompute_ms = (time.perf_counter() - start) * 1000.0

    avg_per_user = batch_register_ms / batch_size if batch_size else 0.0

    rows.append(
        {
            "scenario": "batch_insert",
            "operation": f"Batch Insert ({batch_size})",
            "total_users": total_users,
            "batch_size": batch_size,
            "k_decoys": 0,
            "duration_ms": batch_register_ms,
            "seed": rng_seed,
            "notes": f"avg_per_user_ms={avg_per_user:.3f}",
        }
    )
    rows.append(
        {
            "scenario": "batch_insert",
            "operation": "Rebuild Merkle Tree (batch)",
            "total_users": total_users,
            "batch_size": batch_size,
            "k_decoys": 0,
            "duration_ms": batch_recompute_ms,
            "seed": rng_seed,
            "notes": "post_batch",
        }
    )

    return rows


def measure_rotation_verification(
    db: EncryptedIdentityDatabase,
    client: BatchFetchClient,
    target_index: int,
    k_decoys: int,
    *,
    total_users: int,
    seed: int,
) -> List[Dict[str, object]]:
    server_fetch = make_server_fetch(db)
    captured: Dict[str, object] = {}

    def capture_update(proof, public_signals, new_inner_root, new_encrypted_blob, nullifier_hex):
        captured["proof"] = proof
        captured["public_signals"] = public_signals
        captured["new_inner_root"] = new_inner_root
        captured["new_encrypted_blob"] = new_encrypted_blob
        captured["nullifier_hex"] = nullifier_hex
        return True

    outer_root = db.get_outer_root()
    client.fetch_and_rotate(
        target_index=target_index,
        k_decoys=k_decoys,
        server_fetch_fn=server_fetch,
        server_update_fn=capture_update,
        outer_root=outer_root,
        total_users=db.get_user_count(),
        predicate_request={"attribute_index": 0, "threshold": 21},
    )

    start = time.perf_counter()
    success = db.verify_rotation_proof(
        user_index=target_index,
        proof=captured["proof"],
        new_inner_root=captured["new_inner_root"],
        nullifier=captured["nullifier_hex"],
        new_encrypted_data=captured["new_encrypted_blob"],
        public_signals=captured["public_signals"],
    )
    verify_ms = (time.perf_counter() - start) * 1000.0

    return [
        {
            "scenario": "rotation_update",
            "operation": "Verify Rotation Proof",
            "total_users": total_users,
            "batch_size": 1,
            "k_decoys": k_decoys,
            "duration_ms": verify_ms,
            "seed": seed,
            "notes": f"success={success}",
        }
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Attribute mutation benchmarks")
    parser.add_argument("--total-users", type=int, default=128, help="Initial user count")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size for inserts")
    parser.add_argument("--target-index", type=int, default=42, help="User index for rotation test")
    parser.add_argument("--k-decoys", type=int, default=5, help="Decoy count for rotation test")
    parser.add_argument("--rng-seed", type=int, default=4242, help="Seed for synthetic data")
    parser.add_argument("--skip-rotation", action="store_true", help="Skip rotation proof generation and verification (faster sweep)")

    args = parser.parse_args()

    db, user_keys = seed_database(args.total_users, args.rng_seed, args.target_index)
    client = BatchFetchClient(
        user_id="mutation-benchmark",
        encryption_key=user_keys[args.target_index],
        num_attributes=8,
        verbose=False,
    )

    rows: List[Dict[str, object]] = []
    rows.extend(
        measure_single_insert(db, total_users=args.total_users, seed=args.rng_seed)
    )
    rows.extend(
        measure_batch_insert(
            db, args.batch_size, args.rng_seed, total_users=args.total_users
        )
    )
    if not args.skip_rotation:
        rows.extend(
            measure_rotation_verification(
                db=db,
                client=client,
                target_index=args.target_index,
                k_decoys=args.k_decoys,
                total_users=args.total_users,
                seed=args.rng_seed,
            )
        )

    append_rows(MUTATION_CSV, CSV_HEADER, rows)
    print(f"wrote {len(rows)} rows to {MUTATION_CSV}")


if __name__ == "__main__":
    main()
