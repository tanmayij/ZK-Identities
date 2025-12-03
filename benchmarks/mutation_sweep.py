#!/usr/bin/env python3
"""Run the mutation benchmark across a grid of parameter combinations."""

from __future__ import annotations

import argparse
import itertools
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_PATH = REPO_ROOT / "benchmarks" / "mutation_metrics.py"
DEFAULT_OUTPUT = REPO_ROOT / "artifacts" / "metrics" / "attribute_mutation.csv"


def run_command(args: List[str]) -> None:
    """Execute the mutation benchmark with the provided CLI arguments."""
    cmd = [sys.executable, str(BENCHMARK_PATH)] + args
    print(f"\n$ {' '.join(cmd)}")
    result = subprocess.run(cmd, check=True)
    if result.returncode == 0:
        print("  ✓ completed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mutation benchmark parameter sweep")
    parser.add_argument("--total-users", type=int, nargs="+", default=[256, 512], dest="total_users",
                        help="List of total user counts to evaluate (<= 1024).")
    parser.add_argument("--batch-sizes", type=int, nargs="+", default=[64, 128],
                        help="Batch sizes to use for batched inserts.")
    parser.add_argument("--k-decoys", type=int, nargs="+", default=[1, 3, 5, 7, 9], dest="k_decoys",
                        help="Values for k (number of decoys in rotation proof).")
    parser.add_argument("--seeds", type=int, nargs="+", default=[2025],
                        help="RNG seeds for reproducible synthetic data.")
    parser.add_argument("--target-fraction", type=float, default=0.4,
                        help="Fraction of the user list to pick as target index (clamped into range).")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="Expected CSV output location (used for display only).")
    parser.add_argument("--clean", action="store_true",
                        help="Remove existing attribute_mutation.csv before running the sweep.")
    parser.add_argument("--skip-rotation", action="store_true",
                        help="Skip rotation proof generation in each run (fast path for insert/tree benchmarks).")
    return parser.parse_args()


def compute_target_index(total_users: int, target_fraction: float) -> int:
    target = int(total_users * target_fraction)
    target = max(target, 0)
    target = min(target, total_users - 1)
    return target


def main() -> None:
    ns = parse_args()

    if ns.clean and ns.output.exists():
        print(f"Removing previous metrics file: {ns.output}")
        ns.output.unlink()

    combinations = itertools.product(ns.total_users, ns.batch_sizes, ns.k_decoys, ns.seeds)

    for total_users, batch_size, k_decoys, seed in combinations:
        if total_users > 1024:
            raise ValueError("total-users must not exceed 1024 (outer tree depth limit)")
        if k_decoys >= total_users:
            raise ValueError("k-decoys must be less than total-users")

        target_index = compute_target_index(total_users, ns.target_fraction)

        cli_args = [
            f"--total-users={total_users}",
            f"--batch-size={batch_size}",
            f"--target-index={target_index}",
            f"--k-decoys={k_decoys}",
            f"--rng-seed={seed}",
        ]

        if ns.skip_rotation:
            cli_args.append("--skip-rotation")

        run_command(cli_args)

    print(f"\nSweep completed. Metrics appended to {ns.output}")


if __name__ == "__main__":
    main()
