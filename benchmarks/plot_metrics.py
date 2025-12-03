"""Plotting helpers for benchmark CSV outputs."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

import pandas as pd
import matplotlib.pyplot as plt


METRICS_DIR = Path("artifacts/metrics")


def load_csv(path: Path) -> Optional[pd.DataFrame]:
    if not path.exists():
        print(f"skipping {path} (missing)")
        return None
    return pd.read_csv(path)


def plot_end_to_end(end_to_end: pd.DataFrame, output_dir: Path) -> None:
    cold = end_to_end[end_to_end["scenario"] == "cold_boot"]
    if not cold.empty:
        summary = cold.groupby("phase")["duration_ms"].mean().sort_values()
        fig, ax = plt.subplots(figsize=(8, 4))
        summary.plot(kind="bar", ax=ax, color="#4072a5")
        ax.set_title("Cold Boot Timing")
        ax.set_ylabel("milliseconds")
        ax.set_xlabel("phase")
        ax.tick_params(axis="x", rotation=45)
        for label in ax.get_xticklabels():
            label.set_horizontalalignment("right")
        plt.tight_layout()
        output_path = output_dir / "end_to_end_cold.png"
        fig.savefig(output_path)
        plt.close(fig)
        print(f"wrote {output_path}")

    warm = end_to_end[end_to_end["scenario"] == "warm_cycle"]
    if not warm.empty:
        pivot = warm.pivot_table(
            index="idle_seconds",
            columns="phase",
            values="duration_ms",
            aggfunc="mean",
        ).sort_index()
        fig, ax = plt.subplots(figsize=(8, 4))
        pivot.plot(ax=ax, marker="o")
        ax.set_title("Warm Rotation Timing")
        ax.set_ylabel("milliseconds")
        ax.set_xlabel("idle seconds")
        ax.grid(True, linestyle=":", linewidth=0.8)
        plt.tight_layout()
        output_path = output_dir / "warm_hysteresis.png"
        fig.savefig(output_path)
        plt.close(fig)
        print(f"wrote {output_path}")


def plot_mutation(mutation: pd.DataFrame, output_dir: Path) -> None:
    if mutation.empty:
        return
    summary = (
        mutation.groupby(["scenario", "operation"])["duration_ms"].mean().reset_index()
    )
    fig, ax = plt.subplots(figsize=(8, 4))
    for scenario, group in summary.groupby("scenario"):
        ax.plot(
            group["operation"],
            group["duration_ms"],
            marker="o",
            label=scenario,
        )
    ax.set_title("Mutation Timing")
    ax.set_ylabel("milliseconds")
    ax.set_xlabel("operation")
    ax.legend()
    ax.tick_params(axis="x", rotation=25)
    for label in ax.get_xticklabels():
        label.set_horizontalalignment("right")
    plt.tight_layout()
    output_path = output_dir / "attribute_mutation.png"
    fig.savefig(output_path)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_mutation_by_k(mutation: pd.DataFrame, output_dir: Path) -> None:
    # Rotation verification scaling vs k, grouped by total_users
    rot = mutation[(mutation["scenario"] == "rotation_update") & (mutation["operation"] == "Verify Rotation Proof")]
    if rot.empty or "k_decoys" not in rot.columns or "total_users" not in rot.columns:
        return
    pivot = rot.groupby(["total_users", "k_decoys"])['duration_ms'].mean().reset_index()
    fig, ax = plt.subplots(figsize=(8, 4))
    for total_users, group in pivot.groupby("total_users"):
        ax.plot(group["k_decoys"], group["duration_ms"], marker="o", label=f"users={total_users}")
    ax.set_title("Rotation Verify vs k")
    ax.set_ylabel("milliseconds")
    ax.set_xlabel("k (decoys)")
    ax.grid(True, linestyle=":", linewidth=0.8)
    ax.legend()
    plt.tight_layout()
    output_path = output_dir / "rotation_verify_vs_k.png"
    fig.savefig(output_path)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_batch_insert_scaling(mutation: pd.DataFrame, output_dir: Path) -> None:
    # Batch insert scaling vs batch_size, grouped by total_users
    bi = mutation[(mutation["scenario"] == "batch_insert") & (mutation["operation"].str.startswith("Batch Insert"))]
    if bi.empty or "batch_size" not in bi.columns or "total_users" not in bi.columns:
        return
    agg = bi.groupby(["total_users", "batch_size"])['duration_ms'].mean().reset_index().sort_values("batch_size")
    fig, ax = plt.subplots(figsize=(8, 4))
    for total_users, group in agg.groupby("total_users"):
        ax.plot(group["batch_size"], group["duration_ms"], marker="o", label=f"users={total_users}")
    ax.set_title("Batch Insert Scaling")
    ax.set_ylabel("milliseconds")
    ax.set_xlabel("batch size")
    ax.grid(True, linestyle=":", linewidth=0.8)
    ax.legend()
    plt.tight_layout()
    output_path = output_dir / "batch_insert_scaling.png"
    fig.savefig(output_path)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_predicate(predicate: pd.DataFrame, output_dir: Path) -> None:
    if predicate.empty:
        return
    user_phase = predicate[predicate["phase"] == "cohort_total"]
    if not user_phase.empty:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.plot(
            user_phase["cohort_size"],
            user_phase["duration_ms"],
            marker="o",
            color="#a55040",
        )
        ax.set_title("Predicate Cohort Timing")
        ax.set_ylabel("milliseconds")
        ax.set_xlabel("cohort size")
        ax.grid(True, linestyle=":", linewidth=0.8)
        plt.tight_layout()
        output_path = output_dir / "predicate_cohort.png"
        fig.savefig(output_path)
        plt.close(fig)
        print(f"wrote {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot benchmark metrics")
    parser.add_argument(
        "--metrics-dir",
        type=Path,
        default=METRICS_DIR,
        help="Directory containing CSV files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=METRICS_DIR,
        help="Directory for generated plots",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    end_to_end = load_csv(args.metrics_dir / "end_to_end.csv")
    if end_to_end is not None:
        plot_end_to_end(end_to_end, args.output_dir)

    warm = load_csv(args.metrics_dir / "warm_hysteresis.csv")
    if warm is not None and end_to_end is None:
        # warm metrics may be stored separately when harness not run
        warm["scenario"] = "warm_cycle"
        plot_end_to_end(warm, args.output_dir)

    mutation = load_csv(args.metrics_dir / "attribute_mutation.csv")
    if mutation is not None:
        plot_mutation(mutation, args.output_dir)
        plot_mutation_by_k(mutation, args.output_dir)
        plot_batch_insert_scaling(mutation, args.output_dir)

    predicate = load_csv(args.metrics_dir / "predicate_batch.csv")
    if predicate is not None:
        plot_predicate(predicate, args.output_dir)


if __name__ == "__main__":
    main()
