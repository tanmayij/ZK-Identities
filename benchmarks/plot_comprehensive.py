"""Plotting suite for comprehensive benchmarks.

Generates visualizations for:
1. K-value performance sweep (total latency and component breakdown)
2. Batched vs non-batched merkle rebuild comparison
3. Multi-user cohort scaling
4. Insert/update operation timings
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

METRICS_DIR = Path("artifacts/metrics")


def load_csv(path: Path) -> Optional[pd.DataFrame]:
    if not path.exists():
        print(f"skipping {path} (missing)")
        return None
    return pd.read_csv(path)


def plot_k_sweep_total(df: pd.DataFrame, output_dir: Path) -> None:
    """Plot total latency vs k for both scenarios."""
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    for scenario in df["scenario"].unique():
        subset = df[df["scenario"] == scenario].sort_values("k_value")
        label = "Batched Merkle" if "batched" in scenario else "Non-Batched Merkle"
        ax.plot(
            subset["k_value"],
            subset["total_duration_ms"],
            marker="o",
            label=label,
            linewidth=2,
        )

    ax.set_title("End-to-End Latency vs k-Anonymity Parameter", fontsize=14, fontweight="bold")
    ax.set_xlabel("k (number of decoys)", fontsize=12)
    ax.set_ylabel("Total Duration (ms)", fontsize=12)
    ax.grid(True, linestyle=":", alpha=0.7)
    ax.legend(fontsize=11)
    plt.tight_layout()

    output_path = output_dir / "k_sweep_total_latency.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_k_sweep_components(df: pd.DataFrame, output_dir: Path) -> None:
    """Plot stacked bar chart of component breakdown for each k value."""
    if df.empty:
        return

    # Focus on non-batched scenario for detailed breakdown
    subset = df[df["scenario"] == "non_batched_merkle"].sort_values("k_value")

    if subset.empty:
        return

    components = [
        "query_parse_ms",
        "client_decrypt_ms",
        "predicate_proof_ms",
        "rotation_proof_ms",
        "server_verify_ms",
    ]

    labels = [
        "Query Parse",
        "Client Decrypt",
        "Predicate Proof",
        "Rotation Proof",
        "Server Verify + Merkle",
    ]

    fig, ax = plt.subplots(figsize=(12, 6))

    k_values = subset["k_value"].values
    bottoms = np.zeros(len(k_values))

    colors = plt.cm.Set3(np.linspace(0, 1, len(components)))

    for idx, (component, label) in enumerate(zip(components, labels)):
        values = subset[component].values
        ax.bar(
            k_values,
            values,
            bottom=bottoms,
            label=label,
            color=colors[idx],
            edgecolor="white",
            linewidth=0.5,
        )
        bottoms += values

    ax.set_title("Component Breakdown (Non-Batched Merkle)", fontsize=14, fontweight="bold")
    ax.set_xlabel("k (number of decoys)", fontsize=12)
    ax.set_ylabel("Duration (ms)", fontsize=12)
    ax.legend(fontsize=10, loc="upper left")
    ax.grid(True, axis="y", linestyle=":", alpha=0.7)
    plt.tight_layout()

    output_path = output_dir / "k_sweep_component_breakdown.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_batched_comparison(df: pd.DataFrame, output_dir: Path) -> None:
    """Plot side-by-side comparison of batched vs non-batched merkle rebuild."""
    if df.empty:
        return

    # Select a few k values for comparison
    k_samples = [1, 5, 9, 13]
    available_k = df["k_value"].unique()
    k_samples = [k for k in k_samples if k in available_k]

    if not k_samples:
        return

    batched = df[df["scenario"] == "batched_merkle"]
    non_batched = df[df["scenario"] == "non_batched_merkle"]

    batched_subset = batched[batched["k_value"].isin(k_samples)].sort_values("k_value")
    non_batched_subset = non_batched[non_batched["k_value"].isin(k_samples)].sort_values("k_value")

    if batched_subset.empty or non_batched_subset.empty:
        return

    x = np.arange(len(k_samples))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar(
        x - width / 2,
        non_batched_subset["total_duration_ms"],
        width,
        label="Non-Batched Merkle",
        color="#4072a5",
    )
    ax.bar(
        x + width / 2,
        batched_subset["total_duration_ms"],
        width,
        label="Batched Merkle",
        color="#a55040",
    )

    ax.set_title("Batched vs Non-Batched Merkle Rebuild", fontsize=14, fontweight="bold")
    ax.set_xlabel("k (number of decoys)", fontsize=12)
    ax.set_ylabel("Total Duration (ms)", fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([f"k={k}" for k in k_samples])
    ax.legend(fontsize=11)
    ax.grid(True, axis="y", linestyle=":", alpha=0.7)
    plt.tight_layout()

    output_path = output_dir / "batched_vs_nonbatched_comparison.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_cohort_scaling(df: pd.DataFrame, output_dir: Path) -> None:
    """Plot multi-user cohort scaling."""
    if df.empty:
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Total duration
    ax1.plot(
        df["cohort_size"],
        df["total_duration_ms"],
        marker="o",
        color="#4072a5",
        linewidth=2,
    )
    ax1.set_title("Multi-User Cohort: Total Duration", fontsize=13, fontweight="bold")
    ax1.set_xlabel("Cohort Size (number of users)", fontsize=11)
    ax1.set_ylabel("Total Duration (ms)", fontsize=11)
    ax1.grid(True, linestyle=":", alpha=0.7)

    # Average per user
    ax2.plot(
        df["cohort_size"],
        df["avg_per_user_ms"],
        marker="s",
        color="#a55040",
        linewidth=2,
    )
    ax2.set_title("Multi-User Cohort: Avg per User", fontsize=13, fontweight="bold")
    ax2.set_xlabel("Cohort Size (number of users)", fontsize=11)
    ax2.set_ylabel("Avg Duration per User (ms)", fontsize=11)
    ax2.grid(True, linestyle=":", alpha=0.7)

    plt.tight_layout()

    output_path = output_dir / "cohort_scaling.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"wrote {output_path}")


def plot_insert_update(df: pd.DataFrame, output_dir: Path) -> None:
    """Plot insert and update operation timings."""
    if df.empty:
        return

    fig, ax = plt.subplots(figsize=(8, 5))

    operations = df["operation"].values
    durations = df["duration_ms"].values

    colors = ["#4072a5", "#a55040"]
    ax.barh(operations, durations, color=colors[: len(operations)])

    ax.set_title("Insert and Update Operations", fontsize=14, fontweight="bold")
    ax.set_xlabel("Duration (ms)", fontsize=12)
    ax.grid(True, axis="x", linestyle=":", alpha=0.7)

    plt.tight_layout()

    output_path = output_dir / "insert_update_operations.png"
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"wrote {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot comprehensive benchmark results")
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

    print("Generating comprehensive benchmark plots...")

    # K-value sweep plots
    k_sweep = load_csv(args.metrics_dir / "k_value_sweep.csv")
    if k_sweep is not None:
        plot_k_sweep_total(k_sweep, args.output_dir)
        plot_k_sweep_components(k_sweep, args.output_dir)
        plot_batched_comparison(k_sweep, args.output_dir)

    # Cohort scaling
    cohort = load_csv(args.metrics_dir / "multi_user_cohort.csv")
    if cohort is not None:
        plot_cohort_scaling(cohort, args.output_dir)

    # Insert/update operations
    insert_update = load_csv(args.metrics_dir / "insert_update.csv")
    if insert_update is not None:
        plot_insert_update(insert_update, args.output_dir)

    print("\n✓ All plots generated successfully")


if __name__ == "__main__":
    main()
