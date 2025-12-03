"""Real-time benchmark progress visualization.

Monitors the comprehensive benchmark execution and displays:
- Overall progress timeline
- Time spent on each phase (seeding, cold proof, warm proofs, cohorts)
- Estimated time remaining
- Component breakdown per k-value

Updates live as the benchmark runs.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.animation import FuncAnimation
import pandas as pd

METRICS_DIR = Path("artifacts/metrics")
LOG_FILE = METRICS_DIR / "full_test_run.log"


class BenchmarkProgressTracker:
    """Track and visualize benchmark progress in real-time."""

    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.phases: Dict[str, Dict[str, float]] = {
            "Database Seeding": {"start": None, "end": None, "estimated": 20.0},
            "First Cold Proof (k=1)": {"start": None, "end": None, "estimated": 15.0},
            "Warm Proofs (k=3-40)": {"start": None, "end": None, "estimated": 90.0},
            "Insert/Update": {"start": None, "end": None, "estimated": 5.0},
            "Cohort Tests": {"start": None, "end": None, "estimated": 5.0},
        }
        self.k_values_completed: List[int] = []
        self.total_estimated = sum(p["estimated"] for p in self.phases.values())
        self.start_time: Optional[float] = None

    def parse_log(self) -> None:
        """Parse the log file to extract progress information."""
        if not self.log_file.exists():
            return

        with self.log_file.open("r") as f:
            lines = f.readlines()

        current_time = time.time()

        for i, line in enumerate(lines):
            # Database seeding
            if "creating database with" in line.lower():
                if self.phases["Database Seeding"]["start"] is None:
                    self.phases["Database Seeding"]["start"] = current_time
                    self.start_time = current_time

            if "seeded" in line.lower() and "users in" in line.lower():
                if self.phases["Database Seeding"]["end"] is None:
                    self.phases["Database Seeding"]["end"] = current_time

            # K-value sweep start
            if "k-value sweep" in line.lower() and "non-batched" in line.lower():
                if self.phases["First Cold Proof (k=1)"]["start"] is None:
                    self.phases["First Cold Proof (k=1)"]["start"] = current_time

            # Track k values
            if "k=" in line and "..." in line:
                try:
                    k_val = int(line.split("k=")[1].split()[0])
                    if k_val not in self.k_values_completed:
                        self.k_values_completed.append(k_val)

                        # First k is cold proof
                        if k_val == 1 and self.phases["First Cold Proof (k=1)"]["end"] is None:
                            # Look ahead for timing
                            if i + 1 < len(lines) and "ms" in lines[i + 1]:
                                self.phases["First Cold Proof (k=1)"]["end"] = current_time
                                self.phases["Warm Proofs (k=3-40)"]["start"] = current_time

                        # Track warm proofs
                        elif k_val > 1:
                            if self.phases["Warm Proofs (k=3-40)"]["start"] is None:
                                self.phases["Warm Proofs (k=3-40)"]["start"] = current_time
                except ValueError:
                    pass

            # Insert/Update
            if "insert and update operations" in line.lower():
                if self.phases["Insert/Update"]["start"] is None:
                    self.phases["Insert/Update"]["start"] = current_time

            if "wrote" in line.lower() and "insert_update.csv" in line.lower():
                if self.phases["Insert/Update"]["end"] is None:
                    self.phases["Insert/Update"]["end"] = current_time
                    self.phases["Cohort Tests"]["start"] = current_time

            # Cohort tests
            if "multi-user cohort queries" in line.lower():
                if self.phases["Cohort Tests"]["start"] is None:
                    self.phases["Cohort Tests"]["start"] = current_time

            if "benchmark suite complete" in line.lower():
                if self.phases["Cohort Tests"]["end"] is None:
                    self.phases["Cohort Tests"]["end"] = current_time

    def get_elapsed_time(self, phase_name: str) -> float:
        """Get elapsed time for a phase in minutes."""
        phase = self.phases[phase_name]
        if phase["start"] is None:
            return 0.0

        end_time = phase["end"] if phase["end"] is not None else time.time()
        return (end_time - phase["start"]) / 60.0

    def get_total_elapsed(self) -> float:
        """Get total elapsed time in minutes."""
        if self.start_time is None:
            return 0.0
        return (time.time() - self.start_time) / 60.0

    def estimate_remaining(self) -> float:
        """Estimate remaining time in minutes."""
        total_elapsed = self.get_total_elapsed()
        
        # Estimate based on completed phases
        completed_estimate = 0.0
        for phase_name, phase in self.phases.items():
            if phase["end"] is not None:
                completed_estimate += self.get_elapsed_time(phase_name)
            elif phase["start"] is not None:
                # In progress - use current elapsed
                completed_estimate += self.get_elapsed_time(phase_name)
            else:
                # Not started - use estimate
                completed_estimate += phase["estimated"]

        return max(0.0, self.total_estimated - total_elapsed)


def create_progress_figure(tracker: BenchmarkProgressTracker) -> tuple:
    """Create the matplotlib figure and axes."""
    fig = plt.figure(figsize=(14, 8))
    
    # Timeline chart (top)
    ax1 = plt.subplot(2, 1, 1)
    
    # Stats panel (bottom left)
    ax2 = plt.subplot(2, 2, 3)
    
    # K-value progress (bottom right)
    ax3 = plt.subplot(2, 2, 4)
    
    return fig, (ax1, ax2, ax3)


def update_plot(frame, tracker: BenchmarkProgressTracker, axes):
    """Update the plot with current progress."""
    ax1, ax2, ax3 = axes
    
    # Parse latest log data
    tracker.parse_log()
    
    # Clear axes
    ax1.clear()
    ax2.clear()
    ax3.clear()
    
    # --- Timeline Chart ---
    ax1.set_title("Benchmark Execution Timeline", fontsize=14, fontweight="bold")
    ax1.set_xlabel("Time (minutes)", fontsize=11)
    ax1.set_xlim(0, max(tracker.total_estimated, tracker.get_total_elapsed() + 10))
    
    y_pos = 0
    colors = ["#4472C4", "#ED7D31", "#A5A5A5", "#FFC000", "#5B9BD5"]
    
    for i, (phase_name, phase) in enumerate(tracker.phases.items()):
        elapsed = tracker.get_elapsed_time(phase_name)
        
        if phase["start"] is not None:
            if phase["end"] is not None:
                # Completed
                color = colors[i]
                alpha = 0.9
                label = f"{phase_name}: {elapsed:.1f} min"
            else:
                # In progress
                color = colors[i]
                alpha = 0.6
                label = f"{phase_name}: {elapsed:.1f} min (in progress)"
            
            start_offset = (phase["start"] - tracker.start_time) / 60.0 if tracker.start_time else 0
            ax1.barh(y_pos, elapsed, left=start_offset, height=0.8, 
                    color=color, alpha=alpha, edgecolor="black", linewidth=0.5)
            ax1.text(start_offset + elapsed / 2, y_pos, label, 
                    ha="center", va="center", fontsize=9, fontweight="bold")
        else:
            # Not started - show estimate as gray
            ax1.barh(y_pos, phase["estimated"], left=0, height=0.8,
                    color="lightgray", alpha=0.3, edgecolor="gray", linewidth=0.5)
            ax1.text(phase["estimated"] / 2, y_pos, f"{phase_name} (est: {phase['estimated']:.0f} min)",
                    ha="center", va="center", fontsize=9, color="gray")
        
        y_pos += 1
    
    ax1.set_ylim(-0.5, len(tracker.phases) - 0.5)
    ax1.set_yticks([])
    ax1.grid(True, axis="x", linestyle=":", alpha=0.7)
    
    # --- Stats Panel ---
    ax2.axis("off")
    
    total_elapsed = tracker.get_total_elapsed()
    estimated_remaining = tracker.estimate_remaining()
    estimated_total = total_elapsed + estimated_remaining
    progress_pct = (total_elapsed / tracker.total_estimated * 100) if tracker.total_estimated > 0 else 0
    
    stats_text = f"""
BENCHMARK PROGRESS

Total Elapsed:     {total_elapsed:.1f} min
Estimated Remaining: {estimated_remaining:.1f} min
Estimated Total:   {estimated_total:.1f} min

Progress:          {progress_pct:.1f}%

K-Values Completed: {len(tracker.k_values_completed)} / 13
Last K:            {tracker.k_values_completed[-1] if tracker.k_values_completed else "N/A"}
"""
    
    ax2.text(0.1, 0.5, stats_text, fontsize=11, verticalalignment="center",
            family="monospace", bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.3))
    
    # --- K-Value Progress ---
    ax3.set_title("K-Value Completion", fontsize=12, fontweight="bold")
    
    expected_k_values = [1, 3, 5, 7, 9, 11, 13, 15, 20, 25, 30, 35, 40]
    completed = [k in tracker.k_values_completed for k in expected_k_values]
    
    colors_k = ["green" if c else "lightgray" for c in completed]
    ax3.barh(range(len(expected_k_values)), [1] * len(expected_k_values), color=colors_k, alpha=0.7)
    ax3.set_yticks(range(len(expected_k_values)))
    ax3.set_yticklabels([f"k={k}" for k in expected_k_values])
    ax3.set_xlim(0, 1.5)
    ax3.set_xticks([])
    ax3.grid(True, axis="y", linestyle=":", alpha=0.3)
    
    # Add completion markers
    for i, (k, comp) in enumerate(zip(expected_k_values, completed)):
        if comp:
            ax3.text(0.5, i, "✓", ha="center", va="center", fontsize=14, color="white", fontweight="bold")
    
    plt.tight_layout()


def main():
    parser = argparse.ArgumentParser(description="Visualize benchmark progress in real-time")
    parser.add_argument(
        "--log-file",
        type=Path,
        default=LOG_FILE,
        help="Path to benchmark log file",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5000,
        help="Update interval in milliseconds (default: 5000)",
    )
    args = parser.parse_args()
    
    if not args.log_file.exists():
        print(f"Warning: Log file {args.log_file} not found.")
        print("The visualization will start when the benchmark begins.")
    
    tracker = BenchmarkProgressTracker(args.log_file)
    fig, axes = create_progress_figure(tracker)
    
    # Animate
    ani = FuncAnimation(
        fig,
        update_plot,
        fargs=(tracker, axes),
        interval=args.interval,
        cache_frame_data=False,
    )
    
    plt.show()


if __name__ == "__main__":
    main()
