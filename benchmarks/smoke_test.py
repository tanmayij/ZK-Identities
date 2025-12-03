"""Quick smoke test for comprehensive benchmark suite.

Runs a minimal benchmark (10 users, k=1,3) to verify setup.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
BENCHMARK_SCRIPT = REPO_ROOT / "benchmarks" / "comprehensive_benchmark.py"
PLOT_SCRIPT = REPO_ROOT / "benchmarks" / "plot_comprehensive.py"
METRICS_DIR = REPO_ROOT / "artifacts" / "metrics"

def main():
    print("=" * 70)
    print("  SMOKE TEST: Comprehensive Benchmark Suite")
    print("=" * 70)
    print("\nRunning minimal benchmark (10 users, k=1,3)...")
    print("This will take ~5-10 minutes for first cold proof generation.\n")

    # Run benchmark
    benchmark_cmd = [
        str(VENV_PYTHON),
        str(BENCHMARK_SCRIPT),
        "--total-users", "10",
        "--k-values", "1", "3",
        "--cohort-sizes", "3",
        "--natural-query", "users over 21",
        "--clean",
    ]

    print(f"$ {' '.join(benchmark_cmd)}\n")
    result = subprocess.run(benchmark_cmd)

    if result.returncode != 0:
        print("\n✗ Benchmark failed")
        sys.exit(1)

    print("\n✓ Benchmark completed")

    # Generate plots
    print("\nGenerating plots...")
    plot_cmd = [
        str(VENV_PYTHON),
        str(PLOT_SCRIPT),
        "--output-dir", str(METRICS_DIR),
    ]

    print(f"$ {' '.join(plot_cmd)}\n")
    result = subprocess.run(plot_cmd)

    if result.returncode != 0:
        print("\n✗ Plot generation failed")
        sys.exit(1)

    print("\n✓ Plots generated")

    # Summary
    print("\n" + "=" * 70)
    print("  SMOKE TEST PASSED")
    print("=" * 70)
    print("\nGenerated files:")

    for csv_file in METRICS_DIR.glob("*.csv"):
        size = csv_file.stat().st_size
        print(f"  CSV: {csv_file.name} ({size} bytes)")

    for png_file in METRICS_DIR.glob("*.png"):
        size = png_file.stat().st_size
        print(f"  PNG: {png_file.name} ({size} bytes)")

    print("\nView plots:")
    print(f"  open {METRICS_DIR}/*.png\n")

if __name__ == "__main__":
    main()
