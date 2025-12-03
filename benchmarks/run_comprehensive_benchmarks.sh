#!/bin/bash
# Automated benchmark test suite execution script
#
# This script orchestrates the complete benchmarking workflow:
# 1. Seeds a large database once (expensive, ~10-30 min for 1024 users)
# 2. Runs comprehensive benchmarks with component-level timing
# 3. Generates visualization plots
#
# Usage:
#   ./run_comprehensive_benchmarks.sh [--quick|--full|--custom]

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
BENCHMARKS_DIR="$REPO_ROOT/benchmarks"
METRICS_DIR="$REPO_ROOT/artifacts/metrics"

# Default configuration
TOTAL_USERS=256
K_VALUES="1 3 5 7 9 11 13 15"
COHORT_SIZES="5 10 20"
NATURAL_QUERY="users over 21"
CLEAN_FLAG="--clean"

# Parse command-line arguments
MODE="${1:---quick}"

case "$MODE" in
    --quick)
        echo "Running QUICK benchmarks (256 users, k=1,3,5,7,9)"
        TOTAL_USERS=256
        K_VALUES="1 3 5 7 9"
        COHORT_SIZES="5 10"
        ;;
    --full)
        echo "Running FULL benchmarks (1024 users, k=1..15)"
        TOTAL_USERS=1024
        K_VALUES="1 3 5 7 9 11 13 15"
        COHORT_SIZES="5 10 20 30"
        ;;
    --custom)
        echo "Custom mode: set environment variables before running"
        # Use environment variables if set
        TOTAL_USERS="${BENCH_USERS:-$TOTAL_USERS}"
        K_VALUES="${BENCH_K_VALUES:-$K_VALUES}"
        COHORT_SIZES="${BENCH_COHORT_SIZES:-$COHORT_SIZES}"
        NATURAL_QUERY="${BENCH_QUERY:-$NATURAL_QUERY}"
        ;;
    *)
        echo "Usage: $0 [--quick|--full|--custom]"
        exit 1
        ;;
esac

echo "========================================================================"
echo "  COMPREHENSIVE AUTOMATED BENCHMARK SUITE"
echo "========================================================================"
echo "Configuration:"
echo "  Total Users:   $TOTAL_USERS"
echo "  K Values:      $K_VALUES"
echo "  Cohort Sizes:  $COHORT_SIZES"
echo "  Query:         '$NATURAL_QUERY'"
echo ""

# Ensure metrics directory exists
mkdir -p "$METRICS_DIR"

# Step 1: Run comprehensive benchmark
echo "========================================================================"
echo "  STEP 1: Running Benchmarks (this may take 30-60 minutes)"
echo "========================================================================"

"$VENV_PYTHON" "$BENCHMARKS_DIR/comprehensive_benchmark.py" \
    --total-users "$TOTAL_USERS" \
    --k-values $K_VALUES \
    --cohort-sizes $COHORT_SIZES \
    --natural-query "$NATURAL_QUERY" \
    $CLEAN_FLAG

echo ""
echo "✓ Benchmarks completed"

# Step 2: Generate plots
echo ""
echo "========================================================================"
echo "  STEP 2: Generating Plots"
echo "========================================================================"

"$VENV_PYTHON" "$BENCHMARKS_DIR/plot_comprehensive.py" \
    --output-dir "$METRICS_DIR"

echo ""
echo "✓ Plots generated"

# Step 3: Summary
echo ""
echo "========================================================================"
echo "  BENCHMARK SUITE COMPLETE"
echo "========================================================================"
echo ""
echo "Generated files:"
ls -lh "$METRICS_DIR"/*.csv 2>/dev/null | awk '{print "  CSV:  " $9 "  (" $5 ")"}'
ls -lh "$METRICS_DIR"/*.png 2>/dev/null | awk '{print "  PNG:  " $9 "  (" $5 ")"}'
echo ""
echo "View plots with:"
echo "  open $METRICS_DIR/*.png"
echo ""
