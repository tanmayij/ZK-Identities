#!/bin/bash
# Full comprehensive benchmark test with large dataset and extensive parameter coverage
# This will generate rich data for k-value performance analysis and component breakdowns

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
BENCHMARKS_DIR="$REPO_ROOT/benchmarks"
METRICS_DIR="$REPO_ROOT/artifacts/metrics"

echo "========================================================================"
echo "  FULL COMPREHENSIVE BENCHMARK TEST"
echo "========================================================================"
echo ""
echo "Configuration:"
echo "  Total Users:   1024 (max capacity)"
echo "  K Values:      1, 3, 5, 7, 9, 11, 13, 15, 20, 25, 30, 35, 40"
echo "  Cohort Sizes:  5, 10, 20, 30, 40, 50"
echo "  Query:         'users over 21'"
echo ""
echo "Expected Duration: 90-180 minutes (first cold proof ~10-20 min, then ~5-10 min per k)"
echo ""
read -p "Continue with full test? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Aborted."
    exit 1
fi

# Ensure metrics directory exists
mkdir -p "$METRICS_DIR"

# Run comprehensive benchmark with large dataset
echo ""
echo "========================================================================"
echo "  RUNNING BENCHMARKS"
echo "========================================================================"
echo ""

"$VENV_PYTHON" "$BENCHMARKS_DIR/comprehensive_benchmark.py" \
    --total-users 1024 \
    --k-values 1 3 5 7 9 11 13 15 20 25 30 35 40 \
    --cohort-sizes 5 10 20 30 40 50 \
    --natural-query "users over 21" \
    --clean

echo ""
echo "✓ Benchmarks completed"

# Generate plots
echo ""
echo "========================================================================"
echo "  GENERATING PLOTS"
echo "========================================================================"
echo ""

"$VENV_PYTHON" "$BENCHMARKS_DIR/plot_comprehensive.py" \
    --output-dir "$METRICS_DIR"

echo ""
echo "✓ Plots generated"

# Summary
echo ""
echo "========================================================================"
echo "  FULL TEST COMPLETE"
echo "========================================================================"
echo ""
echo "Generated files:"
ls -lh "$METRICS_DIR"/*.csv 2>/dev/null | awk '{print "  CSV:  " $9 "  (" $5 ")"}'
echo ""
ls -lh "$METRICS_DIR"/*.png 2>/dev/null | awk '{print "  PNG:  " $9 "  (" $5 ")"}'
echo ""
echo "View plots:"
echo "  open $METRICS_DIR/*.png"
echo ""
echo "CSV data available for analysis:"
echo "  - k_value_sweep.csv (component timing for each k)"
echo "  - insert_update.csv (CRUD operation timing)"
echo "  - multi_user_cohort.csv (cohort scaling data)"
echo ""
