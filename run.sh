#!/usr/bin/env bash
#
# run.sh -- Bash automation for the whole pipeline.
#   1. Check that the log files exist
#   2. Run the Python detection pipeline (fills findings.db)
#   3. Generate the incident report
# Usage:  ./run.sh
#
set -e   # stop immediately if any command fails

# Move into the directory this script lives in (so paths work anywhere).
cd "$(dirname "$0")"

DATA_FILES=("data/auth.log" "data/dns.log" "data/http.log" "data/smtp.log" "data/cloud_events.json")

echo "==============================================="
echo " Threat Intelligence & Network Security Pipeline"
echo "==============================================="

# --- Step 1: check inputs -------------------------------------------------
echo "[1/3] Checking input log files..."
for f in "${DATA_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "  ERROR: missing input file: $f"
        exit 1
    fi
    echo "  OK: $f ($(wc -l < "$f") lines)"
done

# --- Step 2: run detection ------------------------------------------------
echo "[2/3] Running Python threat detection..."
python detect.py

# --- Step 3: generate report ----------------------------------------------
echo "[3/3] Generating incident report..."
python report.py

echo "==============================================="
echo " Pipeline finished. See report.txt for details."
echo "==============================================="
