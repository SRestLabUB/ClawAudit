#!/usr/bin/env bash
# End-to-end smoke test on a small 10-advisory subset of OpenClawBench.
# Verifies that Semgrep and CodeQL are wired up correctly without committing
# to the full ~1 hour wall-clock run.
#
# Usage:
#     bash reproduce.sh [num_advisories]
#
# Default num_advisories is 10. Pass 446 for the full benchmark.

set -euo pipefail

NUM=${1:-10}
ROOT=$(cd "$(dirname "$0")" && pwd)
BENCH=$ROOT/05-openclawbench
SCRATCH=$ROOT/.scratch

mkdir -p "$SCRATCH"

# 1. Check dependencies.
echo "[1/5] Checking dependencies ..."
command -v semgrep >/dev/null || { echo "ERROR: semgrep not in PATH"; exit 1; }
command -v codeql  >/dev/null || { echo "ERROR: codeql not in PATH"; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not in PATH"; exit 1; }
echo "  semgrep: $(semgrep --version 2>&1 | head -1)"
echo "  codeql:  $(codeql --version 2>&1 | head -1)"

# 2. Pick a subset of advisories from the manifest.
echo "[2/5] Picking $NUM advisories ..."
python3 -c "
import json
m = json.load(open('$BENCH/manifest.json'))
subset = m['advisories'][:$NUM]
with open('$SCRATCH/subset.json','w') as f:
    json.dump({'advisories': subset}, f)
print(f'  selected {len(subset)} advisories')
"

# 3. Rebuild snapshots for the subset.
echo "[3/5] Rebuilding snapshots ..."
python3 "$BENCH/scripts/build_snapshots.py" \
    --manifest "$SCRATCH/subset.json" \
    --output "$SCRATCH/vulnerable_code" 2>&1 | tail -5

# 4. Scan with Semgrep (baseline + ClawAudit).
echo "[4/5] Running Semgrep ..."
bash "$ROOT/06-evaluation/scripts/run_semgrep_eval.sh" \
    "$SCRATCH/vulnerable_code" "$SCRATCH/semgrep" 2>&1 | tail -3

# 5. Scan with CodeQL (baseline + ClawAudit).
echo "[5/5] Running CodeQL ..."
bash "$ROOT/06-evaluation/scripts/run_codeql_eval.sh" \
    "$SCRATCH/vulnerable_code" "$SCRATCH/codeql" 2>&1 | tail -3

# 6. Aggregate.
echo "[6/6] Computing recall ..."
python3 "$ROOT/06-evaluation/scripts/compute_recall.py" \
    --manifest "$SCRATCH/subset.json" \
    --semgrep-results "$SCRATCH/semgrep" \
    --codeql-results  "$SCRATCH/codeql" \
    --output-dir      "$SCRATCH"

echo
echo "Done. Outputs in $SCRATCH/."
echo "  See $SCRATCH/table_overall.csv for the smoke-test recall table."
