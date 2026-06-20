#!/usr/bin/env bash
# Run Semgrep baseline (--config auto) and Semgrep + ClawAudit on every
# vulnerable_code/<GHSA> snapshot in OpenClawBench.
#
# Usage:
#     bash run_semgrep_eval.sh /path/to/vulnerable_code [output_dir]
#
# Outputs one JSON per advisory per configuration.

set -euo pipefail

VULN_DIR=${1:?Usage: bash run_semgrep_eval.sh <vulnerable_code dir> [output_dir]}
OUT_DIR=${2:-./semgrep_per_advisory}
RULES_DIR="$(dirname "$0")/../../04-clawaudit-rules/semgrep"

mkdir -p "$OUT_DIR/baseline" "$OUT_DIR/clawaudit"

count=0
total=$(ls "$VULN_DIR" | wc -l)
for snap in "$VULN_DIR"/*/; do
    gid=$(basename "$snap")
    count=$((count + 1))

    # Skip if both outputs already exist
    if [[ -f "$OUT_DIR/baseline/$gid.json" ]] && [[ -f "$OUT_DIR/clawaudit/$gid.json" ]]; then
        continue
    fi

    if [[ ! -f "$OUT_DIR/baseline/$gid.json" ]]; then
        semgrep --json --quiet --config auto "$snap" \
            > "$OUT_DIR/baseline/$gid.json" 2>/dev/null || true
    fi

    if [[ ! -f "$OUT_DIR/clawaudit/$gid.json" ]]; then
        # All custom rules in one invocation
        RULES_ARGS=()
        for f in "$RULES_DIR"/openclaw-*.yaml "$RULES_DIR"/xss-json-stringify-inline-script.yaml; do
            RULES_ARGS+=(--config "$f")
        done
        semgrep --json --quiet --metrics=off "${RULES_ARGS[@]}" "$snap" \
            > "$OUT_DIR/clawaudit/$gid.json" 2>/dev/null || true
    fi

    if (( count % 25 == 0 || count == total )); then
        echo "  [$count/$total] $gid"
    fi
done

echo "Done. Results in $OUT_DIR/{baseline,clawaudit}/"
