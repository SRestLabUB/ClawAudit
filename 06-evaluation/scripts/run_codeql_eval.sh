#!/usr/bin/env bash
# Run CodeQL javascript-security-extended.qls and CodeQL + ClawAudit on
# every vulnerable_code/<GHSA> snapshot in OpenClawBench.
#
# Usage:
#     bash run_codeql_eval.sh /path/to/vulnerable_code [output_dir]
#
# Outputs one SARIF per advisory per configuration.

set -euo pipefail

VULN_DIR=${1:?Usage: bash run_codeql_eval.sh <vulnerable_code dir> [output_dir]}
OUT_DIR=${2:-./codeql_per_advisory}
QPACK="$(dirname "$0")/../../04-clawaudit-rules/codeql"
SUITE="codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"

mkdir -p "$OUT_DIR/baseline" "$OUT_DIR/clawaudit"

count=0
total=$(ls "$VULN_DIR" | wc -l)
for snap in "$VULN_DIR"/*/; do
    gid=$(basename "$snap")
    count=$((count + 1))

    if [[ -f "$OUT_DIR/baseline/$gid.sarif" ]] && [[ -f "$OUT_DIR/clawaudit/$gid.sarif" ]]; then
        continue
    fi

    db="/tmp/codeql_db_$gid"
    rm -rf "$db"
    codeql database create "$db" --language=javascript \
        --source-root="$snap" --overwrite --quiet > /dev/null 2>&1 || continue

    if [[ ! -f "$OUT_DIR/baseline/$gid.sarif" ]]; then
        codeql database analyze "$db" "$SUITE" \
            --format=sarif-latest --output="$OUT_DIR/baseline/$gid.sarif" \
            --quiet --threads=2 > /dev/null 2>&1 || true
    fi

    if [[ ! -f "$OUT_DIR/clawaudit/$gid.sarif" ]]; then
        codeql database analyze "$db" "$QPACK" \
            --format=sarif-latest --output="$OUT_DIR/clawaudit/$gid.sarif" \
            --quiet --threads=2 > /dev/null 2>&1 || true
    fi

    rm -rf "$db"

    if (( count % 10 == 0 || count == total )); then
        echo "  [$count/$total] $gid"
    fi
done

echo "Done. Results in $OUT_DIR/{baseline,clawaudit}/"
