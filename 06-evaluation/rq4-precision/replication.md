# RQ4 Precision Audit Replication

## How the sample was drawn

From the HEAD live scan (commit `4752e9a6`, 16,433 JS/TS files), we ran each
ClawAudit configuration and collected production-code findings (test files
excluded). We drew 25 findings per backend by stratified sampling over the
set of fired rules: every rule that produced at least one finding contributes
at least one sample, and remaining slots are filled at random from the
production pool.

Random seed: **43** (used in `precision_eval/v2/sample_50.json` generation).

## How the labels were assigned

Each of the 50 findings was labeled by a single independent reviewer as a
true positive (TP) if the flagged code matches the vulnerability pattern
claimed by the rule, or a false positive (FP) otherwise. All 50 findings
received a binary verdict; the rationale per finding is preserved in
`labels.json` under the `reason` field.

## Files

| File | Description |
|------|-------------|
| `sample_50.json`  | The 50 sampled findings (25 Semgrep + 25 CodeQL), with file path, line range, and the rule message. |
| `labels.json`     | Per-finding `verdict`, `confidence`, and `reason`. |
| `aggregated.json` | Per-tool TP/FP counts and per-rule TP/FP. |

## Aggregate result

| Configuration         | Sample | TP | FP | Precision |
|-----------------------|-------:|---:|---:|----------:|
| Semgrep + ClawAudit   |     25 |  3 | 22 |     12.0% |
| CodeQL + ClawAudit    |     25 |  3 | 22 |     12.0% |
| Combined              |     50 |  6 | 44 |     12.0% |

All six true positives come from six distinct narrow-scope rules; the
high-volume rules in the sample produced no true positives. The breakdown
appears in §6.5 of the paper.

## Reproducing the sample

```sh
# From the artifact root:
python3 06-evaluation/scripts/compute_precision.py \
    --semgrep-findings /path/to/your/semgrep_clawaudit.json \
    --codeql-findings  /path/to/your/codeql_clawaudit.sarif \
    --output           06-evaluation/rq4-precision/sample_50_new.json \
    --seed 43
```

The same seed produces the same sample given the same inputs.
