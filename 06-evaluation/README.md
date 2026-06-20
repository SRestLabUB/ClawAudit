# §6 — Evaluation

Paper section: **§6 Evaluation**.

Five research questions are evaluated, one per subfolder.

| Folder | RQ | Question |
|--------|----|----------|
| `rq1-baseline/` | RQ1 | How well do generic static-analysis tools detect disclosed vulnerabilities in local LLM agent runtimes? |
| `rq2-recall-lift/` | RQ2 | To what extent do agent-specific static rules improve detection across vulnerability classes? |
| `rq3-generalization/` | RQ3 | Do rules derived on past advisories generalize to advisories unseen during rule development? |
| `rq4-precision/` | RQ4 | What is the precision of runtime-layer auditing on current agent versions? |
| `rq5-boundary/` | RQ5 | Where is the boundary between syntactic rule-based detection and semantic reasoning for agent-runtime safety? |

## Detection semantics

An advisory is considered **detected** by a configuration if at least one
rule emits a finding whose file path matches a file modified by the fix
commit. Findings located in test files (`.test.ts`, `/tests/`, `/e2e/`,
etc.) are excluded throughout; all reported numbers are **production-only**.

## How the per-folder CSVs were produced

Each `per_advisory.csv` is a 446-row table with one row per advisory and
one column per configuration. A `1` means at least one rule fired in a
production file modified by the fix commit; a `0` means no such firing.
Aggregate tables (`table_overall.csv`, `table_severity.csv`,
`table_cwe.csv`, `train_test_cwe.csv`) are produced from `per_advisory.csv`
by `scripts/compute_recall.py`.

## Reproducing each RQ

```sh
# Step 1: rebuild the vulnerable-code snapshots (see ../05-openclawbench/README.md).

# Step 2: run the four scan configurations.
cd 06-evaluation/scripts
bash run_semgrep_eval.sh ../../05-openclawbench/vulnerable_code  # ~20 min
bash run_codeql_eval.sh  ../../05-openclawbench/vulnerable_code  # ~40 min

# Step 3: derive the tables.
python3 compute_recall.py    # writes table_overall.csv, table_severity.csv, table_cwe.csv
python3 compute_precision.py # writes rq4-precision/aggregated.json
```

Each script reads the manifest from `../../05-openclawbench/manifest.json`
and writes per-RQ CSVs into the corresponding subfolder.

## Configurations evaluated

| Configuration              | Source ruleset |
|----------------------------|----------------|
| Semgrep Pro baseline       | `semgrep --config auto` (~2,815 community + Pro rules) |
| Semgrep + ClawAudit        | Semgrep Pro + 47 YAML rules from `../04-clawaudit-rules/semgrep/` |
| CodeQL `security-extended` | The `javascript-security-extended.qls` suite (104 queries) |
| CodeQL + ClawAudit         | 30 queries from `../04-clawaudit-rules/codeql/` |

## Headline numbers (held-out test, n = 217)

| Configuration              | Recall (%) |
|----------------------------|-----------:|
| Semgrep Pro                |      21.7 |
| Semgrep + ClawAudit        |      66.8 |
| CodeQL `security-extended` |      13.8 |
| CodeQL + ClawAudit         |      75.1 |

Full table-level breakdowns are under `rq2-recall-lift/`.
