# ClawAudit Artifact

Static auditing for the source-code layer of local LLM agent runtimes.

This artifact accompanies the paper *Local LLM Agents as Vulnerable Runtimes:
A Source-Code Audit of Agent Runtimes*. It contains the rules, the benchmark,
and the evaluation data needed to reproduce every number in §6 and the
appendices.

## What's here

```
clawaudit-artifact/
├── 03-taxonomy/                       § 3   Five-category vulnerability taxonomy
│   ├── README.md
│   ├── taxonomy.json                  machine-readable taxonomy
│   └── stride-mapping.md              STRIDE → cat mapping + decision rule
│
├── 04-clawaudit-rules/                § 4   ClawAudit ruleset
│   ├── README.md
│   ├── semgrep/                       47 YAML rules + INDEX
│   └── codeql/                        30 .ql queries + qlpack + INDEX
│
├── 05-openclawbench/                  § 5   OpenClawBench benchmark
│   ├── README.md
│   ├── manifest.json                  446 advisories: ghsa_id, fix_sha,
│   │                                  parent_sha, vulnerable_files, split
│   ├── splits/
│   │   ├── train.txt                  229 GHSA IDs (rule-derivation)
│   │   └── test.txt                   217 GHSA IDs (held-out)
│   └── scripts/
│       ├── fetch_advisories.py        regenerate the manifest from GitHub + OSV
│       └── build_snapshots.py         rebuild vulnerable_code/<GHSA>/ from raw GH
│
├── 06-evaluation/                     § 6   Five research questions
│   ├── README.md
│   ├── rq1-baseline/                  RQ1: generic-tool baseline recall
│   │   └── per_advisory.csv
│   ├── rq2-recall-lift/               RQ2: ClawAudit recall across CWE
│   │   ├── per_advisory.csv
│   │   ├── table_overall.csv
│   │   ├── table_severity.csv
│   │   └── table_cwe.csv
│   ├── rq3-generalization/            RQ3: train/test gap per CWE
│   │   └── train_test_cwe.csv
│   ├── rq4-precision/                 RQ4: 50-finding manual audit
│   │   ├── sample_50.json
│   │   ├── labels.json
│   │   ├── aggregated.json
│   │   └── replication.md
│   ├── rq5-boundary/                  RQ5: where rule-based stops working
│   │   └── timeout_queries.txt        21 CodeQL queries that did not converge
│   └── scripts/                       end-to-end reproduction scripts
│       ├── run_semgrep_eval.sh
│       ├── run_codeql_eval.sh
│       ├── compute_recall.py
│       └── compute_precision.py
│
├── appendix/                          §A-D  Paper appendices
│   ├── app-a-rule-examples/           one Semgrep + one CodeQL listing
│   ├── app-b-benchmark-construction.md
│   ├── app-c-cwe-longtail.csv         long-tail CWE recall (5 ≤ n ≤ 15)
│   └── app-d-stride-full.md           STRIDE derivation + DFD sketch
│
└── reproduce.sh                       smoke test on 10-advisory subset
```

## Setup

Three external tools, all open-source or freely available:

| Tool          | Version we used | Where to get it |
|---------------|-----------------|-----------------|
| Semgrep       | 1.142.0         | `pip install semgrep` |
| CodeQL CLI    | 2.23.5          | <https://github.com/github/codeql-cli-binaries> |
| Python        | 3.8+            | system package manager |

A GitHub personal-access token is optional but strongly recommended for the
benchmark-building step (avoids unauthenticated rate limits). Set it as
`GITHUB_TOKEN` in your environment.

Disk budget: about **1 GB** once the vulnerable-code snapshots are rebuilt;
the artifact itself is under 5 MB.

## Reproducing the paper

### Smoke test (10 advisories, ~5 minutes)

```sh
bash reproduce.sh 10
```

This downloads ten snapshots, runs all four configurations, and writes a
small recall table under `.scratch/table_overall.csv`. Use it to verify
that Semgrep and CodeQL are wired up correctly.

### Full benchmark (446 advisories, ~1 hour with token)

```sh
# 1. Rebuild the 446 vulnerable_code/<GHSA>/ snapshots.
cd 05-openclawbench/scripts
python3 build_snapshots.py \
    --manifest ../manifest.json \
    --output ../vulnerable_code

# 2. Scan with Semgrep (baseline + ClawAudit).
cd ../../06-evaluation/scripts
bash run_semgrep_eval.sh ../../05-openclawbench/vulnerable_code

# 3. Scan with CodeQL (baseline + ClawAudit).
bash run_codeql_eval.sh ../../05-openclawbench/vulnerable_code

# 4. Recompute Tables 3, 4, 5.
python3 compute_recall.py \
    --semgrep-results ./semgrep_per_advisory \
    --codeql-results  ./codeql_per_advisory
```

### Precision audit (one-time, manual)

```sh
# Draw a fresh 50-finding sample after a HEAD scan.
cd 06-evaluation/scripts
python3 compute_precision.py draw \
    --semgrep /path/to/semgrep_clawaudit.json \
    --codeql  /path/to/codeql_clawaudit.sarif \
    --output  ../rq4-precision/sample_new.json \
    --seed 43

# Label each finding manually (TP/FP). Then aggregate:
python3 compute_precision.py aggregate \
    --labels-dir /path/to/your/labels \
    --output     ../rq4-precision/aggregated_new.json
```

The artifact already contains the 50-finding sample, the labels, and the
aggregated result from the paper (`06-evaluation/rq4-precision/`).

## Headline numbers (held-out test set, n = 217)

| Configuration              | Recall (%) |
|----------------------------|-----------:|
| Semgrep Pro                |      21.7 |
| Semgrep + ClawAudit        |      66.8 |
| CodeQL `security-extended` |      13.8 |
| CodeQL + ClawAudit         |      75.1 |

| Precision audit            | Precision (%) |
|----------------------------|--------------:|
| Semgrep + ClawAudit        |          12.0 |
| CodeQL + ClawAudit         |          12.0 |

## Using the rules outside OpenClaw

Both rule sets are agent-agnostic: identifier-name regexes and pattern
templates are written so that any TypeScript or JavaScript runtime exposing
the same operations will be scanned. To run them on another project:

```sh
# Semgrep
semgrep --config 04-clawaudit-rules/semgrep/ /path/to/your/project

# CodeQL
codeql database create /tmp/db --language=javascript \
    --source-root=/path/to/your/project
codeql database analyze /tmp/db 04-clawaudit-rules/codeql/ \
    --format=sarif-latest --output=results.sarif
```

