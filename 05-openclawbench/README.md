# §5 — OpenClawBench

Paper section: **§5 OpenClawBench**.

`OpenClawBench` is a benchmark of 446 disclosed source-code-level
vulnerabilities from the [openclaw/openclaw](https://github.com/openclaw/openclaw)
repository, partitioned by publication date into a 229-advisory rule-derivation
set (train) and a 217-advisory held-out set (test).

## Files

| File / folder        | Description |
|----------------------|-------------|
| `manifest.json`      | 446 entries, each carrying `ghsa_id`, `cve_id`, `severity`, `cwe_ids`, `published_at`, `summary`, `fix_sha`, `parent_sha`, `vulnerable_files`, and `split` (`train` or `test`). |
| `splits/train.txt`   | 229 GHSA IDs published before 2026-04-01. |
| `splits/test.txt`    | 217 GHSA IDs published on or after 2026-04-01. |
| `scripts/fetch_advisories.py` | Regenerate the manifest from scratch by walking the GitHub Security Advisories API and joining against OSV.dev for fix-commit SHAs. |
| `scripts/build_snapshots.py`  | Rebuild the `vulnerable_code/<GHSA>/` directories by downloading the pre-fix versions of every modified file via `raw.githubusercontent.com`. |

## Statistics

- Severity: 12 critical / 134 high / 250 medium / 50 low.
- Top CWEs: CWE-863 authorization bypass (77), CWE-22 path traversal (31),
  CWE-78 command injection (30), CWE-918 SSRF (20), CWE-285 missing
  authorization (18), CWE-400 resource exhaustion (17), CWE-184 incomplete
  denylist (16), CWE-59 symlink following (15).
- 84 distinct CWE classes in total.

## How to obtain the vulnerable-code snapshots

The snapshots are not bundled with this artifact; they are reproducible from
the manifest. Run:

```sh
cd 05-openclawbench/scripts
export GITHUB_TOKEN=<your token>      # optional but recommended
python3 build_snapshots.py \
    --manifest ../manifest.json \
    --output ../vulnerable_code
```

This walks `manifest.json`, fetches the parent-commit version of every modified
file, and writes the result into `vulnerable_code/<GHSA>/`. Expect about
15--30 minutes with a token; rate limits are the main wall-clock cost.

## Extending the benchmark

To add advisories disclosed after the paper's cutoff:

```sh
cd 05-openclawbench/scripts
python3 fetch_advisories.py \
    --output ../manifest_new.json \
    --since 2026-04-01
```

The script emits a manifest in the same schema. Merge it with `manifest.json`
yourself, or use it standalone to evaluate the rules on newer disclosures.
