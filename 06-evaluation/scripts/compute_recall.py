#!/usr/bin/env python3
"""From per-advisory Semgrep JSON and CodeQL SARIF, compute the recall
tables reported in §6 (Tables 3, 4, 5) and write them as CSVs.

Usage:
    python compute_recall.py \
        --manifest        ../../05-openclawbench/manifest.json \
        --semgrep-results /path/to/semgrep_per_advisory \
        --codeql-results  /path/to/codeql_per_advisory \
        --output-dir      .

The semgrep-results dir should contain `baseline/` and `clawaudit/`
subdirs, each holding one `<GHSA>.json` per advisory; same layout for
codeql-results.
"""
import argparse, csv, json, os, re, sys
from pathlib import Path
from collections import Counter, defaultdict

TEST_RE = re.compile(
    r'(/test/|/tests/|/__tests__/|/__mocks__/|/e2e/|'
    r'\.test\.(t|j)sx?$|\.spec\.(t|j)sx?$|\.e2e\.(t|j)sx?$|'
    r'/vitest\.|/jest\.|/mocha\.)',
    re.I)


def sg_detected(json_path: Path) -> bool:
    """Did Semgrep produce a finding in a non-test file?"""
    if not json_path.exists():
        return False
    try:
        d = json.load(open(json_path))
    except Exception:
        return False
    for r in d.get('results', []):
        if not TEST_RE.search(r.get('path', '')):
            return True
    return False


def cq_detected(sarif_path: Path) -> bool:
    """Did CodeQL produce a finding in a non-test file?"""
    if not sarif_path.exists():
        return False
    try:
        d = json.load(open(sarif_path))
    except Exception:
        return False
    for run in d.get('runs', []):
        for res in run.get('results', []):
            for loc in res.get('locations', []):
                p = loc.get('physicalLocation', {}).get(
                    'artifactLocation', {}).get('uri', '')
                if p and not TEST_RE.search(p):
                    return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', default='../../05-openclawbench/manifest.json')
    ap.add_argument('--semgrep-results', default='./semgrep_per_advisory')
    ap.add_argument('--codeql-results', default='./codeql_per_advisory')
    ap.add_argument('--output-dir', default='.')
    args = ap.parse_args()

    manifest = json.load(open(args.manifest))
    advs = manifest['advisories']
    sg_dir = Path(args.semgrep_results)
    cq_dir = Path(args.codeql_results)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    train = set(); test = set()
    for a in advs:
        gid = a['ghsa_id']
        sp = sg_detected(sg_dir / 'baseline' / f'{gid}.json')
        sc = sg_detected(sg_dir / 'clawaudit' / f'{gid}.json')
        cp = cq_detected(cq_dir / 'baseline' / f'{gid}.sarif')
        cc = cq_detected(cq_dir / 'clawaudit' / f'{gid}.sarif')
        rows.append({**a, 'semgrep_pro': sp, 'semgrep_clawaudit': sc,
                     'codeql_secext': cp, 'codeql_clawaudit': cc})
        if a['split'] == 'train': train.add(gid)
        else: test.add(gid)

    # per-advisory CSV
    with open(out / 'per_advisory.csv', 'w') as f:
        w = csv.writer(f)
        w.writerow(['ghsa_id', 'split', 'severity', 'cwe_ids',
                    'semgrep_pro', 'semgrep_clawaudit',
                    'codeql_secext', 'codeql_clawaudit'])
        for r in rows:
            w.writerow([r['ghsa_id'], r['split'], r['severity'],
                        ';'.join(r['cwe_ids'] or []),
                        int(r['semgrep_pro']), int(r['semgrep_clawaudit']),
                        int(r['codeql_secext']), int(r['codeql_clawaudit'])])
    print(f'Wrote per_advisory.csv ({len(rows)} rows)')

    # Overall table
    configs = [
        ('Semgrep Pro',          'semgrep_pro',       'semgrep_pro'),
        ('Semgrep + ClawAudit',  'semgrep_pro',       'semgrep_clawaudit'),
        ('CodeQL security-extended', 'codeql_secext', 'codeql_secext'),
        ('CodeQL + ClawAudit',   'codeql_secext',     'codeql_clawaudit'),
    ]
    def recall(key, base_key, ids):
        return sum(1 for r in rows if r['ghsa_id'] in ids and (r[key] or r[base_key]))
    with open(out / 'table_overall.csv', 'w') as f:
        w = csv.writer(f)
        w.writerow(['configuration', 'train_detected', 'train_total', 'train_pct',
                    'test_detected', 'test_total', 'test_pct', 'delta_pp'])
        for name, base, key in configs:
            td = recall(key, base, train); ed = recall(key, base, test)
            tn, en = len(train), len(test)
            tpc = 100*td/tn; epc = 100*ed/en
            w.writerow([name, td, tn, f'{tpc:.1f}', ed, en, f'{epc:.1f}',
                        f'{epc-tpc:+.1f}'])

    # Severity table
    sev_g = defaultdict(set)
    for r in rows: sev_g[r['severity']].add(r['ghsa_id'])
    with open(out / 'table_severity.csv', 'w') as f:
        w = csv.writer(f)
        w.writerow(['severity', 'n', 'semgrep_pro', 'semgrep_clawaudit',
                    'codeql_secext', 'codeql_clawaudit'])
        for sev in ['critical', 'high', 'medium', 'low']:
            ids = sev_g[sev]; n = len(ids)
            if n == 0: continue
            sp = sum(1 for r in rows if r['ghsa_id'] in ids and r['semgrep_pro'])
            sc = sum(1 for r in rows if r['ghsa_id'] in ids
                     and (r['semgrep_clawaudit'] or r['semgrep_pro']))
            cp = sum(1 for r in rows if r['ghsa_id'] in ids and r['codeql_secext'])
            cc = sum(1 for r in rows if r['ghsa_id'] in ids
                     and (r['codeql_clawaudit'] or r['codeql_secext']))
            w.writerow([sev, n, f'{100*sp/n:.1f}', f'{100*sc/n:.1f}',
                        f'{100*cp/n:.1f}', f'{100*cc/n:.1f}'])

    # CWE table
    cwe_g = defaultdict(set)
    for r in rows:
        for c in (r['cwe_ids'] or []):
            cwe_g[c].add(r['ghsa_id'])
    with open(out / 'table_cwe.csv', 'w') as f:
        w = csv.writer(f)
        w.writerow(['cwe', 'n', 'semgrep_pro', 'semgrep_clawaudit',
                    'codeql_secext', 'codeql_clawaudit'])
        for cwe, ids in sorted(cwe_g.items(), key=lambda x: -len(x[1])):
            n = len(ids)
            if n < 5: continue
            sp = sum(1 for r in rows if r['ghsa_id'] in ids and r['semgrep_pro'])
            sc = sum(1 for r in rows if r['ghsa_id'] in ids
                     and (r['semgrep_clawaudit'] or r['semgrep_pro']))
            cp = sum(1 for r in rows if r['ghsa_id'] in ids and r['codeql_secext'])
            cc = sum(1 for r in rows if r['ghsa_id'] in ids
                     and (r['codeql_clawaudit'] or r['codeql_secext']))
            w.writerow([cwe, n, f'{100*sp/n:.1f}', f'{100*sc/n:.1f}',
                        f'{100*cp/n:.1f}', f'{100*cc/n:.1f}'])

    print('Wrote table_overall.csv, table_severity.csv, table_cwe.csv')


if __name__ == '__main__':
    main()
