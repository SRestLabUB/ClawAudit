#!/usr/bin/env python3
"""Draw a stratified precision sample (matching the paper's methodology)
from a Semgrep JSON and a CodeQL SARIF, then aggregate manual labels.

Usage A: draw a fresh sample.
    python compute_precision.py draw \
        --semgrep /path/to/semgrep_clawaudit.json \
        --codeql  /path/to/codeql_clawaudit.sarif \
        --output  ./sample_50.json \
        --seed 43

Usage B: aggregate per-batch labels.
    python compute_precision.py aggregate \
        --labels-dir ./labels \
        --output     ./aggregated.json
"""
import argparse, glob, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

TEST_RE = re.compile(
    r'(/test/|/tests/|/__tests__/|/__mocks__/|/e2e/|'
    r'\.test\.(t|j)sx?$|\.spec\.(t|j)sx?$|\.e2e\.(t|j)sx?$|'
    r'/vitest\.|/jest\.|/mocha\.)',
    re.I)


def load_semgrep(path: Path):
    return [r for r in json.load(open(path)).get('results', [])
            if not TEST_RE.search(r.get('path', ''))]


def load_codeql(path: Path):
    out = []
    d = json.load(open(path))
    for run in d.get('runs', []):
        for res in run.get('results', []):
            loc = (res.get('locations') or [{}])[0]
            p = loc.get('physicalLocation', {}).get(
                'artifactLocation', {}).get('uri', '')
            if not p or TEST_RE.search(p):
                continue
            region = loc.get('physicalLocation', {}).get('region', {})
            out.append({
                'rule_id': res.get('ruleId', ''),
                'file': p,
                'line_start': region.get('startLine', 0),
                'line_end': region.get('endLine', region.get('startLine', 0)),
                'message': (res.get('message', {}).get('text') or '')[:300],
            })
    return out


def stratify(findings, n, get_rule):
    buckets = defaultdict(list)
    for r in findings:
        buckets[get_rule(r)].append(r)
    sample = []
    for items in buckets.values():
        sample.append(random.choice(items))
    remaining = [r for items in buckets.values() for r in items if r not in sample]
    while len(sample) < n and remaining:
        sample.append(random.choice(remaining))
    return sample[:n]


def cmd_draw(args):
    random.seed(args.seed)
    sg = load_semgrep(Path(args.semgrep)) if args.semgrep else []
    cq = load_codeql(Path(args.codeql)) if args.codeql else []
    print(f'Semgrep production findings: {len(sg)}', file=sys.stderr)
    print(f'CodeQL  production findings: {len(cq)}', file=sys.stderr)

    sg_sample = stratify(sg, args.n_per_tool,
                         lambda r: r['check_id'].split('.')[-1])
    cq_sample = stratify(cq, args.n_per_tool, lambda r: r['rule_id'])

    out = []
    for i, r in enumerate(sg_sample, 1):
        out.append({
            'idx': i, 'tool': 'semgrep',
            'rule_id': r['check_id'].split('.')[-1],
            'file': r['path'],
            'line_start': r['start']['line'],
            'line_end': r['end']['line'],
            'message': r['extra'].get('message', '')[:300],
        })
    for i, r in enumerate(cq_sample, 1):
        out.append({
            'idx': i + args.n_per_tool, 'tool': 'codeql',
            'rule_id': r['rule_id'],
            'file': r['file'],
            'line_start': r['line_start'],
            'line_end': r['line_end'],
            'message': r['message'],
        })
    json.dump(out, open(args.output, 'w'), indent=2)
    print(f'Wrote {len(out)} findings to {args.output}')


def cmd_aggregate(args):
    labels = []
    for f in sorted(glob.glob(str(Path(args.labels_dir) / 'batch_*.json'))):
        labels.extend(json.load(open(f)))

    by_tool = defaultdict(list)
    for l in labels:
        by_tool[l['tool']].append(l)

    summary = {'total': len(labels), 'by_tool': {}, 'per_rule': {}}
    for tool, items in by_tool.items():
        tp = sum(1 for l in items if l['verdict'] == 'TP')
        fp = sum(1 for l in items if l['verdict'] == 'FP')
        uc = sum(1 for l in items if l['verdict'] == 'unclear')
        precision = 100*tp/(tp+fp) if tp+fp > 0 else 0.0
        summary['by_tool'][tool] = {'TP': tp, 'FP': fp, 'unclear': uc,
                                     'sample_size': len(items),
                                     'precision_pct': round(precision, 1)}

    per_rule = defaultdict(lambda: {'tool': '', 'TP': 0, 'FP': 0})
    for l in labels:
        per_rule[l['rule_id']]['tool'] = l['tool']
        per_rule[l['rule_id']][l['verdict']] = \
            per_rule[l['rule_id']].get(l['verdict'], 0) + 1
    summary['per_rule'] = {k: dict(v) for k, v in per_rule.items()}
    summary['labels'] = labels

    json.dump(summary, open(args.output, 'w'), indent=2)
    print(f'Wrote {args.output}: {summary["by_tool"]}')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_draw = sub.add_parser('draw', help='Draw a stratified sample.')
    p_draw.add_argument('--semgrep', help='Semgrep + ClawAudit JSON.')
    p_draw.add_argument('--codeql',  help='CodeQL + ClawAudit SARIF.')
    p_draw.add_argument('--output', required=True)
    p_draw.add_argument('--n-per-tool', type=int, default=25)
    p_draw.add_argument('--seed', type=int, default=43)
    p_draw.set_defaults(func=cmd_draw)

    p_agg = sub.add_parser('aggregate', help='Aggregate manual labels.')
    p_agg.add_argument('--labels-dir', required=True)
    p_agg.add_argument('--output', required=True)
    p_agg.set_defaults(func=cmd_aggregate)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
