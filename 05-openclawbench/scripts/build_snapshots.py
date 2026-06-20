#!/usr/bin/env python3
"""Rebuild vulnerable_code/<GHSA>/ snapshots for every advisory in manifest.json.

For each advisory we fetch the pre-fix version of every modified file from
github.com/openclaw/openclaw at the parent SHA of the fix commit. The advisory's
parent_sha and vulnerable_files come from the manifest.

Usage:
    python build_snapshots.py \
        --manifest ../manifest.json \
        --output ./vulnerable_code \
        [--ghsa GHSA-xxx ...]      # optional: limit to specific GHSA IDs
"""
import argparse, json, os, sys, time, urllib.request, urllib.error
from pathlib import Path


def fetch_file(parent_sha: str, path: str, token: str | None) -> bytes | None:
    url = f'https://raw.githubusercontent.com/openclaw/openclaw/{parent_sha}/{path}'
    headers = {'User-Agent': 'openclawbench-rebuild'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        req = urllib.request.Request(url, headers=headers)
        return urllib.request.urlopen(req, timeout=30).read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        if e.code in (403, 429):
            print(f'  rate limited; sleeping 60s ...', file=sys.stderr)
            time.sleep(60)
            return fetch_file(parent_sha, path, token)
        raise


def rebuild_one(adv: dict, out_root: Path, token: str | None) -> tuple[int, int]:
    gid = adv['ghsa_id']
    parent_sha = adv.get('parent_sha')
    files = adv.get('vulnerable_files', [])
    if not parent_sha or not files:
        return 0, 0

    out_dir = out_root / gid
    out_dir.mkdir(parents=True, exist_ok=True)
    ok = 0
    err = 0
    for f in files:
        dst = out_dir / f
        if dst.exists():
            ok += 1
            continue
        content = fetch_file(parent_sha, f, token)
        if content is None:
            err += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, 'wb') as out:
            out.write(content)
        ok += 1
    return ok, err


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', default='../manifest.json',
                    help='Path to OpenClawBench manifest.json')
    ap.add_argument('--output', default='./vulnerable_code',
                    help='Output directory for snapshots')
    ap.add_argument('--ghsa', action='append',
                    help='Limit to specific GHSA IDs (can be repeated)')
    ap.add_argument('--token', default=os.environ.get('GITHUB_TOKEN'),
                    help='GitHub token (also reads $GITHUB_TOKEN). Optional but '
                         'recommended to avoid rate limits.')
    args = ap.parse_args()

    manifest = json.load(open(args.manifest))
    advs = manifest['advisories']
    if args.ghsa:
        keep = set(args.ghsa)
        advs = [a for a in advs if a['ghsa_id'] in keep]
    out_root = Path(args.output)
    out_root.mkdir(parents=True, exist_ok=True)

    print(f'Rebuilding {len(advs)} snapshots into {out_root}')
    if not args.token:
        print('Warning: no GitHub token; rate limits may slow you down.', file=sys.stderr)

    total_ok = total_err = empty = 0
    for i, adv in enumerate(advs, 1):
        ok, err = rebuild_one(adv, out_root, args.token)
        total_ok += ok
        total_err += err
        if ok == 0 and err == 0:
            empty += 1
        if i % 20 == 0 or i == len(advs):
            print(f'  [{i}/{len(advs)}] files_ok={total_ok} files_err={total_err} '
                  f'empty_manifest_entries={empty}')

    print(f'\nDone. Wrote {total_ok} files; {total_err} files could not be fetched.')
    if total_err:
        print('Files that 404 are usually files renamed or removed after the parent '
              'commit; the rest of the snapshot is still valid for scanning.')


if __name__ == '__main__':
    main()
