# Appendix B — OpenClawBench Construction Details

Paper section: **Appendix B**.

This appendix documents how OpenClawBench was assembled, mirroring §5.1 of
the paper with implementation detail at a level useful for reproduction.

## Advisory fetching

We enumerated all advisories under `openclaw/openclaw` via the GitHub
Security Advisories REST endpoint with cursor-based pagination:
`/repos/openclaw/openclaw/security-advisories?per_page=100`, followed by the
`Link: rel="next"` cursor. For each of the 602 published advisories
returned, we retrieved the JSON metadata (GHSA identifier, CVE identifier,
summary, description, severity, CVSS, CWE classes, publication and update
timestamps, advisory state, structured affected-package list). Withdrawn
advisories were excluded.

See `../05-openclawbench/scripts/fetch_advisories.py`.

## Fix-commit recovery

The public Security Advisories endpoint does not return the SHA of the
commit that patched each advisory. We recovered it through OSV.dev, whose
`/v1/vulns/<ghsa-id>` endpoint exposes `references` pointing at
`github.com/openclaw/openclaw/commit/<sha>` URLs. Of the 602 advisories,
365 carried at least one such reference. The remainder were either too
recent for OSV.dev's nightly sync (73), or carried no commit-typed
reference in OSV (52), or had a malformed commit reference (4). When
multiple commits were listed, we used the first and verified its parent
existed.

## Snapshot construction

For each advisory with a recovered fix commit, we identified the
*vulnerable revision* as the first parent of the fix commit, walked the
fix commit's `files[]` array, and downloaded the pre-fix version of every
modified file via `raw.githubusercontent.com/openclaw/openclaw/<parent>/<path>`.
The repository directory structure is preserved under
`vulnerable_code/<ghsa-id>/`. Only files touched by the fix commit are
included; this keeps per-advisory snapshots compact and avoids inflating
the file base used by per-advisory scans.

See `../05-openclawbench/scripts/build_snapshots.py`.

## File categorization

Paths matching `/test/`, `/tests/`, `/__tests__/`, `.test-d.ts`,
`*.test.*`, or `*.spec.*` are labeled **test**; paths ending in `.md`,
`.mdx`, `.rst`, `.adoc`, `.txt` are labeled **doc**; all other files
are **vulnerable source code**. The denominator for the recall numbers in
§6 is restricted to advisories whose snapshot contains at least one
non-test, non-documentation file in a scannable JavaScript or TypeScript
extension. This filter excludes 26 advisories whose fix touched only
configuration, lockfiles, or markdown, yielding the 446 scannable
advisories evaluated.

## Temporal train/test split

We split the 446 scannable advisories by publication date with cutoff
**2026-04-01**: 229 advisories published before the cutoff form the
rule-derivation set (train), and 217 advisories published on or after the
cutoff form the held-out test set. The cutoff was chosen operationally as
the date the working advisory set was frozen during rule writing; every
test advisory was therefore collected after the rules had been committed.
The test set is evaluated exactly once, without iteration.

## HEAD live target

For the HEAD finding-volume and precision measurements in §6.5, we cloned
OpenClaw at commit `4752e9a6` (2026-06-05), which contains **16,433**
JavaScript or TypeScript files (19,755 total, 283 MB unpacked). All four
configurations were run against this single revision with default extractor
settings.

## Reproducibility

The manifest plus the two scripts above reconstruct OpenClawBench end to
end from the public GitHub and OSV APIs without further configuration.
