# §4 — ClawAudit Rules

Paper section: **§4 ClawAudit Design**.

ClawAudit instantiates the five-category taxonomy (§3) in two static-analysis
backends:

- **Semgrep**: 47 YAML rules, organized into 10 files.
- **CodeQL**: 30 `.ql` queries packaged as one qlpack.

Both backends target the same patterns. Semgrep encodes them as syntactic
templates over the AST; CodeQL encodes them as declarative predicates over a
relational program representation that supports limited inter-procedural
reasoning. Cross-tool comparison on the same patterns is one of the paper's
core contributions.

## Subdirectories

| Folder    | What it contains |
|-----------|------------------|
| `semgrep/` | 47 Semgrep YAML rules + per-rule `INDEX.md`. |
| `codeql/`  | 30 CodeQL queries + `qlpack.yml` + per-query `INDEX.md`. |

## Per-category rule counts

| Cat                                | Semgrep | CodeQL |
|------------------------------------|--------:|-------:|
| CAT-1 Pre-prompt Sanitization      |       3 |      4 |
| CAT-2 Operand-to-Execution         |       5 |      3 |
| CAT-3 Action-to-Resource           |      14 |     12 |
| CAT-4 Action-to-Outbound           |      13 |      7 |
| CAT-5 Caller-to-Handler Authz      |       9 |      4 |
| Web XSS (uncategorized)            |       3 |      — |
| **Total**                          |  **47** | **30** |

## Running the rules

### Semgrep
```sh
# Scan any TypeScript/JavaScript repository.
semgrep --config semgrep/ /path/to/your/repo
```

### CodeQL
```sh
# Build a database first.
codeql database create /tmp/db --language=javascript \
    --source-root=/path/to/your/repo

# Run all custom queries.
codeql database analyze /tmp/db codeql/ \
    --format=sarif-latest --output=results.sarif
```

See `semgrep/INDEX.md` and `codeql/INDEX.md` for per-rule metadata (category,
CWE, example advisory).
