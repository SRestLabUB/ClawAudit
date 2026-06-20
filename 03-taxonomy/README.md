# §3 — Vulnerability Taxonomy

Paper section: **§3 Agent Runtime Vulnerability Taxonomy**.

ClawAudit organizes implementation-level weaknesses in local LLM agent runtimes
into five categories, derived from STRIDE applied to the runtime's data-flow
diagram. Every rule in this artifact (47 Semgrep YAML rules and 30 CodeQL
queries) belongs to exactly one of these categories.

## Files

| File | Description |
|------|-------------|
| `taxonomy.json` | Machine-readable definition of the five categories. Each entry lists the STRIDE threat, the mediating runtime component, the decision question, and example advisories. |
| `stride-mapping.md` | Markdown rendering of Table 1 (paper) and the MECE decision procedure used to classify rules. |

## The five categories at a glance

| ID    | Name                                     | Sink                                        |
|-------|------------------------------------------|---------------------------------------------|
| CAT-1 | Pre-prompt Sanitization (B1)             | prompt builder, memory writer               |
| CAT-2 | Operand-to-Execution (B2)                | exec / spawn / eval / dynamic require       |
| CAT-3 | Action-to-Resource Confinement (B3)      | filesystem op, sandbox, parser-then-allocator |
| CAT-4 | Action-to-Outbound Egress (B4)           | HTTP/WS, log emit, error formatter          |
| CAT-5 | Caller-to-Handler Authorization (B5)     | handler entry, route mount                  |

See `stride-mapping.md` for the full STRIDE derivation and edge-case rules.
