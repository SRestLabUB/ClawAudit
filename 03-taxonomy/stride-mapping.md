# STRIDE → ClawAudit Five-Category Mapping

| STRIDE threat            | Boundary | Sink                                  | Mediating component                  | Category |
|--------------------------|----------|---------------------------------------|---------------------------------------|----------|
| Tampering                | B1       | prompt builder, memory writer         | text destined for the prompt          | **CAT-1** Pre-prompt Sanitization |
| Tampering                | B2       | exec / spawn / eval / dynamic require | tool dispatcher, skill loader         | **CAT-2** Operand-to-Execution    |
| Elevation of Privilege   | B3       | filesystem op, sandbox op, parser, bind | fs adapter, sandbox manager         | **CAT-3** Action-to-Resource      |
| Information Disclosure   | B4       | HTTP/WS, log emission, error formatter | network client, logger               | **CAT-4** Action-to-Outbound      |
| Spoofing                 | B5       | handler entry, route mount             | permission gate                      | **CAT-5** Caller-to-Handler Authz |

## Excluded STRIDE threats

- **Denial of Service** — manifests as runtime resource exhaustion; not statically observable.
- **Repudiation** — concerns audit-log integrity; orthogonal to implementation weaknesses.

## MECE decision procedure

Walk the boundaries in order; the first sink that matches the missing guard determines the category:

```
sink = prompt builder / memory writer?         → CAT-1
sink = exec / spawn / eval / dynamic-require?  → CAT-2
sink = non-network non-exec resource op?       → CAT-3
sink = outbound egress (fetch / log / error)?  → CAT-4
sink = handler entry needing authorization?    → CAT-5
```

## Edge cases (classify by fix location, not by downstream impact)

| Rule                              | Cat   | Why                                       |
|-----------------------------------|-------|-------------------------------------------|
| untrusted-header-into-log         | CAT-4 | fix at log call, not at prompt            |
| path-join-user-input-no-boundary  | CAT-3 | fix at fs op, not at exec                 |
| hardcoded-credential-literal      | CAT-4 | fix is data egress at source              |
