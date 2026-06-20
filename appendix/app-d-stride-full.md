# Appendix D — STRIDE Mapping and Trust-Boundary Details

Paper section: **Appendix D**.

## Full STRIDE → ClawAudit derivation

| STRIDE threat            | $B_i$ | Crossing data                                  | Downstream op.                       | Mediating component                | Category |
|--------------------------|:-----:|------------------------------------------------|---------------------------------------|------------------------------------|:--------:|
| Tampering                | $B_1$ | untrusted text destined for the prompt         | the model treats text as trusted instruction | prompt builder, memory writer    | **CAT-1** |
| Tampering                | $B_2$ | model- or user-controlled operand              | exec / spawn / eval / dynamic require | tool dispatcher, skill loader      | **CAT-2** |
| Elevation of Privilege   | $B_3$ | filesystem path or sandbox arg                 | resource access on host               | fs adapter, sandbox manager        | **CAT-3** |
| Information Disclosure   | $B_4$ | URL, log message, or error                     | outbound HTTP/WS, log emission, error formatter | network client, logger     | **CAT-4** |
| Spoofing                 | $B_5$ | caller identity at handler entry               | handler-side privileged action        | permission gate, route mount       | **CAT-5** |

## Excluded STRIDE threats

- **Denial of Service** — manifests as runtime resource exhaustion, observable only at runtime; static analysis of source cannot reliably reach it.
- **Repudiation** — concerns audit-logging integrity; orthogonal to the implementation weaknesses targeted here.

## Why Tampering splits into CAT-1 and CAT-2

Tampering crosses two structurally different runtime boundaries with two
different mediating components. At $B_1$, untrusted text enters the prompt
builder; the bug fix is a sanitizer or fence at the prompt construction
site. At $B_2$, untrusted operands enter the tool dispatcher or skill
loader; the bug fix is a validator at the executor call site. A rule that
guards $B_1$ does not guard $B_2$ and vice versa, so the two boundaries are
kept as separate categories. The MECE check then reduces to verifying that
every rule's fix lives at exactly one $B_i$.

## Runtime data-flow boundaries (informal sketch)

```
                  ┌────────────────────────────────┐
                  │      external/user input       │
                  └──────────────┬─────────────────┘
                                 │
                         ─── B1 ─┴────────────────── prompt builder, memory writer
                                 │  (CAT-1: Pre-prompt Sanitization)
                                 │
                  ┌──────────────▼─────────────────┐
                  │              model              │
                  └──────────────┬─────────────────┘
                                 │
                         ─── B2 ─┴────────────────── tool dispatcher, skill loader
                                 │  (CAT-2: Operand-to-Execution)
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
         ─── B3 ─┴── fs/sandbox  │   ─── B4 ─────┴── network client, logger
            (CAT-3)               │       (CAT-4: outbound egress)
                                 │
   incoming call ──── B5 ───────┘    permission gate, route mount
                          (CAT-5: caller-to-handler authorization)
```

Each ClawAudit rule names the boundary it guards (`metadata.cat` in the
Semgrep YAML, `openclaw-cat-N` tag in the CodeQL `.ql`). This labeling
permits a mechanical MECE check at rule-development time.
