# Appendix A — Representative Rule Examples

Paper section: **Appendix A**.

Two representative ClawAudit rules, one Semgrep and one CodeQL, paired so
that they showcase complementary backend strengths.

| File | Backend | Cat | Pattern |
|------|--------|-----|---------|
| `workspace-path-into-system-prompt.yaml` | Semgrep | CAT-1 | Workspace / cwd path interpolated into a system-prompt template without sanitization. |
| `path-join-no-containment.ql`            | CodeQL  | CAT-3 | `path.join` with a risky-named argument, no containment guard reachable in the enclosing function. |

Both rules are written agent-agnostic. The identifier-name regexes apply
to any TypeScript or JavaScript runtime that exposes workspace or filesystem
operations; nothing in the rule body is specific to OpenClaw.

The full ruleset lives under `../../04-clawaudit-rules/`.
