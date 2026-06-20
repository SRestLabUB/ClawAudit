# CodeQL Custom Queries Index

Total: **30 queries**.

| Cat | Query ID | Severity | CWE | Description |
|-----|----------|----------|-----|-------------|
| CAT-1 | `memory-write-untrusted` | warning | CWE-913 | Memory store written with content lacking sanitizer |
| CAT-1 | `resource-link-into-prompt` | warning | CWE-77 | Resource-link metadata interpolated into prompt text |
| CAT-1 | `workspace-path-into-system-prompt` | warning | CWE-077 | Workspace / cwd path interpolated into system prompt |
| CAT-2 | `env-vars-no-dangerous-check` | warning | CWE-78 | process.env assignment loop without dangerous-name filter |
| CAT-2 | `execsync-template-literal` | error | CWE-78 | execSync/exec called with a template-literal string |
| CAT-2 | `scp-ssh-unvalidated-host` | error | CWE-78 | SCP/SSH spawn with template-literal host:path argument |
| CAT-2 | `spawn-shell-true` | warning | CWE-78 | spawn with shell:true |
| CAT-3 | `file-write-no-symlink-protection` | warning | CWE-059 | fs.writeFile without symlink protection |
| CAT-3 | `fs-write-risky-path` | warning | CWE-022 | fs write to a risky path variable |
| CAT-3 | `json-parse-no-size-limit` | warning | CWE-400 | JSON.parse without size / depth bounding |
| CAT-3 | `listen-bind-all-interfaces` | warning | CWE-668,CWE-200 | HTTP / TCP server listens on all network interfaces |
| CAT-3 | `path-join-no-containment` | warning | CWE-022 | path.join with risky input lacks boundary check |
| CAT-3 | `path-resolve-no-containment` | warning | CWE-022 | path.resolve with risky input lacks containment check |
| CAT-3 | `realpath-no-symlink-guard` | warning | CWE-059,CWE-367 | realpath() without lstat / isSymbolicLink check |
| CAT-3 | `sandbox-mode-default-off` | warning | CWE-693,CWE-1188 | Sandbox config defaults to off/false |
| CAT-3 | `sensitive-file-write-no-mode` | warning | CWE-276,CWE-732 | Sensitive file written without explicit restrictive mode |
| CAT-4 | `error-stack-in-response` | warning | CWE-209,CWE-200 | Error stack/message returned in HTTP response or chat reply |
| CAT-4 | `fetch-no-ssrf-guard` | warning | CWE-918 | fetch / http.get with a variable URL lacks SSRF guard |
| CAT-4 | `hardcoded-credential-literal` | error | CWE-798 | Hardcoded credential literal |
| CAT-4 | `math-random-for-secret` | error | CWE-330,CWE-338 | Math.random() used to produce a secret / token / nonce |
| CAT-4 | `untrusted-header-into-log` | warning | CWE-117 | Untrusted request header concatenated into log |
| CAT-4 | `url-no-host-allowlist` | warning | CWE-918 | new URL() with variable input lacks host allowlist |
| CAT-4 | `url-with-secret-into-error` | error | CWE-532,CWE-200 | URL variable interpolated into Error / log |
| CAT-5 | `allowlist-no-deny-on-miss` | warning | CWE-285,CWE-863 | Allowlist check without explicit deny-on-miss |
| CAT-5 | `auth-function-default-allow` | warning | CWE-285,CWE-863 | Auth/policy/allowlist function defaults to allow |
| CAT-5 | `reaction-handler-no-auth` | warning | CWE-863,CWE-862 | Reaction / DM / ingress handler missing allowFrom check |
| CAT-5 | `send-action-no-target-validation` | warning | CWE-863 | sendMessage / sendAction with unvalidated target identifier |
| CAT-5 | `weak-token-comparison` | warning | CWE-208,CWE-200 | Weak (non-constant-time) token / secret comparison |
| CAT-5 | `webhook-handler-no-auth` | warning | CWE-862,CWE-306 | Webhook / route handler with no auth check |
| WEB-XSS | `regex-from-user-input` | warning | CWE-1333,CWE-400 | new RegExp() with a non-literal source |
