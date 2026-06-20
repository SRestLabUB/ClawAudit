# Semgrep Custom Rules Index

Total: **47 rules** across 10 YAML files.

| Cat | Rule ID | Severity | CWE | Example Advisory | File |
|-----|---------|----------|-----|------------------|------|
| CAT-1 | `memory-write-untrusted-content` | WARNING | CWE-20,CWE-913 |  | `openclaw-prompt-handling.yaml` |
| CAT-1 | `resource-link-metadata-into-prompt` | WARNING | CWE-20,CWE-77 | GHSA-74xj-763f-264w | `openclaw-prompt-handling.yaml` |
| CAT-1 | `workspace-path-into-system-prompt` | WARNING | CWE-20,CWE-77 | GHSA-2qj5-gwg2-xwc4 | `openclaw-prompt-handling.yaml` |
| CAT-2 | `env-vars-no-dangerous-name-check` | WARNING | CWE-78 |  | `openclaw-command-injection.yaml` |
| CAT-2 | `execsync-template-literal` | ERROR | CWE-78 |  | `openclaw-command-injection.yaml` |
| CAT-2 | `scp-ssh-accept-new-host-key` | WARNING | CWE-295 |  | `openclaw-command-injection.yaml` |
| CAT-2 | `scp-ssh-unvalidated-remote-host` | ERROR | CWE-78 |  | `openclaw-command-injection.yaml` |
| CAT-2 | `spawn-shell-true-with-user-input` | WARNING | CWE-78 |  | `openclaw-command-injection.yaml` |
| CAT-3 | `browser-output-path-no-symlink-guard` | WARNING | CWE-59 |  | `openclaw-symlink.yaml` |
| CAT-3 | `chrome-no-sandbox-without-validation` | WARNING | CWE-693 | GHSA-43x4-g22p-3hrq | `openclaw-isolation.yaml` |
| CAT-3 | `file-write-without-symlink-protection` | WARNING | CWE-367,CWE-59 |  | `openclaw-symlink.yaml` |
| CAT-3 | `json-parse-no-size-limit` | WARNING | CWE-400 |  | `openclaw-extended.yaml` |
| CAT-3 | `listen-bind-all-interfaces` | WARNING | CWE-668 |  | `openclaw-extended.yaml` |
| CAT-3 | `path-boundary-startswith-only` | INFO | CWE-59,CWE-22 |  | `openclaw-path-traversal.yaml` |
| CAT-3 | `path-join-user-input-no-boundary-check` | WARNING | CWE-22 |  | `openclaw-path-traversal.yaml` |
| CAT-3 | `path-resolve-missing-containment` | WARNING | CWE-22 |  | `openclaw-path-traversal.yaml` |
| CAT-3 | `realpath-without-hardlink-check` | WARNING | CWE-59 |  | `openclaw-symlink.yaml` |
| CAT-3 | `sandbox-mode-default-off` | WARNING | CWE-693,CWE-1188 | GHSA-43x4-g22p-3hrq | `openclaw-isolation.yaml` |
| CAT-3 | `sandbox-path-check-missing-hardlink` | WARNING | CWE-59 |  | `openclaw-symlink.yaml` |
| CAT-3 | `sensitive-file-write-no-mode-restriction` | WARNING | CWE-276,CWE-732 | GHSA-vr7j-g7jv-h5mp | `openclaw-isolation.yaml` |
| CAT-3 | `user-path-to-file-write-no-boundary` | WARNING | CWE-22 |  | `openclaw-path-traversal.yaml` |
| CAT-4 | `error-stack-in-response` | WARNING | CWE-209,CWE-200 |  | `openclaw-extended.yaml` |
| CAT-4 | `external-payload-url-fetch` | WARNING | CWE-918 |  | `openclaw-ssrf.yaml` |
| CAT-4 | `fetch-remote-media-no-ssrf-policy` | WARNING | CWE-918 |  | `openclaw-ssrf.yaml` |
| CAT-4 | `fetch-url-without-ssrf-guard` | WARNING | CWE-918 |  | `openclaw-ssrf.yaml` |
| CAT-4 | `hardcoded-credential-literal` | ERROR | CWE-798 |  | `openclaw-cred-leak-logs.yaml` |
| CAT-4 | `hardcoded-credential-literal` | ERROR | CWE-798 |  | `openclaw-extended.yaml` |
| CAT-4 | `incomplete-private-ip-check` | WARNING | CWE-918 |  | `openclaw-ssrf.yaml` |
| CAT-4 | `math-random-for-secret` | ERROR | CWE-330 |  | `openclaw-extended.yaml` |
| CAT-4 | `secret-variable-into-log` | ERROR | CWE-532 |  | `openclaw-cred-leak-logs.yaml` |
| CAT-4 | `untrusted-header-into-log` | WARNING | CWE-20,CWE-117 | GHSA-g27f-9qjv-22pm | `openclaw-prompt-handling.yaml` |
| CAT-4 | `url-download-protocol-only-check` | WARNING | CWE-918 |  | `openclaw-ssrf.yaml` |
| CAT-4 | `url-no-host-allowlist` | WARNING | CWE-918 |  | `openclaw-extended.yaml` |
| CAT-4 | `url-with-secret-into-error-message` | ERROR | CWE-532,CWE-200 | GHSA-chf7-jq6g-qrwv, GHSA-xwcj-hwhf-h378 | `openclaw-cred-leak-logs.yaml` |
| CAT-5 | `allowlist-no-deny-on-miss` | WARNING | CWE-863 |  | `openclaw-auth-bypass.yaml` |
| CAT-5 | `auth-function-default-allow` | WARNING | CWE-863 |  | `openclaw-auth-bypass.yaml` |
| CAT-5 | `group-policy-mutable-name-lookup` | WARNING | CWE-639,CWE-863 |  | `openclaw-auth-bypass.yaml` |
| CAT-5 | `reaction-handler-missing-auth-check` | WARNING | CWE-863 |  | `openclaw-auth-bypass.yaml` |
| CAT-5 | `send-action-missing-target-validation` | WARNING | CWE-863 |  | `openclaw-auth-bypass.yaml` |
| CAT-5 | `send-action-no-target-validation` | WARNING | CWE-863 |  | `openclaw-extended.yaml` |
| CAT-5 | `weak-token-comparison` | WARNING | CWE-208 |  | `openclaw-extended.yaml` |
| CAT-5 | `webhook-handler-no-auth` | WARNING | CWE-306,CWE-400 |  | `openclaw-auth-bypass.yaml` |
| CAT-5 | `webhook-handler-no-auth-broad` | WARNING | CWE-862 |  | `openclaw-extended.yaml` |
| WEB-XSS | `regex-from-user-input` | WARNING | CWE-1333,CWE-400 |  | `openclaw-extended.yaml` |
| WEB-XSS | `xss-json-stringify-html-splice` | WARNING | CWE-79 |  | `xss-json-stringify-inline-script.yaml` |
| WEB-XSS | `xss-json-stringify-in-inline-script` | WARNING | CWE-79 |  | `xss-json-stringify-inline-script.yaml` |
| WEB-XSS | `xss-json-stringify-in-script-tag-regex` | INFO | CWE-79 |  | `xss-json-stringify-inline-script.yaml` |
