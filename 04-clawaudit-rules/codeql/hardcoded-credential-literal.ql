/**
 * @name Hardcoded credential literal
 * @description String literal that looks like an API key / bearer token / bot
 *              token (well-known prefixes or 32+ char hex/base64) assigned to
 *              a secret-named identifier. Cat-4.
 * @kind problem
 * @id openclaw/hardcoded-credential-literal
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-798
 *       openclaw-cat-4
 */

import javascript

from VariableDeclarator v, StringLiteral s, Identifier name
where
  v.getInit() = s and
  name = v.getBindingPattern() and
  name.getName().regexpMatch("(?i)^(token|apikey|api_key|secret|password|accesstoken|refreshtoken|privatekey|bottoken|bearer|authtoken)$") and
  (
    s.getStringValue().regexpMatch("sk-[A-Za-z0-9]{20,}") or
    s.getStringValue().regexpMatch("ghp_[A-Za-z0-9]{20,}") or
    s.getStringValue().regexpMatch("xox[baprs]-[A-Za-z0-9-]{10,}") or
    s.getStringValue().regexpMatch("[0-9]{8,12}:[A-Za-z0-9_-]{30,}") or
    s.getStringValue().regexpMatch("[A-Fa-f0-9]{32,}") or
    s.getStringValue().regexpMatch("[A-Za-z0-9+/]{40,}={0,2}")
  )
select v, "Hardcoded credential assigned to '" + name.getName() + "' (move to env var / secret manager)."
