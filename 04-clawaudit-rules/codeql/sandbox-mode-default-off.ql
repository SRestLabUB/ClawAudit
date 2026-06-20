/**
 * @name Sandbox config defaults to off/false
 * @description Object literal property `sandbox`, `sandboxEnabled`, `sandboxMode`
 *              set to false, "off", or "disabled" — disables a protection mechanism
 *              by default. Cat-3.
 * @kind problem
 * @id openclaw/sandbox-mode-default-off
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-693
 *       external/cwe/cwe-1188
 *       openclaw-cat-3
 */

import javascript

from Property p, Expr v
where
  p.getName().regexpMatch("(?i)(sandbox|sandboxenabled|sandboxmode|isolated|isolation)") and
  v = p.getInit() and
  (
    (v instanceof BooleanLiteral and v.(BooleanLiteral).getValue() = "false")
    or
    (v instanceof StringLiteral and
     v.(StringLiteral).getStringValue().regexpMatch("(?i)(off|disabled|none|false)"))
  )
select p, "Sandbox-related config '" + p.getName() + "' defaults to '" + v.toString() + "'."
