/**
 * @name Sensitive file written without explicit restrictive mode
 * @description fs.writeFile* to a path whose identifier name contains
 *              transcript / session / credential / token / memory, without an
 *              explicit { mode: 0o600 } options object. Cat-3.
 * @kind problem
 * @id openclaw/sensitive-file-write-no-mode
 * @problem.severity warning
 * @precision high
 * @tags security
 *       external/cwe/cwe-276
 *       external/cwe/cwe-732
 *       openclaw-cat-3
 */

import javascript

predicate hasModeOption(InvokeExpr c) {
  exists(ObjectExpr o | o = c.getAnArgument() and
    exists(Property p | p = o.getAProperty() and p.getName() = "mode"))
}

predicate isEncodingArg(Expr e) {
  e instanceof StringLiteral and
  e.getStringValue().regexpMatch("utf-?8|utf16le|ascii|latin1|binary|base64|hex")
}

from MethodCallExpr c, Identifier pathArg
where
  c.getMethodName() in ["writeFile","writeFileSync","appendFile","appendFileSync"] and
  pathArg = c.getArgument(0) and
  pathArg.getName().regexpMatch("(?i).*(transcript|session|sessionfile|credential|creds|token|secret|memory).*") and
  not hasModeOption(c) and
  (
    c.getNumArgument() <= 2 or
    isEncodingArg(c.getArgument(2))
  )
select c, "fs." + c.getMethodName() + "() to sensitive path '" + pathArg.getName() + "' has no { mode: 0o600 } option."
