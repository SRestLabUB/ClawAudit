/**
 * @name Error stack/message returned in HTTP response or chat reply
 * @description An Express-like response or message-send call whose body
 *              contains err.stack / err.message / formatError(...) — exposes
 *              internal paths, env vars, and config. Cat-4.
 * @kind problem
 * @id openclaw/error-stack-in-response
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-200
 *       openclaw-cat-4
 */

import javascript

from MethodCallExpr c, Expr arg, PropAccess pa
where
  c.getMethodName() in ["send","json","reply","write","end","sendMessage"] and
  arg = c.getAnArgument() and
  (
    pa = arg or
    (arg instanceof TemplateLiteral and pa = arg.(TemplateLiteral).getAChild())
  ) and
  pa.getPropertyName() in ["stack","message"] and
  pa.getBase().toString().regexpMatch("(?i)^(err|error|e|ex|exception)$")
select c, "Response/reply includes '" + pa.toString() + "' (exposes internal info)."
