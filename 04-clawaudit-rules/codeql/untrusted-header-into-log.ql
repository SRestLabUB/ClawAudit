/**
 * @name Untrusted request header concatenated into log
 * @description Log calls (logger.info/warn/error, console.*) include a
 *              template literal interpolating a request header (origin, user-agent,
 *              referer, forwarded-for). If logs are later read by an LLM, this
 *              enables indirect prompt injection. Cat-1.
 * @kind problem
 * @id openclaw/untrusted-header-into-log
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-117
 *       openclaw-cat-1
 */

import javascript

predicate isLogCall(InvokeExpr c) {
  c.getCalleeName() in ["log","info","warn","error","debug"]
  or
  exists(MethodCallExpr m | m = c and
    m.getMethodName() in ["log","info","warn","error","debug"])
}

predicate hasNeutralizer(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["neutralizeForLog","sanitizeLog","truncate","escapeLog"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["neutralizeForLog","sanitizeLog","truncate","escapeLog"])
}

from InvokeExpr c, TemplateLiteral tl, Identifier part
where
  isLogCall(c) and
  tl = c.getAnArgument() and
  part = tl.getAChild() and
  part.getName().regexpMatch("(?i).*(origin|useragent|user_agent|referer|referrer|forwardedfor|forwarded_for|xforwardedfor|realip|real_ip|host).*") and
  not hasNeutralizer(c.getEnclosingFunction())
select c, "Log call interpolates untrusted header identifier '" + part.getName() + "' with no neutralizer."
