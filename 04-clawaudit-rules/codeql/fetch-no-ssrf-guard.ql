/**
 * @name fetch / http.get with a variable URL lacks SSRF guard
 * @description Calls to fetch() / http.get() / axios.get() with a URL argument
 *              that is a variable (not a literal), with no isPrivateIp / allowlist
 *              check in the surrounding function. Cat-4 SSRF.
 * @kind problem
 * @id openclaw/fetch-no-ssrf-guard
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-918
 *       openclaw-cat-4
 */

import javascript

predicate hasSsrfGuard(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["isPrivateIp", "isLoopback", "isPublicIp", "isAllowedUrl",
                          "checkSsrfPolicy", "assertExternalUrl", "validateUrl",
                          "isInAllowlist", "guardSsrf", "ssrfGuard"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["isPrivateIp", "isLoopback", "isPublicIp", "checkSsrf"])
}

from InvokeExpr c, Expr urlArg
where
  (
    c.getCalleeName() = "fetch" or
    exists(MethodCallExpr m | m = c and m.getMethodName() in ["get","post","request"]
      and m.getReceiver().toString().toLowerCase().regexpMatch(".*(http|https|axios|client|fetch).*"))
  ) and
  urlArg = c.getArgument(0) and
  not urlArg instanceof StringLiteral and
  not urlArg instanceof TemplateLiteral and  // template literal w/ vars handled separately
  not hasSsrfGuard(c.getEnclosingFunction())
select c, c.getCalleeName() + "() called with variable URL '" + urlArg.toString() + "' with no SSRF guard."
