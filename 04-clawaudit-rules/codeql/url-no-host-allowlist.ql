/**
 * @name new URL() with variable input lacks host allowlist
 * @description new URL(x) on user input followed by a fetch/http call without
 *              an isPrivateIp / isAllowedHost / hostAllowlist check on the
 *              resulting URL's host. Cat-4 / CWE-918.
 * @kind problem
 * @id openclaw/url-no-host-allowlist
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-918
 *       openclaw-cat-4
 */

import javascript

predicate hasHostAllowlist(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["isAllowedHost","isPrivateIp","isLoopback","isPublicIp",
                          "checkSsrfPolicy","assertExternalUrl","validateUrl"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["isAllowedHost","isPrivateIp","isLoopback","isPublicIp",
                          "checkSsrfPolicy","assertExternalUrl"])
}

from NewExpr ne, Expr arg
where
  ne.getCalleeName() = "URL" and
  arg = ne.getArgument(0) and
  not arg instanceof StringLiteral and
  not arg instanceof TemplateLiteral and
  not hasHostAllowlist(ne.getEnclosingFunction())
select ne, "new URL() built from variable '" + arg.toString() + "' has no host allowlist."
