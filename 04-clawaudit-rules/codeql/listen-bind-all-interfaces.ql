/**
 * @name HTTP / TCP server listens on all network interfaces
 * @description server.listen(port, "0.0.0.0") / "::" exposes the service on
 *              every network interface. For local-only services this leaks
 *              unauthenticated endpoints. Cat-3.
 * @kind problem
 * @id openclaw/listen-bind-all-interfaces
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-668
 *       external/cwe/cwe-200
 *       openclaw-cat-3
 */

import javascript

from MethodCallExpr c, StringLiteral host
where
  c.getMethodName() = "listen" and
  host = c.getAnArgument() and
  host.getStringValue().regexpMatch("(0\\.0\\.0\\.0|::|::0)")
select c, "server.listen() bound to all interfaces ('" + host.getStringValue() + "')."
