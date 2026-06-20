/**
 * @name SCP/SSH spawn with template-literal host:path argument
 * @description spawn("scp", [..., `${host}:${path}`, ...]) without first
 *              normalizing/validating $host — crafted hostnames inject SCP
 *              options. Cat-2.
 * @kind problem
 * @id openclaw/scp-ssh-unvalidated-host
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-78
 *       openclaw-cat-2
 */

import javascript

predicate hasHostNormalizer(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["normalizeScpRemoteHost","validateRemoteHost","sanitizeHost",
                          "assertValidHost","escapeShellArg"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["normalizeScpRemoteHost","validateRemoteHost","sanitizeHost"])
}

from InvokeExpr c, ArrayExpr args, TemplateLiteral tl, Identifier hostId
where
  (c.getCalleeName() = "spawn" or
   exists(MethodCallExpr m | m = c and m.getMethodName() = "spawn")) and
  c.getArgument(0).(StringLiteral).getStringValue().regexpMatch(".*(scp|ssh).*") and
  args = c.getArgument(1) and
  tl = args.getAnElement() and
  hostId = tl.getAChild() and
  hostId.getName().regexpMatch("(?i).*(host|remote|target|server).*") and
  not hasHostNormalizer(c.getEnclosingFunction())
select c, "spawn(scp/ssh, ...) with unvalidated host identifier '" + hostId.getName() + "'."
