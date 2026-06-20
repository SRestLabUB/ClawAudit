/**
 * @name Webhook / route handler with no auth check
 * @description An exported handler / route registration whose body contains no
 *              call resembling auth (isAuthenticated, requireAuth, checkAuth,
 *              authorize, allowFrom). Cat-5.
 * @kind problem
 * @id openclaw/webhook-handler-no-auth
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-862
 *       external/cwe/cwe-306
 *       openclaw-cat-5
 */

import javascript

predicate hasAuthCall(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName().regexpMatch("(?i)(is)?(auth|authenticated|authorized|allowfrom|allowsender|requireauth|checkauth|verifyauth|hasrole|haspermission|canaccess|isadmin|allowuser|checkperm).*"))
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName().regexpMatch("(?i)(is)?(auth|authenticated|authorized|allowfrom|allowsender|requireauth|checkauth|verifyauth|hasrole|haspermission|canaccess|isadmin|allowuser|checkperm).*"))
}

from Function f
where
  f.getName().regexpMatch("(?i)(handle|on|process)(webhook|hook|message|update|event|reaction|command).*") and
  exists(f.getBody()) and
  not hasAuthCall(f) and
  // body is non-trivial: at least one expression statement
  count(ExprStmt s | s.getContainer() = f) >= 2
select f, "Handler '" + f.getName() + "' has no auth-related call in its body."
