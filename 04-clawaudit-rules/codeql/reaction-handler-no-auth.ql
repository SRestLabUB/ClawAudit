/**
 * @name Reaction / DM / ingress handler missing allowFrom check
 * @description Function named handle*Reaction / on*Reaction / processReaction /
 *              handle*Dm / process*DM whose body has no allowFrom / dmPolicy /
 *              authorize call. Cat-5.
 * @kind problem
 * @id openclaw/reaction-handler-no-auth
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-863
 *       external/cwe/cwe-862
 *       openclaw-cat-5
 */

import javascript

predicate hasAllowFromCall(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName().regexpMatch("(?i).*(allowfrom|allowsender|dmpolicy|allowuser|isallowed|authorize|requireauth|verifyauth|checkperm|haspermission).*"))
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName().regexpMatch("(?i).*(allowfrom|allowsender|dmpolicy|allowuser|isallowed|authorize|requireauth|verifyauth|checkperm|haspermission).*"))
}

from Function f
where
  f.getName().regexpMatch("(?i)(handle|on|process)(reaction|dm|dmingress|directmessage|directmsg).*") and
  exists(f.getBody()) and
  not hasAllowFromCall(f)
select f, "Reaction / DM handler '" + f.getName() + "' has no allowFrom/dmPolicy check."
