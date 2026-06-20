/**
 * @name path.join with risky input lacks boundary check
 * @description Calls to path.join() where one of the arguments looks like
 *              user-controlled input, with no startsWith()/realpath() containment
 *              check in the same function. Cat-2 path traversal.
 * @kind problem
 * @id openclaw/path-join-no-containment
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-022
 *       openclaw-cat-2
 */

import javascript

predicate hasContainmentGuard(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["startsWith", "isInside", "isWithin", "ensureInside",
                          "realpath", "realpathSync", "resolveSafe", "assertWithinRoot"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["startsWith", "isInside", "isWithin", "ensureInside",
                          "realpath", "realpathSync", "resolveSafe", "assertWithinRoot"])
}

from MethodCallExpr c, Identifier arg
where
  c.getMethodName() = "join" and
  c.getReceiver().toString() = "path" and
  arg = c.getAnArgument() and
  arg.getName().regexpMatch("(?i).*(input|param|payload|body|query|req|user|external|untrusted|provided|client|filename|filepath|userpath|requested|target).*") and
  not hasContainmentGuard(c.getEnclosingFunction())
select c, "path.join() with risky argument '" + arg.getName() + "' has no containment check."
