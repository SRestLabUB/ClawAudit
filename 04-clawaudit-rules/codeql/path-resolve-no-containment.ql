/**
 * @name path.resolve with risky input lacks containment check
 * @description path.resolve() with a non-literal argument and no startsWith()
 *              / realpath / assertWithinRoot check in the enclosing function.
 *              Cat-2.
 * @kind problem
 * @id openclaw/path-resolve-no-containment
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-022
 *       openclaw-cat-2
 */

import javascript

predicate hasContainmentGuard(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["assertWithinRoot", "ensureInside", "isWithin", "isInside",
                          "resolveSafe", "checkBoundary"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["startsWith", "isInside", "isWithin",
                          "realpath", "realpathSync", "resolveSafe", "assertWithinRoot"])
}

from MethodCallExpr c, Identifier arg
where
  c.getMethodName() = "resolve" and
  c.getReceiver().toString() = "path" and
  arg = c.getAnArgument() and
  arg.getName().regexpMatch("(?i).*(input|param|payload|body|query|req|user|external|untrusted|provided|client|filename|filepath|userpath|requested|target|relative).*") and
  not hasContainmentGuard(c.getEnclosingFunction())
select c, "path.resolve() with risky argument '" + arg.getName() + "' has no containment check."
