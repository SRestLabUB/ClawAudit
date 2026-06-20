/**
 * @name Math.random() used to produce a secret / token / nonce
 * @description Math.random() is not cryptographically secure. If its output is
 *              assigned to a token / nonce / session-id, predict-and-replay
 *              attacks become feasible. Use crypto.randomBytes /
 *              crypto.randomUUID. Cat-4 / CWE-330.
 * @kind problem
 * @id openclaw/math-random-for-secret
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-330
 *       external/cwe/cwe-338
 *       openclaw-cat-4
 */

import javascript

predicate isMathRandom(Expr e) {
  exists(MethodCallExpr m | m = e and
    m.getReceiver().toString() = "Math" and
    m.getMethodName() = "random")
}

from Expr e, Identifier target
where
  isMathRandom(e) and
  (
    exists(AssignExpr a | a.getRhs() = e or
      (a.getRhs() instanceof BinaryExpr and a.getRhs().(BinaryExpr).getAnOperand() = e))
  ) and
  (
    exists(AssignExpr a | a.getRhs() = e and target = a.getLhs())
    or
    exists(AssignExpr a | a.getRhs().(BinaryExpr).getAnOperand() = e and target = a.getLhs())
    or
    exists(VariableDeclarator v | v.getInit() = e and target = v.getBindingPattern())
  ) and
  target.getName().regexpMatch("(?i).*(token|nonce|sessionid|sessionkey|secret|requestid|csrf|otp).*")
select e, "Math.random() used to generate '" + target.getName() + "' — use crypto.randomBytes()."
