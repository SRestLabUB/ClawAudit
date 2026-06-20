/**
 * @name sendMessage / sendAction with unvalidated target identifier
 * @description Functions named send*Message / send*Action / dispatch*  where the
 *              target arg is a variable and there's no isAllowedTarget /
 *              validateTarget / target allowlist call. Cat-5.
 * @kind problem
 * @id openclaw/send-action-no-target-validation
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-863
 *       openclaw-cat-5
 */

import javascript

predicate hasTargetValidation(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName().regexpMatch("(?i).*(validatetarget|isallowedtarget|targetallowed|allowedsendtarget|checkdestination).*"))
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName().regexpMatch("(?i).*(validatetarget|isallowedtarget|targetallowed|allowedsendtarget|checkdestination).*"))
}

from InvokeExpr c, Expr targetArg
where
  c.getCalleeName().regexpMatch("(?i)(send|dispatch)(message|action|reply|notification|broadcast).*") and
  targetArg = c.getArgument(0) and
  not targetArg instanceof StringLiteral and
  not hasTargetValidation(c.getEnclosingFunction())
select c, c.getCalleeName() + "() with unvalidated target '" + targetArg.toString() + "'."
