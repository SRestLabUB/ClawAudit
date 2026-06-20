/**
 * @name spawn with shell:true
 * @description spawn() / exec() with { shell: true } enables shell parsing of
 *              arguments — if any argument is user-controlled the shell will
 *              interpret metacharacters. Cat-2.
 * @kind problem
 * @id openclaw/spawn-shell-true
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-78
 *       openclaw-cat-2
 */

import javascript

from InvokeExpr c, ObjectExpr opts, Property p
where
  (c.getCalleeName() = "spawn" or
   exists(MethodCallExpr m | m = c and m.getMethodName() in ["spawn","exec"])) and
  opts = c.getAnArgument() and
  p = opts.getAProperty() and
  p.getName() = "shell" and
  p.getInit().(BooleanLiteral).getValue() = "true"
select c, c.getCalleeName() + "() called with shell:true (shell interprets args)."
