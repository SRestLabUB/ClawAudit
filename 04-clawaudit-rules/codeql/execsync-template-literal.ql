/**
 * @name execSync/exec called with a template-literal string
 * @description execSync(`...${var}...`) interpolates a variable into a shell
 *              command string. Use execFile / spawn with an argument array
 *              instead. Cat-2.
 * @kind problem
 * @id openclaw/execsync-template-literal
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-78
 *       openclaw-cat-2
 */

import javascript

from InvokeExpr c, TemplateLiteral tl
where
  (c.getCalleeName() in ["execSync","exec","execFileSync"] or
   exists(MethodCallExpr m | m = c and m.getMethodName() in ["execSync","exec","execFileSync"])) and
  tl = c.getArgument(0) and
  exists(tl.getAChild())  // has at least one interpolated expression
select c, c.getCalleeName() + "() called with template-literal command string (shell injection risk)."
