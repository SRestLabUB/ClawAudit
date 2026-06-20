/**
 * @name JSON.parse without size / depth bounding
 * @description JSON.parse(body) where the body is a variable and the enclosing
 *              function has no body-size guard (maxBytes / contentLength check).
 *              Large or deeply nested JSON enables DoS. Cat-3 / CWE-400.
 * @kind problem
 * @id openclaw/json-parse-no-size-limit
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-400
 *       openclaw-cat-3
 */

import javascript

predicate hasSizeGuard(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName().regexpMatch("(?i).*(maxbytes|maxsize|sizelimit|readlimit|contentlengthlimit|jsonsizecheck).*"))
  or
  exists(BinaryExpr be | be.getEnclosingFunction() = f and
    be.getOperator() in ["<",">"," <="," >="] and
    be.getAnOperand().toString().regexpMatch("(?i).*(maxbytes|maxsize|sizelimit|contentlength|maxlength).*"))
}

from MethodCallExpr c, Expr arg
where
  c.getMethodName() = "parse" and
  c.getReceiver().toString() = "JSON" and
  arg = c.getArgument(0) and
  not arg instanceof StringLiteral and
  not hasSizeGuard(c.getEnclosingFunction())
select c, "JSON.parse() on variable '" + arg.toString() + "' has no size guard (DoS risk)."
