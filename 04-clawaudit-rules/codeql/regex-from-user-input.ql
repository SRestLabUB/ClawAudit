/**
 * @name new RegExp() with a non-literal source
 * @description new RegExp(x) where x is not a string literal — enables ReDoS
 *              if x is user-controlled, plus regex injection (custom anchors,
 *              alternation). Cat-3 / CWE-1333.
 * @kind problem
 * @id openclaw/regex-from-user-input
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-1333
 *       external/cwe/cwe-400
 *       openclaw-cat-3
 */

import javascript

from NewExpr ne, Expr arg
where
  ne.getCalleeName() = "RegExp" and
  arg = ne.getArgument(0) and
  not arg instanceof StringLiteral and
  not arg instanceof RegExpLiteral
select ne, "new RegExp() constructed from non-literal source — ReDoS / regex-injection risk."
