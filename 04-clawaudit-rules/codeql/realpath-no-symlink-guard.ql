/**
 * @name realpath() without lstat / isSymbolicLink check
 * @description Calls to fs.realpath* are used to resolve paths but if the result
 *              is later passed to writeFile / readFile, the lack of an lstat /
 *              isSymbolicLink check allows symlink TOCTOU. Cat-2.
 * @kind problem
 * @id openclaw/realpath-no-symlink-guard
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-059
 *       external/cwe/cwe-367
 *       openclaw-cat-2
 */

import javascript

predicate hasLstatCheck(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["lstat","lstatSync","isSymbolicLink"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["lstat","lstatSync","isSymbolicLink"])
}

from InvokeExpr c
where
  c.getCalleeName() in ["realpath","realpathSync"] and
  not hasLstatCheck(c.getEnclosingFunction())
select c, "realpath() used without an accompanying lstat()/isSymbolicLink() check."
