/**
 * @name fs.writeFile without symlink protection
 * @description fs.writeFile* call where the surrounding function has no lstat/
 *              isSymbolicLink check and does not use { flag: 'wx' } (which fails
 *              if target exists). Can be redirected via a symlink. Cat-2.
 * @kind problem
 * @id openclaw/file-write-no-symlink-protection
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-059
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

predicate hasWxFlag(MethodCallExpr c) {
  exists(ObjectExpr o | o = c.getAnArgument() and
    exists(Property p | p = o.getAProperty() and p.getName() = "flag" and
      p.getInit().(StringLiteral).getStringValue().regexpMatch("wx[+]?")))
}

from MethodCallExpr c
where
  c.getMethodName() in ["writeFile","writeFileSync","appendFile","appendFileSync",
                         "createWriteStream","copyFile","copyFileSync"] and
  not hasLstatCheck(c.getEnclosingFunction()) and
  not hasWxFlag(c)
select c, "fs." + c.getMethodName() + "() with no lstat/isSymbolicLink check or 'wx' flag (symlink redirect risk)."
