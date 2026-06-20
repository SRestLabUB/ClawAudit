/**
 * @name fs write to a risky path variable
 * @description fs.writeFile* / unlink / rename with a path argument whose
 *              identifier name suggests user/external origin. Cat-2.
 * @kind problem
 * @id openclaw/fs-write-risky-path
 * @problem.severity warning
 * @precision low
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

from MethodCallExpr c, Identifier pathArg
where
  c.getMethodName() in ["writeFile", "writeFileSync", "appendFile", "appendFileSync",
                         "unlink", "unlinkSync", "rename", "renameSync",
                         "copyFile", "copyFileSync", "createWriteStream"] and
  pathArg = c.getArgument(0) and
  pathArg.getName().regexpMatch("(?i).*(input|param|payload|body|query|req|user|external|untrusted|provided|client|target|requested|userpath|outputpath|filepath).*") and
  not hasContainmentGuard(c.getEnclosingFunction())
select c, "fs." + c.getMethodName() + "() called with risky path '" + pathArg.getName() + "'."
