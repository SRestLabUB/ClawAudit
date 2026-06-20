/**
 * @name process.env assignment loop without dangerous-name filter
 * @description Iterating config entries and assigning to process.env / env without
 *              filtering dangerous names like BASH_ENV, LD_PRELOAD, PYTHONSTARTUP,
 *              DYLD_INSERT_LIBRARIES which enable code execution at subprocess start.
 *              Cat-2.
 * @kind problem
 * @id openclaw/env-vars-no-dangerous-check
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-78
 *       openclaw-cat-2
 */

import javascript

predicate hasDangerousNameFilter(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["isDangerousHostEnvVarName","sanitizeHostExecEnv",
                          "isAllowedEnvVar","filterDangerousEnv"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["isDangerousHostEnvVarName","sanitizeHostExecEnv"])
}

from AssignExpr a, IndexExpr ie, Identifier base
where
  a.getLhs() = ie and
  ie.getBase() = base and
  base.getName().regexpMatch("(?i).*(env|envvars|environment|processenv).*") and
  // inside a loop (for/forEach/for-of)
  exists(LoopStmt l | a.getEnclosingStmt().getParent*() = l)
  and not hasDangerousNameFilter(a.getEnclosingFunction())
select a, "Env-var assignment to '" + base.getName() + "[...]' inside a loop has no dangerous-name filter."
