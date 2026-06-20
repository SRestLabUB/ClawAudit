/**
 * @name Memory store written with content lacking sanitizer
 * @description appendMemory / writeMemory / fs.writeFile to a memory-like path
 *              (memory.md, memoryStore, memory-core) without a sanitizer in the
 *              same function. Memory replays into future prompts —
 *              "memory contamination". Cat-1.
 * @kind problem
 * @id openclaw/memory-write-untrusted
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-913
 *       openclaw-cat-1
 */

import javascript

predicate hasSanitizer(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["sanitizeMemory","escapeMemoryContent","redactMemory","fenceContent"])
  or
  exists(MethodCallExpr m | m.getEnclosingFunction() = f and
    m.getMethodName() in ["sanitizeMemory","escapeMemoryContent","redactMemory","fenceContent"])
}

from InvokeExpr c
where
  (
    (c.getCalleeName() in ["appendMemory","writeMemory"])
    or
    exists(MethodCallExpr m | m = c and m.getMethodName() in ["appendMemory","writeMemory"])
    or
    exists(MethodCallExpr m | m = c and
      m.getMethodName() in ["writeFile","writeFileSync","appendFile","appendFileSync"] and
      m.getArgument(0).toString().regexpMatch("(?i).*(memory\\.md|memoryfile|memorystore|memory-core|memorycore).*"))
  ) and
  not hasSanitizer(c.getEnclosingFunction())
select c, "Memory store write '" + c.getCalleeName() + "' has no sanitizer (memory-contamination risk)."
