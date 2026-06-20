/**
 * @name Allowlist check without explicit deny-on-miss
 * @description if (allowlist.includes(x)) { ... allow ... } with no else { deny }.
 *              Code falls through allowing the operation when the entry is missing —
 *              a default-allow on lookup miss. Cat-5.
 * @kind problem
 * @id openclaw/allowlist-no-deny-on-miss
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-285
 *       external/cwe/cwe-863
 *       openclaw-cat-5
 */

import javascript

from IfStmt ifs, MethodCallExpr cond, Identifier base
where
  ifs.getCondition() = cond and
  cond.getMethodName() in ["includes","has","get","find","indexOf"] and
  base = cond.getReceiver() and
  base.getName().regexpMatch("(?i).*(allowlist|allowed|whitelist|approved|permitted|authorized).*") and
  not exists(ifs.getElse())
select ifs, "Allowlist check on '" + base.getName() + "' lacks explicit else { deny } branch."
