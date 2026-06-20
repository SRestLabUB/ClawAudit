/**
 * @name Weak (non-constant-time) token / secret comparison
 * @description Comparing a secret / token / hmac with === or != enables timing
 *              attacks. Use crypto.timingSafeEqual. Cat-5 / CWE-208.
 * @kind problem
 * @id openclaw/weak-token-comparison
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-208
 *       external/cwe/cwe-200
 *       openclaw-cat-5
 */

import javascript

from EqualityTest e, Identifier lhs
where
  lhs = e.getAnOperand() and
  lhs.getName().regexpMatch("(?i).*(token|secret|password|hmac|signature|apikey|api_key|hash|digest|mac).*")
select e, "Equality comparison on secret-like identifier '" + lhs.getName() + "' (timing attack risk)."
