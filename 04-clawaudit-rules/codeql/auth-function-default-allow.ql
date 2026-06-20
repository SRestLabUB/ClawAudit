/**
 * @name Auth/policy/allowlist function defaults to allow
 * @description Function whose name suggests authorization (isAllowed, canAccess,
 *              hasPermission, allowFrom, authorize) where one of its return
 *              statements unconditionally returns true. Cat-5.
 * @kind problem
 * @id openclaw/auth-function-default-allow
 * @problem.severity warning
 * @precision low
 * @tags security
 *       external/cwe/cwe-285
 *       external/cwe/cwe-863
 *       openclaw-cat-5
 */

import javascript

from Function f, ReturnStmt r, BooleanLiteral lit
where
  f.getName().regexpMatch("(?i)(is)?(allowed|authorized|permitted|granted|canaccess|haspermission|checkallow|authorize|allowfrom|allowsender|allowuser|isallowlisted).*") and
  r.getContainer() = f and
  lit = r.getExpr() and
  lit.getValue() = "true" and
  count(ReturnStmt other | other.getContainer() = f) <= 3
select f, "Auth-like function '" + f.getName() + "' has a default-true return."
