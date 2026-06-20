/**
 * @name URL variable interpolated into Error / log
 * @description new Error(...) whose message string interpolates a variable
 *              named url / fileUrl / requestUrl. URLs commonly carry embedded
 *              credentials (Telegram bot tokens, basic-auth, ?api_key). Cat-4.
 * @kind problem
 * @id openclaw/url-with-secret-into-error
 * @problem.severity error
 * @precision medium
 * @tags security
 *       external/cwe/cwe-532
 *       external/cwe/cwe-200
 *       openclaw-cat-4
 */

import javascript

predicate hasRedactor(Function f) {
  exists(InvokeExpr e | e.getEnclosingFunction() = f and
    e.getCalleeName() in ["redactUrl","redactSecret","scrubUrl","sanitizeUrl"])
}

from NewExpr ne, TemplateLiteral tl, Identifier part
where
  ne.getCalleeName().regexpMatch(".*Error$") and
  tl = ne.getAnArgument() and
  part = tl.getAChild() and
  part.getName().regexpMatch("(?i)^(url|fileurl|requesturl|fetchurl|targeturl|telegramurl|boturl)$") and
  not hasRedactor(ne.getEnclosingFunction())
select ne, "new " + ne.getCalleeName() + "() interpolates URL '" + part.getName() + "' (may leak embedded token)."
