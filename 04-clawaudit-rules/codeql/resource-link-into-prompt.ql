/**
 * @name Resource-link metadata interpolated into prompt text
 * @description Template literal containing block.title / block.uri / block.name
 *              fields used to build prompt text. These metadata fields are
 *              attacker-controlled (ACP resource_link). Cat-1.
 * @kind problem
 * @id openclaw/resource-link-into-prompt
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-77
 *       openclaw-cat-1
 */

import javascript

from TemplateLiteral tl, PropAccess pa
where
  pa = tl.getAChild() and
  pa.getPropertyName().regexpMatch("(?i)(title|uri|name|description|label)") and
  exists(string blockName | blockName = pa.getBase().toString() and
    blockName.regexpMatch("(?i).*(block|resource|link|attachment).*"))
select tl, "Prompt template interpolates resource-link metadata '" + pa.toString() + "'."
