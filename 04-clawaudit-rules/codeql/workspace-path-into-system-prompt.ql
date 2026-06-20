/**
 * @name Workspace / cwd path interpolated into system prompt
 * @description Template literals containing workspaceDir/cwd/projectRoot
 *              interpolated where the assignment target is a prompt-like
 *              variable. Cat-1.
 * @kind problem
 * @id openclaw/workspace-path-into-system-prompt
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external/cwe/cwe-077
 *       openclaw-cat-1
 */

import javascript

from TemplateLiteral tl, Identifier part, AssignExpr a, Identifier lhs
where
  a.getRhs() = tl and
  lhs = a.getLhs() and
  lhs.getName().regexpMatch("(?i).*(systemprompt|prompttemplate|prompttext|promptmessage).*") and
  part = tl.getAChild() and
  part.getName().regexpMatch("(?i).*(workspacedir|workspacepath|cwd|currentdir|workingdir|projectdir|projectroot)$")
select a,
  "System-prompt template interpolates workspace path '" + part.getName() +
  "' (prompt injection via control chars)."
