import { McpTool } from '../types';

// A tool registered without readOnlyHint is treated as a write action by
// ChatGPT: it needs a per-call confirmation, and on some workspace plans write
// actions are blocked outright. An entirely read-only server therefore presents
// as having no usable actions at all, with nothing on the wire to explain it.
//
// GET is safe by HTTP semantics, so it can be inferred. Everything else has to
// be named here, because the two mistakes are not symmetric: calling a read tool
// a write costs a confirmation prompt, while calling a write tool read-only lets
// a client invoke it silently. Anything not listed stays a write.
const READ_ONLY_NON_GET: ReadonlySet<string> = new Set([
  // Lark models these as POST because the query goes in the body, but none of
  // them modify anything -- `search.v2.message.create` "creates" a search.
  'docx.builtin.search',
  'search.v2.message.create',
  'wiki.v1.node.search',
  'drive.v1.meta.batchQuery',
]);

export function isReadOnlyTool(tool: McpTool): boolean {
  return tool.httpMethod?.toUpperCase() === 'GET' || READ_ONLY_NON_GET.has(tool.name);
}
