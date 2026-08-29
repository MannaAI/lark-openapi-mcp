import { McpTool } from '../types';

// The generated tool definitions carry an `accessTokens` list taken from Lark's
// published API reference, and for the IM APIs that reference is behind their
// own product. Lark's official CLI ships all of the endpoints below under
// `--as user`, which is user_access_token, while the reference still documents
// them as tenant-only:
//
//   https://github.com/larksuite/cli/blob/main/skills/lark-im/SKILL.md
//     +chat-messages-list   -> im.v1.message.list    "user/bot"
//     +messages-mget        -> im.v1.message.get     "user/bot"
//     +messages-send        -> im.v1.message.create  "user/bot"
//     +messages-reply       -> im.v1.message.reply   "user/bot"
//     +message-read-users   -> im.v1.message.readUsers "user/bot"
//
// This matters because `filterTools` drops anything without 'user' when the
// server runs in user_access_token mode, so the stale metadata makes reading a
// chat's history or sending as yourself impossible -- silently, since the tool
// simply never appears.
//
// Kept as an override rather than an edit to zod/im_v1.ts because that file is
// regenerated wholesale by the openapi sync, which would revert it without a
// diff anyone would notice.
//
// Each entry is a claim that Lark accepts a user_access_token, verified against
// the deployment rather than assumed -- if one turns out to be wrong the tool
// surfaces a Lark permission error instead of going missing, which is the
// failure we can actually see.
const USER_CAPABLE: ReadonlySet<string> = new Set([
  'im.v1.message.list',
  'im.v1.message.get',
  'im.v1.message.create',
  'im.v1.message.reply',
  'im.v1.message.readUsers',
]);

export function accessTokensFor(tool: McpTool): string[] {
  const declared = tool.accessTokens ?? [];
  if (!USER_CAPABLE.has(tool.name) || declared.includes('user')) {
    return declared;
  }
  return [...declared, 'user'];
}
