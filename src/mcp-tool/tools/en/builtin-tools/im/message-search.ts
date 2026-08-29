import * as lark from '@larksuiteoapi/node-sdk';
import { z } from 'zod';
import { McpTool } from '../../../../types';

// Reading your own Lark messages takes two calls and neither one is the obvious
// candidate. Everything here was settled by probing a live tenant, because the
// published reference disagrees with the API on most of it:
//
//   * `/open-apis/search/v2/message` -- the endpoint the generated tool set
//     exposes -- returns message IDs in an ID space `mget` rejects outright
//     ("not a valid {open_message_id}"), so its results cannot be resolved into
//     content at all. `/open-apis/im/v1/messages/search` is the one that works,
//     and it already carries sender, chat, timestamp and a highlighted snippet.
//   * `mget` does not batch despite the name. A comma-joined list is rejected as
//     malformed; an array parameter returns `items: []` with a 200, which is the
//     dangerous one -- it looks like "no results" rather than "wrong format".
//     One ID per request is the only form that returns anything.
//   * Both calls need a token minted by the v2 authorization flow. The legacy
//     `authen/v1` flow yields 99991695 "user authorization API is a legacy
//     version", so the server must run with scopes configured -- that is what
//     selects LarkOAuth2OAuthServerProvider over the OIDC one.
//   * Reading a direct message additionally needs `im:message.p2p_msg:get_as_user`.
//     Without it Lark answers 230027 and names the scope.
//
// Runs entirely on the user's token, so it sees exactly what that person sees in
// Lark, including their own DMs, which no bot identity can reach.
const SEARCH_PATH = '/open-apis/im/v1/messages/search';
const MGET_PATH = '/open-apis/im/v1/messages/mget';

// Each hit costs its own request, so a full page is a burst. Kept well under the
// page ceiling to stay clear of per-user rate limits.
const FETCH_CONCURRENCY = 6;

interface SearchHit {
  id?: string;
  display_info?: string;
  meta_data?: {
    message_id?: string;
    chat_id?: string;
    from_id?: string;
    create_time?: string;
    update_time?: string;
    is_p2p_chat?: boolean;
    type?: string;
  };
}

// Runs `worker` over `items` with a fixed number in flight. Promise.all over a
// whole page would open one connection per hit.
export const mapWithConcurrency = async <T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> => {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index]);
    }
  });
  await Promise.all(runners);
  return results;
};

export const larkImBuiltinMessageSearchTool: McpTool = {
  project: 'im',
  name: 'im.builtin.messageSearch',
  accessTokens: ['user'],
  description:
    '[Feishu/Lark]-IM-Search messages and return their content-Searches the messages visible to the signed-in user, including their own direct messages, and returns each hit with its sender, chat, timestamp and full message body. Prefer this over the raw message search, whose results cannot be resolved into readable content. Results are limited to what that user can already see in Lark. Filtering by chat or sender is not supported by the API, so filter the returned results by their chat_id, from_id and is_p2p_chat fields instead.',
  schema: {
    data: z.object({
      query: z.string().describe('Search keyword'),
    }),
    params: z
      .object({
        page_size: z.number().describe('Hits per page, 1-50 (default 20)').optional(),
        page_token: z.string().describe('Cursor returned as page_token by a previous call').optional(),
      })
      .optional(),
    useUAT: z.boolean().describe('Use user access token, otherwise use tenant access token').optional(),
  },
  customHandler: async (client, params, options): Promise<any> => {
    const fail = (payload: unknown) => ({
      isError: true,
      content: [{ type: 'text' as const, text: JSON.stringify(payload) }],
    });

    try {
      const { userAccessToken } = options || {};
      if (!userAccessToken) {
        return fail({ msg: 'User access token is not configured' });
      }
      const asUser = lark.withUserAccessToken(userAccessToken);

      const search = await client.request(
        { method: 'POST', url: SEARCH_PATH, data: params.data, params: params.params },
        asUser,
      );
      const searchData = (search as any)?.data ?? search;
      const hits: SearchHit[] = Array.isArray(searchData?.items) ? searchData.items : [];

      const messages = await mapWithConcurrency(hits, FETCH_CONCURRENCY, async (hit) => {
        const meta = hit.meta_data || {};
        const base = {
          message_id: meta.message_id ?? hit.id,
          chat_id: meta.chat_id,
          from_id: meta.from_id,
          create_time: meta.create_time,
          is_p2p_chat: meta.is_p2p_chat,
          type: meta.type,
          // The search snippet, wrapping matches in <h> tags. Kept even when the
          // body loads, since it is what actually matched the query.
          snippet: hit.display_info,
        };

        const id = base.message_id;
        if (!id) {
          return base;
        }

        try {
          const full = await client.request({ method: 'GET', url: MGET_PATH, params: { message_ids: id } }, asUser);
          const item = ((full as any)?.data ?? full)?.items?.[0];
          return { ...base, body: item?.body, msg_type: item?.msg_type, sender: item?.sender };
        } catch (error) {
          // One unreadable message must not lose the rest of the page -- a
          // recalled message or one in a chat the scope does not cover still has
          // useful metadata from the search hit.
          return { ...base, body_error: (error as any)?.response?.data?.msg || 'could not load message body' };
        }
      });

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              messages,
              total: messages.length,
              has_more: searchData?.has_more,
              page_token: searchData?.page_token,
            }),
          },
        ],
      };
    } catch (error) {
      return fail((error as any)?.response?.data || (error as Error)?.message || error);
    }
  },
};
