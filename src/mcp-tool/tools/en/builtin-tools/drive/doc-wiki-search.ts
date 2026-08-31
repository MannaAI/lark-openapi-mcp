import { McpTool } from '../../../../types';
import * as lark from '@larksuiteoapi/node-sdk';
import { z } from 'zod';

export type driveBuiltinToolName = 'drive.builtin.search';

const SEARCH_PATH = '/open-apis/search/v2/doc_wiki/search';

// The server rejects a longer query outright with 99992402 rather than
// truncating it, so the cap is enforced here where the model can read it.
const MAX_QUERY_LENGTH = 30;

type Filter = Record<string, unknown>;

// folder_tokens belongs to doc_filter and space_ids to wiki_filter, and the two
// are mutually exclusive: narrowing to a Drive folder makes the wiki half of the
// search meaningless and vice versa. With neither, both halves are sent, which
// is the whole point of this endpoint over the legacy docs-only search.
//
// ponytail: the doc_filter/wiki_filter envelope follows larksuite/cli's
// documented flag mapping (skills/lark-drive/references/lark-drive-search.md)
// and has not been fired at a live tenant -- the app is missing search:docs:read,
// so every probe stops at 99991672 before the body is ever parsed. If the shape
// is wrong Lark answers with a field validation error naming the field.
const buildBody = (params: any) => {
  const { query, page_size, page_token, folder_tokens, space_ids, ...rest } = params.data;

  const filter: Filter = {};
  for (const [key, value] of Object.entries(rest)) {
    if (value !== undefined) {
      filter[key] = value;
    }
  }

  const body: Record<string, unknown> = { query };
  if (page_size !== undefined) {
    body.page_size = page_size;
  }
  if (page_token !== undefined) {
    body.page_token = page_token;
  }

  if (space_ids?.length) {
    body.wiki_filter = { ...filter, space_ids };
  } else if (folder_tokens?.length) {
    body.doc_filter = { ...filter, folder_tokens };
  } else {
    body.doc_filter = { ...filter };
    body.wiki_filter = { ...filter };
  }

  return body;
};

export const larkDriveBuiltinSearchTool: McpTool = {
  project: 'drive',
  name: 'drive.builtin.search',
  accessTokens: ['user', 'tenant'],
  description:
    '[Feishu/Lark]-Docs-Search documents and wiki pages by keyword-Searches Drive and Wiki together and returns docx documents, wiki nodes, sheets, Base tables, folders and files with their titles, tokens, types and URLs. Prefer this over docx.builtin.search, which calls an older endpoint that cannot return docx documents or wiki nodes at all. Results are limited to what the signed-in user can already see in Lark: a document that does not appear may simply not be shared with them, which is not evidence that it does not exist. To find what a particular person owns, resolve their open_id first and pass it as creator_ids.',
  schema: {
    data: z.object({
      query: z
        .string()
        .max(
          MAX_QUERY_LENGTH,
          `Query is limited to ${MAX_QUERY_LENGTH} characters. Compress it to the core entity and topic instead of passing a whole question.`,
        )
        .describe(
          'Search keyword, at most 30 characters. Supports intitle:, quoted phrases, OR and -. Pass an empty string to browse by filters alone.',
        ),
      doc_types: z
        .array(z.enum(['doc', 'docx', 'sheet', 'bitable', 'mindnote', 'file', 'wiki', 'folder', 'slides', 'shortcut']))
        .describe('Restrict to these object types. Modern Lark documents are docx, and wiki pages are wiki.')
        .optional(),
      creator_ids: z
        .array(z.string())
        .describe(
          'Open IDs of the document owners. Despite the field name this matches the owner, not whoever originally created the document.',
        )
        .optional(),
      space_ids: z
        .array(z.string())
        .describe('Restrict the search to these wiki spaces. Mutually exclusive with folder_tokens.')
        .optional(),
      folder_tokens: z
        .array(z.string())
        .describe('Restrict the search to these Drive folders. Mutually exclusive with space_ids.')
        .optional(),
      only_title: z.boolean().describe('Match the query against titles only, ignoring document bodies.').optional(),
      page_size: z.number().describe('Hits per page, at most 20 (default 15).').optional(),
      page_token: z.string().describe('Cursor returned as page_token by a previous call.').optional(),
    }),
    useUAT: z.boolean().describe('Use user access token, otherwise use tenant access token').optional(),
  },
  customHandler: async (client, params, options): Promise<any> => {
    const fail = (payload: unknown) => ({
      isError: true,
      content: [{ type: 'text' as const, text: JSON.stringify(payload) }],
    });

    try {
      const { userAccessToken } = options || {};
      if (params.data.space_ids?.length && params.data.folder_tokens?.length) {
        return fail({
          msg: 'space_ids searches wiki and folder_tokens searches Drive; pass one or neither, not both.',
        });
      }

      const body = buildBody(params);
      const response = userAccessToken
        ? await client.request(
            { method: 'POST', url: SEARCH_PATH, data: body },
            lark.withUserAccessToken(userAccessToken),
          )
        : await client.request({ method: 'POST', url: SEARCH_PATH, data: body });

      return {
        content: [{ type: 'text' as const, text: JSON.stringify((response as any)?.data ?? response) }],
      };
    } catch (error) {
      return fail((error as any)?.response?.data || error);
    }
  },
};

export const driveBuiltinTools = [larkDriveBuiltinSearchTool];
