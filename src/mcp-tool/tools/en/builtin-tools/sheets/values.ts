import { McpTool } from '../../../../types';
import * as lark from '@larksuiteoapi/node-sdk';
import { z } from 'zod';

export type sheetsBuiltinToolName = 'sheets.builtin.read';

// Cell values never moved to v3. Sheets v3 covers the workbook and the sheets
// inside it -- create, patch, list, move, filters, filter views, float images,
// find and replace -- and `find` answers with cell *coordinates*, not content.
// Reading a range is still the v2 endpoint below, which upstream's codegen does
// not generate, which is why this is a builtin rather than a name added to
// LARK_TOOLS.
const valuesPath = (token: string) =>
  `/open-apis/sheets/v2/spreadsheets/${encodeURIComponent(token)}/values_batch_get`;

// A spreadsheet is the one document type where a single call can return more
// than a context window holds: 5,000 rows of a data dictionary arrive as one
// JSON array. The cap is per range and overridable, and truncation is reported
// rather than silent, so a model that needs the tail asks for it by range.
const DEFAULT_MAX_ROWS = 200;

type Cell = unknown;

// v2 returns a cell as a primitive when it is plain, and as an array of rich
// text segments when it carries a link, a mention or an at-mention -- each
// segment an object with its own `text`. Left alone, one hyperlinked cell costs
// more tokens than the row it sits in, so segments are joined back into the
// string a person would see. Anything unrecognised is stringified rather than
// dropped: a cell nobody anticipated should still be readable.
const flattenCell = (cell: Cell): unknown => {
  if (Array.isArray(cell)) {
    return cell.map((segment: any) => segment?.text ?? segment?.link ?? '').join('');
  }
  if (cell && typeof cell === 'object') {
    return (cell as any).text ?? JSON.stringify(cell);
  }
  return cell;
};

export const larkSheetsBuiltinReadTool: McpTool = {
  project: 'sheets',
  name: 'sheets.builtin.read',
  // Inert at call time -- customHandler wins over path/httpMethod in
  // registerMcpServer -- but it is what isReadOnlyTool reads, and the request
  // below really is a GET. Without the hint a client treats the tool as a write
  // and asks before every read.
  httpMethod: 'GET',
  accessTokens: ['user', 'tenant'],
  description:
    '[Feishu/Lark]-Docs-Sheets-Read cell values from a spreadsheet-Returns the contents of one or more A1 ranges as rows of values. A range is written `<sheet_id>!A1:D50`, or just `<sheet_id>` for a whole tab. The sheet_id is the `?sheet=` parameter in the spreadsheet URL, so a link alone is enough to read from; sheets_v3_spreadsheetSheet_query lists the tabs of a workbook when it is not. Pass the spreadsheet token from the URL after /sheets/. For a spreadsheet that lives in a wiki, resolve the wiki node with wiki_v2_space_getNode first and read its obj_token. Results are limited to what the signed-in user can already open in Lark.',
  schema: {
    data: z.object({
      spreadsheet_token: z
        .string()
        .describe('Spreadsheet token, the segment after /sheets/ in the URL, or a wiki node obj_token.'),
      ranges: z
        .array(z.string())
        .min(1)
        .describe(
          'A1 ranges to read, each `<sheet_id>!A1:D50`, or a bare `<sheet_id>` for the whole tab. Several ranges are fetched in one call.',
        ),
      max_rows: z
        .number()
        .describe(`Rows to return per range before truncating (default ${DEFAULT_MAX_ROWS}).`)
        .optional(),
      value_render_option: z
        .enum(['ToString', 'Formula', 'FormattedValue', 'UnformattedValue'])
        .describe(
          'How cells are rendered. Leave unset for raw values. Formula returns formulas instead of their results; FormattedValue returns what the sheet displays, dates and currency included.',
        )
        .optional(),
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
      const { spreadsheet_token, ranges, max_rows, value_render_option } = params.data;
      const maxRows = max_rows ?? DEFAULT_MAX_ROWS;

      const query: Record<string, string> = { ranges: ranges.join(',') };
      if (value_render_option) {
        query.valueRenderOption = value_render_option;
      }

      const request = { method: 'GET', url: valuesPath(spreadsheet_token), params: query };
      const response = userAccessToken
        ? await client.request(request, lark.withUserAccessToken(userAccessToken))
        : await client.request(request);

      const payload = (response as any)?.data ?? response;
      const valueRanges = payload?.valueRanges || [];

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              spreadsheet_token,
              revision: payload?.revision,
              value_ranges: valueRanges.map((valueRange: any) => {
                const rows = valueRange?.values || [];
                return {
                  range: valueRange?.range,
                  rows_returned: Math.min(rows.length, maxRows),
                  truncated: rows.length > maxRows ? { total_rows: rows.length } : undefined,
                  values: rows.slice(0, maxRows).map((row: Cell[]) => row.map(flattenCell)),
                };
              }),
            }),
          },
        ],
      };
    } catch (error) {
      return fail((error as any)?.response?.data || error);
    }
  },
};

export const sheetsBuiltinTools = [larkSheetsBuiltinReadTool];
