import { Client } from '@larksuiteoapi/node-sdk';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { LarkMcpToolOptions, McpTool, SettableValue, ToolNameCase, TokenMode } from './types';
import { AllTools, AllToolsZh } from './tools';
import { defaultToolNames } from './constants';
import { filterTools, larkOapiHandler, caseTransf, getShouldUseUAT, isReadOnlyTool } from './utils';
import { LarkAuthHandler, isTokenValid } from '../auth';
import { safeJsonParse } from '../utils/safe-json-parse';
import { OAPI_MCP_ERROR_CODE } from '../utils/constants';
import { logger } from '../utils/logger';

/**
 * Feishu/Lark MCP
 */
export class LarkMcpTool {
  // Lark Client
  private client: Client | null = null;

  // User Access Token
  private userAccessToken: SettableValue = {};

  // Lark User Auth Handler
  private auth: LarkAuthHandler | undefined;

  // Lark MCP Tool Options
  private options: LarkMcpToolOptions;

  // All Tools
  private allTools: McpTool[] = [];

  /**
   * Feishu/Lark MCP
   * @param options Feishu/Lark Client Options
   */
  constructor(options: LarkMcpToolOptions, auth?: LarkAuthHandler) {
    this.options = options;
    this.auth = auth;

    if (options.client) {
      this.client = options.client;
    } else if (options.appId && options.appSecret) {
      this.client = new Client({ appId: options.appId, appSecret: options.appSecret, ...options });
    }

    const isZH = options.toolsOptions?.language === 'zh';

    const filterOptions = {
      allowTools: defaultToolNames,
      tokenMode: this.options.tokenMode || TokenMode.AUTO,
      ...options.toolsOptions,
    };

    this.allTools = filterTools(isZH ? AllToolsZh : AllTools, filterOptions);

    logger.info(`[LarkMcpTool] Initialized with ${this.allTools.length} tools, tokenMode: ${this.options.tokenMode}`);
  }

  /**
   * Get MCP Tools
   * @returns MCP Tool Definition Array
   */
  getTools(): McpTool[] {
    return this.allTools;
  }

  /**
   * Update User Access Token
   * @param userAccessToken User Access Token
   */
  updateUserAccessToken(userAccessToken: string | SettableValue) {
    if (typeof userAccessToken === 'string') {
      this.userAccessToken.value = userAccessToken;
    } else {
      this.userAccessToken = userAccessToken;
    }
  }

  private async getUserAccessToken() {
    if (this.userAccessToken.getter) {
      return await this.userAccessToken.getter();
    }
    return this.userAccessToken.value;
  }

  private async setUserAccessToken(userAccessToken: string) {
    this.userAccessToken.value = userAccessToken;
    if (this.userAccessToken.setter) {
      await this.userAccessToken.setter(userAccessToken);
    }
  }

  async reAuthorize(): Promise<{ userAccessToken?: string; authorizeUrl?: string }> {
    const userAccessToken = await this.getUserAccessToken();
    // if not enable oauth mode, return empty object
    if (!this.auth || !this.options.oauth) {
      return {};
    }
    logger.info(`[LarkMcpTool] Re-authorizing user access token`);
    const { authorizeUrl, accessToken } = await this.auth.reAuthorize(userAccessToken);
    if (accessToken) {
      logger.info(`[LarkMcpTool] Successfully re-authorized user access token`);
      this.setUserAccessToken(accessToken);
      return { userAccessToken: accessToken };
    }
    return { authorizeUrl };
  }

  async ensureGetUserAccessToken(): Promise<{ userAccessToken?: string; authorizeUrl?: string }> {
    const userAccessToken = await this.getUserAccessToken();
    if (!this.auth) {
      return { userAccessToken };
    }

    const { valid, isExpired, token } = await isTokenValid(userAccessToken);
    if (valid) {
      return { userAccessToken };
    }

    logger.info(`[LarkMcpTool] UserAccessToken is invalid or expired, trying to get new token...`);

    try {
      if (isExpired && token?.extra?.refreshToken) {
        logger.info(`[LarkMcpTool] UserAccessToken is expired, trying to use refreshToken to refresh...`);
        const newToken = await this.auth.refreshToken(token.token);
        if (newToken?.access_token) {
          this.setUserAccessToken(newToken.access_token);
          return { userAccessToken: newToken.access_token };
        }
      }
    } catch (error) {
      logger.error(`[LarkMcpTool] Failed to refreshToken: ${error}`);
    }

    // reAuthorize
    return await this.reAuthorize();
  }

  getReAuthorizeMessage(authorizeUrl?: string, errorCode?: number, errorText?: string) {
    // A missing scope and an expired token are the same shape of failure here --
    // both arrive as isError with a code -- and they have opposite remedies. The
    // old text ran them together: it mentioned the developer console and then
    // handed over an authorization link, and a client reading it does the thing
    // with the link in it. Signing in again cannot grant a permission the app was
    // never given, so that loop runs forever, which is what it did.
    //
    // Lark names the scopes it wanted in the error itself -- "Access denied. One
    // of the following scopes is required: [...]" -- and that string is already
    // being passed through as rawErrorText. Say so, and put the console first.
    const isMissingScope = errorCode === OAPI_MCP_ERROR_CODE.USER_ACCESS_TOKEN_UNAUTHORIZED;
    const errorMessage = isMissingScope
      ? 'This user_access_token is valid, but the app has not been granted a scope this API requires. ' +
        'Lark lists the accepted scopes in rawErrorText below. Signing in again will NOT fix this on its own: ' +
        'the scope has to be added to the app in the Lark developer console under Permissions & Scopes and a new ' +
        'version published, and only then does re-authorizing pick it up.'
      : 'Current user_access_token is invalid or expired';

    // The /my-token handout is a standing entry point, not a one-shot authorize
    // URL: nothing about it expires in 60 seconds, there is no redirect_uri for
    // the person to go and configure, and signing in there re-points the
    // connector URL they already pasted into their client. Telling them
    // otherwise is how they end up hunting for a setting that is already right.
    const isHandout = authorizeUrl === this.auth?.tokenHandoutUrl;

    const instruction = !authorizeUrl
      ? ''
      : isMissingScope
        ? [
            'Do this first, in order. The link alone will not help:',
            '1. Add the scope named in rawErrorText to the app in the Lark developer console (Permissions & Scopes, User token scopes).',
            '2. Publish a new version of the app and have it approved.',
            '3. Only then sign in again here:',
            authorizeUrl,
          ].join('\n')
        : isHandout
        ? [
            'Open this link in your browser and sign in to Lark again:',
            authorizeUrl,
            'Your existing connector URL keeps working afterwards -- there is nothing to re-paste or reconfigure.',
          ].join('\n')
        : [
            'Please open the following URL in your browser to complete the authorization:',
            `Note: Ensure the redirect URL (${this.auth?.callbackUrl}) is configured in your app's security settings.`,
            `   If not configured, go to: ${this.options.domain}/app/${this.options.appId}/safe`,
            'Authorization URL:',
            authorizeUrl,
            'This authorization link expires in 60 seconds. Generating a new link will immediately invalidate this one.',
          ]
            .join('\n')
            .trim();

    const reAuthorizeMessage = {
      errorCode,
      errorMessage,
      instruction,
      rawErrorText: errorText,
    };

    return {
      isError: true,
      content: [{ type: 'text' as const, text: JSON.stringify(reAuthorizeMessage) }],
    };
  }

  /**
   * Register Tools to MCP Server
   * @param server MCP Server Instance
   */
  registerMcpServer(server: McpServer, options?: { toolNameCase?: ToolNameCase }): void {
    for (const tool of this.allTools) {
      server.tool(
        caseTransf(tool.name, options?.toolNameCase),
        tool.description,
        tool.schema,
        { readOnlyHint: isReadOnlyTool(tool) },
        async (params: any) => {
          try {
            if (!this.client) {
              return {
                isError: true,
                content: [{ type: 'text' as const, text: JSON.stringify({ msg: 'Client not initialized' }) }],
              };
            }
            const handler = tool.customHandler || larkOapiHandler;

            const shouldUseUAT = getShouldUseUAT(this.options.tokenMode, params?.useUAT ?? false);

            if (shouldUseUAT) {
              const { userAccessToken, authorizeUrl } = await this.ensureGetUserAccessToken();
              if (!userAccessToken) {
                return this.getReAuthorizeMessage(authorizeUrl);
              }

              logger.info(`[LarkMcpTool] Calling tool: ${tool.name}`);
              const result = await handler(this.client, { ...params, useUAT: shouldUseUAT }, { userAccessToken, tool });

              // Content blocks are a discriminated union, and only the text one
              // carries the API error payload.
              const first = result.content?.[0];
              const firstText = first?.type === 'text' ? first.text : undefined;
              const errorCode = safeJsonParse(firstText, { code: 0 }).code;
              if (
                result.isError &&
                [
                  OAPI_MCP_ERROR_CODE.USER_ACCESS_TOKEN_UNAUTHORIZED,
                  OAPI_MCP_ERROR_CODE.USER_ACCESS_TOKEN_INVALID,
                ].includes(errorCode)
              ) {
                logger.info(
                  `[LarkMcpTool] User access token unauthorized the scope or invalid, reAuthorize, errorCode: ${errorCode}`,
                );
                // user access token unauthorized the scope or invalid, reAuthorize
                const { authorizeUrl } = await this.reAuthorize();
                return this.getReAuthorizeMessage(authorizeUrl, errorCode, firstText);
              }

              return result;
            }
            logger.info(`[LarkMcpTool] Calling tool: ${tool.name}`);
            return handler(this.client, { ...params, useUAT: shouldUseUAT }, { tool });
          } catch (error) {
            logger.error(`[LarkMcpTool] Failed to call tool: ${tool.name}, error: ${error}`);
            return {
              isError: true,
              content: [{ type: 'text' as const, text: JSON.stringify((error as Error)?.message) }],
            };
          }
        },
      );
    }
  }
}
