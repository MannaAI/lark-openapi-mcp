import { Express, Request, Response, NextFunction } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { LarkOIDC2OAuthServerProvider, LarkOAuth2OAuthServerProvider } from '../provider';
import { authStore } from '../store';
import { generatePKCEPair } from '../utils/pkce';
import { logger } from '../../utils/logger';

export interface LarkOAuthClientConfig {
  port: number;
  host: string;
  domain: string;

  appId: string;
  appSecret: string;

  scope?: string[];
}

export class LarkAuthHandler {
  protected readonly options: LarkOAuthClientConfig;
  protected readonly provider: LarkOIDC2OAuthServerProvider | LarkOAuth2OAuthServerProvider;

  // Behind a proxy the server only ever sees its own bind address, but every URL
  // below is handed to an external party -- Lark's redirect_uri, the OAuth
  // discovery metadata, the client's authorize redirect -- so they have to be the
  // address the outside world reaches. Falls back to the bind address, which is
  // what the local `lark-mcp login` flow wants.
  get publicBaseUrl() {
    const configured = process.env.PUBLIC_BASE_URL;
    return configured ? configured.replace(/\/+$/, '') : `http://${this.options.host}:${this.options.port}`;
  }

  get callbackUrl() {
    return `${this.publicBaseUrl}/callback`;
  }

  get issuerUrl() {
    return this.publicBaseUrl;
  }

  constructor(
    protected readonly app: Express,
    options: Partial<LarkOAuthClientConfig>,
  ) {
    const { port, host, domain, appId, appSecret } = options;

    if (!port || !host || !domain || !appId || !appSecret) {
      throw new Error('[Lark MCP]  appId, and appSecret are required');
    }

    this.options = options as LarkOAuthClientConfig;

    const params = {
      domain,
      host,
      port,
      appId,
      appSecret,
      callbackUrl: this.callbackUrl,
    };

    if (!this.options.scope?.length) {
      this.provider = new LarkOIDC2OAuthServerProvider(params);
    } else {
      this.provider = new LarkOAuth2OAuthServerProvider(params);
    }
  }

  protected async callback(req: Request, res: Response) {
    const redirectUri = req.query.redirect_uri as string;
    const finalRedirectUri = new URL(redirectUri);
    finalRedirectUri.searchParams.set('code', req.query.code as string);
    finalRedirectUri.searchParams.set('state', req.query.state as string);
    res.redirect(finalRedirectUri.toString());

    if (req.query.state === 'reauthorize') {
      if (!req.query.code || typeof req.query.code !== 'string') {
        logger.error(`[LarkAuthHandler] Failed to exchange authorization code: ${req.query.code}`);
        res.end('error, failed to exchange authorization code, please try again');
        return;
      }

      const codeVerifier = authStore.getCodeVerifier('reauthorize');
      if (!codeVerifier) {
        logger.error(`[LarkAuthHandler] Code verifier not found`);
        res.end('error: code_verifier not found, please try again');
        return;
      }

      await this.provider.exchangeAuthorizationCode(
        { client_id: 'LOCAL', redirect_uris: [] },
        req.query.code,
        codeVerifier,
        this.callbackUrl,
      );

      authStore.removeCodeVerifier('reauthorize');

      logger.info(`[LarkAuthHandler] callback: Successfully exchanged authorization code`);
      res.end('success, you can close this page now');
    }
  }

  setupRoutes = (): void => {
    logger.info(`[LarkAuthHandler] setupRoutes: issuerUrl: ${this.issuerUrl}`);
    this.app.use(mcpAuthRouter({ provider: this.provider, issuerUrl: new URL(this.issuerUrl) }));
    this.app.get('/callback', (req, res) => this.callback(req, res));
  };

  authenticateRequest(req: Request, res: Response, next: NextFunction): void {
    // Without this a 401 carries no pointer to the protected-resource metadata, so
    // a client that discovers auth from the challenge (rather than by probing
    // /.well-known) has nothing to follow.
    requireBearerAuth({
      verifier: this.provider,
      requiredScopes: [],
      resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(this.issuerUrl)),
    })(req, res, next);
  }

  async refreshToken(accessToken: string) {
    const token = await authStore.getToken(accessToken);
    if (!token) {
      logger.error(`[LarkAuthHandler] refreshToken: No local access token found`);
      throw new Error('No local access token found');
    }
    if (!token.extra?.refreshToken) {
      logger.error(`[LarkAuthHandler] refreshToken: No refresh token found`);
      throw new Error('No refresh token found');
    }

    const newToken = await this.provider.exchangeRefreshToken(
      { client_id: token.clientId, redirect_uris: [this.callbackUrl] },
      token.extra?.refreshToken as string,
      token.scopes,
    );

    logger.info(`[LarkAuthHandler] refreshToken: Successfully refreshed token`);

    await authStore.removeToken(accessToken);
    return newToken;
  }

  async reAuthorize(accessToken?: string) {
    if (!accessToken) {
      logger.error(`[LarkAuthHandler] reAuthorize: Invalid access token, please reconnect the mcp server`);
      throw new Error('Invalid access token, please reconnect the mcp server');
    }

    const token = await authStore.getToken(accessToken);
    if (!token) {
      logger.error(`[LarkAuthHandler] reAuthorize: Invalid access token, please reconnect the mcp server`);
      throw new Error('Invalid access token, please reconnect the mcp server');
    }

    const { clientId } = token;

    const { codeVerifier, codeChallenge } = generatePKCEPair();

    authStore.storeCodeVerifier('reauthorize', codeVerifier);

    const authorizeUrl = new URL(`${this.publicBaseUrl}/authorize`);
    authorizeUrl.searchParams.set('client_id', clientId);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('code_challenge', codeChallenge);
    authorizeUrl.searchParams.set('code_challenge_method', 'S256');
    authorizeUrl.searchParams.set('redirect_uri', this.callbackUrl);
    authorizeUrl.searchParams.set('state', 'reauthorize');
    if (this.options.scope) {
      authorizeUrl.searchParams.set('scope', this.options.scope.join(' '));
    }
    return {
      accessToken: '',
      authorizeUrl: authorizeUrl.toString(),
    };
  }
}
