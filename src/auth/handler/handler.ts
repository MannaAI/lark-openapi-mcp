import { randomBytes } from 'crypto';
import { Express, Request, Response, NextFunction } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { LarkOIDC2OAuthServerProvider, LarkOAuth2OAuthServerProvider } from '../provider';
import { authStore } from '../store';
import { advertisedScopes } from '../config';
import { generatePKCEPair } from '../utils/pkce';
import { logger } from '../../utils/logger';

// Everything the token endpoint can actually verify. client_secret_basic is
// absent on purpose: the SDK's client authentication reads client_id and
// client_secret out of the request body only.
const SUPPORTED_CLIENT_AUTH_METHODS = ['client_secret_post', 'none'];

// ChatGPT registers with token_endpoint_auth_method: 'none' and then refuses the
// registration unless it comes back with a client_secret anyway -- it asks not to
// be given a credential and requires one in the same breath. Honouring 'none' the
// way RFC 7591 says to is what makes it abandon the flow the moment it registers,
// with no error and no request to /authorize. So give it a secret to look at.
//
// Nothing verifies this value: the client is still stored as public, so the SDK's
// token endpoint skips client authentication entirely and does not care whether
// the secret comes back. PKCE (S256, the only challenge method advertised) is the
// actual protection, exactly as it already was for a public client -- this is a
// field in a response, not a credential, and it makes the flow no weaker than it
// is today.
//
// ponytail: theatre for one broken client. Delete it once ChatGPT either honours
// 'none' or moves to Client ID Metadata Documents, which is where the 2026-07-28
// MCP spec is going anyway.
const withPlaceholderClientSecret = (body: unknown, statusCode: number): unknown => {
  const registration = (body ?? {}) as Record<string, unknown>;
  if (statusCode !== 201 || !registration.client_id || registration.client_secret) {
    return body;
  }
  return {
    ...registration,
    client_secret: randomBytes(32).toString('hex'),
    // RFC 7591 s3.2.1 requires this whenever a secret is issued. 0 means it never
    // expires, which is honest: nothing ever checks it.
    client_secret_expires_at: 0,
  };
};

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

  // The protected resource is the MCP endpoint itself, not the origin. Clients
  // send this exact string as the `resource` parameter (RFC 8707) and compare it
  // against the `resource` in the metadata below, so the two have to agree.
  get resourceUrl() {
    return `${this.publicBaseUrl}/mcp`;
  }

  get protectedResourceMetadataUrl() {
    return `${this.publicBaseUrl}/.well-known/oauth-protected-resource/mcp`;
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
    // A client that finds no scopes_supported has nothing to offer the user to
    // pick from, and ChatGPT says so outright ("the discovered OAuth config did
    // not advertise supported scopes"). This is discovery metadata only: the OIDC
    // provider ignores requested scopes and Lark grants whatever the app itself
    // was granted, so advertising them changes what a client can display, not
    // what a token can reach.
    const scopesSupported = advertisedScopes();
    const issuerUrl = new URL(this.issuerUrl);

    // The SDK's registration handler treats a client as public only when it asks
    // for token_endpoint_auth_method: 'none'. Omit the field -- RFC 7591 then
    // defaults it to client_secret_basic -- and it mints a client_secret instead.
    // Nothing here can honour that: the token endpoint reads credentials from the
    // request body, never the Authorization header, and the metadata advertises
    // no such method. So the client walks away holding a secret it can never
    // spend, and one that checks the metadata before authorizing gives up the
    // moment it registers, without saying why. Register anything we cannot
    // actually accept as a public client instead; PKCE is what protects it.
    // Still true as of SDK 1.30.
    this.app.use('/register', (req: Request, res: Response, next: NextFunction) => {
      if (req.method !== 'POST' || !req.body) {
        return next();
      }
      const requested = req.body.token_endpoint_auth_method;
      // Both sides in full. A client that registers and then walks away without
      // authorizing says nothing about why; the registration it was handed is the
      // only evidence of what it objected to, and the request alone does not show
      // what the SDK's handler made of it.
      logger.info(`[LarkAuthHandler] register: request ${JSON.stringify(req.body)}`);
      if (!SUPPORTED_CLIENT_AUTH_METHODS.includes(requested)) {
        req.body.token_endpoint_auth_method = 'none';
        logger.info(`[LarkAuthHandler] register: registering as a public client instead`);
      }
      const json = res.json.bind(res);
      res.json = (body: unknown) => {
        const registration = withPlaceholderClientSecret(body, res.statusCode);
        const { client_secret, ...rest } = registration as Record<string, unknown>;
        logger.info(
          `[LarkAuthHandler] register: response ${res.statusCode} ` +
            `${JSON.stringify(rest)}${client_secret ? ' (+client_secret, redacted)' : ''}`,
        );
        return json(registration);
      };
      next();
    });

    this.app.use(
      mcpAuthRouter({
        provider: this.provider,
        issuerUrl,
        scopesSupported,
        // The protected resource is the MCP endpoint itself, not the origin.
        // Clients send this exact string as the RFC 8707 `resource` and compare it
        // against the metadata, and it is what makes the SDK publish the
        // path-inserted well-known document (RFC 9728 s3.1) an MCP 2025-06-18
        // client looks for first.
        resourceServerUrl: new URL(this.resourceUrl),
      }),
    );

    // Clients that connected before the path-inserted document existed still ask
    // here. Mounted after the router, because as a prefix of the path-inserted
    // path it would otherwise shadow it.
    this.app.use(
      '/.well-known/oauth-protected-resource',
      metadataHandler({
        resource: this.resourceUrl,
        authorization_servers: [issuerUrl.href],
        scopes_supported: scopesSupported,
      }),
    );

    this.app.get('/callback', (req, res) => this.callback(req, res));
  };

  authenticateRequest(req: Request, res: Response, next: NextFunction): void {
    // Without this a 401 carries no pointer to the protected-resource metadata, so
    // a client that discovers auth from the challenge (rather than by probing
    // /.well-known) has nothing to follow.
    requireBearerAuth({
      verifier: this.provider,
      requiredScopes: [],
      resourceMetadataUrl: this.protectedResourceMetadataUrl,
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
