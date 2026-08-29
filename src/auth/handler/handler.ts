import { Express, Request, Response, NextFunction } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { mcpAuthRouter, createOAuthMetadata } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { LarkOIDC2OAuthServerProvider, LarkOAuth2OAuthServerProvider } from '../provider';
import { authStore } from '../store';
import { advertisedScopes } from '../config';
import { generatePKCEPair } from '../utils/pkce';
import { CLIENT_ASSERTION_TYPE, readAssertionSubject, verifyClientAssertion } from '../utils/client-assertion';
import { logger } from '../../utils/logger';

// What a dynamically registered client may ask for. client_secret_basic is
// absent on purpose: the SDK's client authentication reads client_id and
// client_secret out of the request body only. private_key_jwt is absent because
// a DCR client has no published key to check an assertion against -- that only
// works for a client whose id is a metadata document.
const SUPPORTED_CLIENT_AUTH_METHODS = ['client_secret_post', 'none'];

// What the token endpoint can verify, which is the above plus the assertion a
// CIMD client signs with the key at its jwks_uri. ChatGPT's document declares
// `token_endpoint_auth_method: private_key_jwt`, and a client that reads this
// list before it authorizes has no reason to start a flow it cannot finish.
const ADVERTISED_CLIENT_AUTH_METHODS = [...SUPPORTED_CLIENT_AUTH_METHODS, 'private_key_jwt'];

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

  // The SDK's client authentication understands client_id and client_secret and
  // nothing else, so a client that authenticates by signed assertion is checked
  // here, ahead of it. Two jobs: reject an assertion that does not verify, and
  // reject a client that declared private_key_jwt and then sent none -- the
  // second is the one that matters, since without it declaring the method would
  // be a way of asking to skip authentication entirely.
  protected async authenticateAssertion(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { client_assertion: assertion, client_assertion_type: assertionType } = req.body;
    const clientId = req.body.client_id || (typeof assertion === 'string' && readAssertionSubject(assertion));

    const fail = (description: string) => {
      logger.error(`[LarkAuthHandler] token: ${description}`);
      res.status(401).json({ error: 'invalid_client', error_description: description });
    };

    if (!clientId) {
      return next();
    }
    const client = await authStore.getClient(clientId);
    // An unknown client is the SDK's error to report, in its own shape.
    if (!client) {
      return next();
    }

    const declared = (client as { token_endpoint_auth_method?: string }).token_endpoint_auth_method;
    if (!assertion) {
      if (declared === 'private_key_jwt') {
        return fail(`${clientId} declares private_key_jwt but sent no client_assertion`);
      }
      return next();
    }

    if (assertionType !== CLIENT_ASSERTION_TYPE) {
      return fail(`unsupported client_assertion_type ${JSON.stringify(assertionType)}`);
    }

    const error = await verifyClientAssertion(client, assertion, [`${this.publicBaseUrl}/token`, this.issuerUrl]);
    if (error) {
      return fail(`${clientId}: ${error}`);
    }

    // The SDK reads client_id out of the body and requires it. RFC 7523 lets a
    // client leave it out and be named by the assertion alone.
    req.body.client_id = clientId;
    logger.info(`[LarkAuthHandler] token: verified private_key_jwt assertion for ${clientId}`);
    next();
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
        const { client_secret, ...rest } = (body ?? {}) as Record<string, unknown>;
        logger.info(
          `[LarkAuthHandler] register: response ${res.statusCode} ` +
            `${JSON.stringify(rest)}${client_secret ? ' (+client_secret, redacted)' : ''}`,
        );
        return json(body);
      };
      next();
    });

    // The SDK publishes `issuer` as URL.href, which for a bare origin is
    // `https://host/`. RFC 8414 s3.3 says the value MUST be identical to the
    // issuer identifier the well-known path was inserted into, and that
    // identifier is `https://host` -- no trailing slash. A client that checks it
    // sees a mismatch and discards the whole document, which looks from here like
    // it read the metadata fine and then lost interest. Measured against three
    // remote MCP servers ChatGPT does connect to (Linear, Sentry, Notion): all
    // three publish the slash-free form, and this server was the only one that
    // did not.
    const oauthMetadata = {
      ...createOAuthMetadata({ provider: this.provider, issuerUrl, scopesSupported }),
      issuer: this.issuerUrl,
      token_endpoint_auth_methods_supported: ADVERTISED_CLIENT_AUTH_METHODS,
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      // Also present on all three, absent here. RFC 8414 lets a client assume the
      // default when it is missing, but only a client that bothers to.
      response_modes_supported: ['query'],
      // A client picks its registration mechanism from this document, in the
      // order the spec gives: pre-registration, then Client ID Metadata Documents
      // if the server says it supports them, then dynamic registration. Without
      // this flag ChatGPT has only /register to fall back to.
      client_id_metadata_document_supported: true,
    } as Parameters<typeof metadataHandler>[0];

    const protectedResourceMetadata = {
      resource: this.resourceUrl,
      authorization_servers: [this.issuerUrl],
      scopes_supported: scopesSupported,
      bearer_methods_supported: ['header'],
    };

    this.app.use('/token', (req: Request, res: Response, next: NextFunction) => {
      if (req.method !== 'POST' || !req.body) {
        return next();
      }
      this.authenticateAssertion(req, res, next).catch(next);
    });

    // Both documents are served ahead of the SDK's own router, which would
    // otherwise answer with the trailing-slash issuer. The router still owns
    // /authorize, /token and /register.
    this.app.use('/.well-known/oauth-authorization-server', metadataHandler(oauthMetadata));
    this.app.use(
      `/.well-known/oauth-protected-resource${new URL(this.resourceUrl).pathname}`,
      metadataHandler(protectedResourceMetadata),
    );

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
    this.app.use('/.well-known/oauth-protected-resource', metadataHandler(protectedResourceMetadata));

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
