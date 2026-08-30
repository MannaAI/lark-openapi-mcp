import express, { NextFunction, Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { InitTransportServerFunction } from '../shared';
import { parseMCPServerOptionsFromRequest, sendJsonRpcError } from './utils';
import { LarkAuthHandler } from '../../auth';
import { logger } from '../../utils/logger';

export const initStreamableServer: InitTransportServerFunction = (
  getNewServer,
  options,
  { needAuthFlow } = { needAuthFlow: false },
) => {
  const { userAccessToken, oauth, port, host } = options;

  if (!port || !host) {
    throw new Error('[Lark MCP] Port and host are required');
  }

  const app = express();
  app.use(express.json());

  // Behind a TLS terminator (Railway, any reverse proxy) the real client IP only
  // exists in X-Forwarded-For. Without this the SDK's auth router rate-limits
  // every user under the proxy's single IP -- one shared bucket, so a handful of
  // users can 429 each other -- and express-rate-limit logs a validation error on
  // every request. Opt-in: trusting the header with no proxy in front would let a
  // client spoof its own IP. The container image sets TRUST_PROXY=1.
  if (process.env.TRUST_PROXY) {
    app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
  }

  // Nothing else logs per request, so a remote client that never gets past
  // discovery or auth leaves no trace at all and the server reads as idle rather
  // than as rejecting something. Method, path, status and User-Agent only --
  // never the token. The agent string is what tells two clients apart: without
  // it, a discovery sequence that stops halfway cannot be attributed to the
  // client that abandoned it, which is exactly the case worth reading.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.on('finish', () => {
      // The JSON-RPC method, on /mcp only. A client that posts something other
      // than the method you assumed is indistinguishable from one that posts
      // nothing, and both look like a bare 401 in a log that records only the
      // path. Method names carry no user data; the params they arrive with are
      // deliberately not logged.
      const rpc =
        req.path === '/mcp' && req.method === 'POST'
          ? ` rpc=${JSON.stringify(
              (Array.isArray(req.body) ? req.body : [req.body])
                .map((message) => (message as { method?: unknown } | null)?.method ?? null)
                .join(','),
            )} ct=${JSON.stringify(req.headers['content-type'] ?? '')}`
          : '';
      logger.info(
        `[http] ${req.method} ${req.originalUrl} -> ${res.statusCode}` +
          `${req.headers.authorization ? ' (bearer)' : ''}` +
          `${rpc}` +
          ` ua=${JSON.stringify(req.headers['user-agent'] ?? '')}`,
      );
    });
    next();
  });

  let authHandler: LarkAuthHandler | undefined;

  if (!userAccessToken && needAuthFlow) {
    authHandler = new LarkAuthHandler(app, options);
    if (oauth) {
      authHandler.setupRoutes();
    }
  }

  // Methods that describe the server rather than reach Lark with anybody's
  // identity. Answering these without a token costs nothing -- the tool list is
  // generated from static metadata and is the same for every user -- and it is
  // what lets a client show what the server offers before asking anyone to sign
  // in. ChatGPT registers an OAuth client, never opens an authorization window,
  // and reports "no actions found"; unauthenticated it could at least see that
  // there are 29 of them. Every method that actually calls Lark still needs a
  // bearer, so this widens what can be read about the server, not what can be
  // read through it.
  const UNAUTHENTICATED_METHODS = new Set([
    'initialize',
    'notifications/initialized',
    'ping',
    'tools/list',
    'prompts/list',
    'resources/list',
    'resources/templates/list',
  ]);

  const isDiscoveryOnly = (body: unknown): boolean => {
    const messages = Array.isArray(body) ? body : [body];
    return (
      messages.length > 0 &&
      messages.every((message) => {
        const method = (message as { method?: unknown } | null)?.method;
        return typeof method === 'string' && UNAUTHENTICATED_METHODS.has(method);
      })
    );
  };

  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    if (authHandler && oauth) {
      // A bearer is still honoured when one is sent -- this only stops the
      // request being rejected when one is not.
      if (!req.headers.authorization && isDiscoveryOnly(req.body)) {
        return next();
      }
      authHandler.authenticateRequest(req, res, next);
    } else {
      const authToken = req.headers.authorization?.split(' ')[1];
      if (authToken) {
        req.auth = { token: authToken, clientId: 'client_id_for_local_auth', scopes: [] };
      }
      next();
    }
  };

  app.post('/mcp', authMiddleware, async (req: Request, res: Response) => {
    const token = req.auth?.token;
    const { data } = parseMCPServerOptionsFromRequest(req);
    const server = getNewServer({ ...options, ...data, userAccessToken: data.userAccessToken || token }, authHandler);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const handleMethodNotAllowed = async (_req: Request, res: Response) => {
    res
      .writeHead(405)
      .end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
  };

  app.get('/mcp', async (req: Request, res: Response) => {
    try {
      console.log('Received GET MCP request');
      logger.info(`[StreamableServerTransport] Received GET MCP request`);
      await handleMethodNotAllowed(req, res);
    } catch (error) {
      sendJsonRpcError(res, error as Error);
    }
  });

  app.delete('/mcp', async (req: Request, res: Response) => {
    try {
      console.log('Received DELETE MCP request');
      logger.info(`[StreamableServerTransport] Received DELETE MCP request`);
      await handleMethodNotAllowed(req, res);
    } catch (error) {
      sendJsonRpcError(res, error as Error);
    }
  });

  app.listen(port, host, (error) => {
    if (error) {
      logger.error(`[StreamableServerTransport] Server error: ${error}`);
      process.exit(1);
    }
    console.log(`📡 Streamable endpoint: http://${host}:${port}/mcp`);
    logger.info(`[StreamableServerTransport] Streamable endpoint: http://${host}:${port}/mcp`);
  });
};
