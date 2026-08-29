import express, { NextFunction, Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { InitTransportServerFunction } from '../shared';
import { parseMCPServerOptionsFromRequest, sendJsonRpcError } from './utils';
import { LarkAuthHandler } from '../../auth';
import { logger } from '../../utils/logger';

// The handshake and the catalogue -- everything a client needs to describe the
// server without reaching Lark. tools/call is deliberately absent.
const UNAUTHENTICATED_METHODS = new Set(['initialize', 'notifications/initialized', 'ping', 'tools/list']);

export const isDiscoveryOnly = (body: unknown): boolean => {
  const messages = Array.isArray(body) ? body : [body];
  return (
    messages.length > 0 &&
    messages.every((message) => UNAUTHENTICATED_METHODS.has((message as { method?: string })?.method ?? ''))
  );
};

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
  // than as rejecting something. Method, path and status only -- never the token.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.on('finish', () => {
      // The user agent is what separates a client's backend from the browser it
      // is supposed to send to /authorize, which is the difference between a
      // client rejecting the server and a user never being shown a sign-in.
      logger.info(
        `[http] ${req.method} ${req.originalUrl} -> ${res.statusCode}` +
          `${req.headers.authorization ? ' (bearer)' : ''} ua=${JSON.stringify(req.headers['user-agent'] ?? '')}`,
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

  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    if (authHandler && oauth) {
      // ChatGPT scans a connector's tools before it offers the user anything to
      // sign in to, and it runs that scan with no token. A 401 there reads to it
      // as a server with nothing to offer -- "no actions found" -- so the OAuth
      // flow it just prepared goes unused: it discovers, registers, and stops,
      // without ever opening /authorize. That is exactly the sequence in the
      // deployed server's logs, across every build so far.
      //
      // So answer the handshake and the tool listing unauthenticated. This
      // publishes tool names, descriptions and schemas to anyone who asks. It
      // publishes no Lark data: every tools/call still needs a bearer token, and
      // a user_access_token behind it.
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
