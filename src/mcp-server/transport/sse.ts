import express, { NextFunction, Request, Response } from 'express';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { InitTransportServerFunction } from '../shared';
import { LarkAuthHandler } from '../../auth';
import { parseMCPServerOptionsFromRequest } from './utils';
import { logger } from '../../utils/logger';

export const initSSEServer: InitTransportServerFunction = (
  getNewServer,
  options,
  { needAuthFlow } = { needAuthFlow: false },
) => {
  const { userAccessToken, port, host, oauth } = options;

  if (!port || !host) {
    throw new Error('[Lark MCP] Port and host are required');
  }

  const app = express();
  const transports: Map<string, SSEServerTransport> = new Map();

  // Behind a TLS terminator (Railway, any reverse proxy) the real client IP only
  // exists in X-Forwarded-For. Without this the SDK's auth router rate-limits
  // every user under the proxy's single IP -- one shared bucket, so a handful of
  // users can 429 each other -- and express-rate-limit logs a validation error on
  // every request. Opt-in: trusting the header with no proxy in front would let a
  // client spoof its own IP. The container image sets TRUST_PROXY=1.
  if (process.env.TRUST_PROXY) {
    app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
  }

  let authHandler: LarkAuthHandler | undefined;

  if (!userAccessToken && needAuthFlow) {
    authHandler = new LarkAuthHandler(app, options);
    if (oauth) {
      authHandler.setupRoutes();
    }
  }

  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    if (authHandler && oauth) {
      authHandler.authenticateRequest(req, res, next);
    } else {
      const authToken = req.headers.authorization?.split(' ')[1];
      if (authToken) {
        req.auth = { token: authToken, clientId: 'client_id_for_local_auth', scopes: [] };
      }
      next();
    }
  };

  app.get('/sse', authMiddleware, async (req: Request, res: Response) => {
    logger.info(`[SSEServerTransport] Received GET SSE request`);

    const token = req.auth?.token;
    const { data } = parseMCPServerOptionsFromRequest(req);
    const server = getNewServer({ ...options, ...data, userAccessToken: data.userAccessToken || token }, authHandler);
    const transport = new SSEServerTransport('/messages', res);
    transports.set(transport.sessionId, transport);

    res.on('close', () => {
      transport.close();
      server.close();
      transports.delete(transport.sessionId);
    });

    await server.connect(transport);
  });

  app.post('/messages', authMiddleware, async (req: Request, res: Response) => {
    console.log('Received POST messages request');
    logger.info(`[SSEServerTransport] Received POST messages request`);

    const sessionId = req.query.sessionId as string;
    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(400).send('No transport found for sessionId');
      return;
    }
    await transport.handlePostMessage(req, res);
  });

  console.log('⚠️ SSE Mode is deprecated and will be removed in a future version. Please use Streamable mode instead.');

  app.listen(port, host, (error) => {
    if (error) {
      logger.error(`[SSEServerTransport] Server error: ${error}`);
      process.exit(1);
    }
    console.log(`📡 SSE endpoint: http://${host}:${port}/sse`);
    logger.info(`[SSEServerTransport] SSE endpoint: http://${host}:${port}/sse`);
  });
};
