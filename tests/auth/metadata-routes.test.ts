import express from 'express';
import { AddressInfo } from 'net';
import { Server } from 'http';
import { LarkAuthHandler } from '../../src/auth/handler/handler';

jest.mock('fs', () => ({
  existsSync: jest.fn().mockReturnValue(false),
  watch: jest.fn(),
  readFileSync: jest.fn(),
  writeFileSync: jest.fn(),
  mkdirSync: jest.fn(),
}));

jest.mock('../../src/auth/utils/storage-manager', () => ({
  storageManager: {
    loadStorageData: jest.fn().mockResolvedValue({ tokens: {}, clients: {} }),
    saveStorageData: jest.fn().mockResolvedValue(undefined),
    storageFile: '/mock/storage/storage.json',
  },
}));

// The discovery documents are the only thing a client sees before it decides
// whether it can authenticate at all, and getting them wrong fails silently --
// the client just never comes back. Mount the real routes and read them back
// over HTTP, since which route wins for a given path is the thing being tested.
describe('OAuth discovery metadata', () => {
  const BASE = 'https://mcp.example.com';
  let server: Server;
  let origin: string;

  beforeAll((done) => {
    process.env.PUBLIC_BASE_URL = BASE;
    process.env.LARK_OAUTH_SCOPES = 'docx:document im:message:readonly';

    const app = express();
    app.use(express.json());
    new LarkAuthHandler(app, {
      port: 3000,
      host: 'localhost',
      domain: 'https://open.larksuite.com',
      appId: 'cli_test',
      appSecret: 'secret',
    }).setupRoutes();

    server = app.listen(0, '127.0.0.1', () => {
      origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    delete process.env.PUBLIC_BASE_URL;
    delete process.env.LARK_OAUTH_SCOPES;
    server.close(() => done());
  });

  const read = async (path: string) => {
    const res = await fetch(`${origin}${path}`);
    expect(res.status).toBe(200);
    return res.json();
  };

  it('advertises a token endpoint a public client can actually use', async () => {
    const metadata = await read('/.well-known/oauth-authorization-server');

    // /register issues clients with no client_secret, so omitting 'none' here
    // describes a token endpoint they can never satisfy.
    expect(metadata.token_endpoint_auth_methods_supported).toContain('none');
    expect(metadata.code_challenge_methods_supported).toContain('S256');
    expect(metadata.registration_endpoint).toBe(`${BASE}/register`);
    // Without this a client has only the deprecated /register path to fall back to.
    expect(metadata.client_id_metadata_document_supported).toBe(true);
    expect(metadata.scopes_supported).toEqual(['docx:document', 'im:message:readonly']);
  });

  // RFC 8414 s3.3: identical to the issuer identifier the well-known path was
  // inserted into. The SDK publishes URL.href, which appends a slash to a bare
  // origin and fails that comparison for a client that makes it.
  it('publishes an issuer with no trailing slash', async () => {
    expect((await read('/.well-known/oauth-authorization-server')).issuer).toBe(BASE);
  });

  // ChatGPT's Client ID Metadata Document declares private_key_jwt. A client
  // that reads this list before it authorizes has no reason to start a flow it
  // cannot finish.
  it('advertises the assertion method a CIMD client authenticates with', async () => {
    const metadata = await read('/.well-known/oauth-authorization-server');
    expect(metadata.token_endpoint_auth_methods_supported).toContain('private_key_jwt');
    expect(metadata.token_endpoint_auth_signing_alg_values_supported).toEqual(['RS256']);
  });

  // The branch that matters: declaring private_key_jwt must not become a way of
  // asking to skip client authentication.
  it('refuses a token request from a private_key_jwt client that sent no assertion', async () => {
    const clientId = 'https://chatgpt.com/oauth/client.json';
    // Only the server's own outbound fetch is mocked. Driving the endpoint uses
    // the real one, so a mock that swallowed both would pass without ever
    // reaching express.
    const realFetch = global.fetch;
    global.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.startsWith(origin)) {
        return realFetch(input, init);
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          client_id: clientId,
          client_name: 'ChatGPT',
          redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
          token_endpoint_auth_method: 'private_key_jwt',
          jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
        }),
      } as unknown as Response;
    }) as typeof fetch;

    try {
      const res = await fetch(`${origin}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'authorization_code', client_id: clientId, code: 'x' }),
      });

      expect(res.status).toBe(401);
      expect((await res.json()).error).toBe('invalid_client');
    } finally {
      global.fetch = realFetch;
    }
  });

  it('names /mcp as the protected resource, at both well-known paths', async () => {
    const expected = {
      resource: `${BASE}/mcp`,
      authorization_servers: [BASE],
      scopes_supported: ['docx:document', 'im:message:readonly'],
    };

    // Path-inserted (RFC 9728 s3.1) is what a current client tries first; the
    // bare path is what already-connected clients use. The bare path is a prefix
    // of the other, so mounting order decides whether both actually answer.
    expect(await read('/.well-known/oauth-protected-resource/mcp')).toMatchObject(expected);
    expect(await read('/.well-known/oauth-protected-resource')).toMatchObject(expected);
  });
});
