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

// The registration response is the last thing a client sees before it decides
// whether to open the authorize URL, and a client that dislikes it just stops --
// no error, no retry. Asserting on the middleware's mutation of req.body says
// nothing about what actually goes back over the wire, so run the real router:
// mount it, POST to it, read the 201.
describe('POST /register', () => {
  const BASE = 'https://mcp.example.com';
  let server: Server;
  let url: string;

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
      url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/register`;
      done();
    });
  });

  afterAll((done) => {
    delete process.env.PUBLIC_BASE_URL;
    delete process.env.LARK_OAUTH_SCOPES;
    server.close(() => done());
  });

  const register = async (body: Record<string, unknown>) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  };

  // Omitting the field makes the SDK's handler mint a client_secret, which the
  // token endpoint cannot verify and the metadata does not advertise.
  it('hands an omitted auth method back a usable public client', async () => {
    const { status, body } = await register({
      client_name: 'omits the method',
      redirect_uris: ['https://client.example.com/callback'],
    });

    expect(status).toBe(201);
    expect(body.token_endpoint_auth_method).toBe('none');
    expect(body.client_id).toEqual(expect.any(String));
  });

  it('hands an unsupported auth method back a usable public client', async () => {
    const { status, body } = await register({
      client_name: 'asks for basic',
      redirect_uris: ['https://client.example.com/callback'],
      token_endpoint_auth_method: 'client_secret_basic',
    });

    expect(status).toBe(201);
    expect(body.token_endpoint_auth_method).toBe('none');
  });

  // What ChatGPT actually sends, verbatim from the deployed server's logs.
  it('leaves a client that already asks to be public alone', async () => {
    const { status, body } = await register({
      client_name: 'ChatGPT',
      redirect_uris: ['https://chatgpt.com/connector/oauth/abc123'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'none',
    });

    expect(status).toBe(201);
    expect(body.token_endpoint_auth_method).toBe('none');
    expect(body.redirect_uris).toEqual(['https://chatgpt.com/connector/oauth/abc123']);
    // It asks for 'none' and then discards a registration that honours it.
    expect(body.client_secret).toEqual(expect.any(String));
    expect(body.client_secret_expires_at).toBe(0);
    // A client that asked for no scope has nothing to put on the authorize URL,
    // so the store fills in what the metadata advertises.
    expect(body.scope).toBe('docx:document im:message:readonly');
  });
});
