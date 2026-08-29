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
    expect(metadata.scopes_supported).toEqual(['docx:document', 'im:message:readonly']);
  });

  it('names /mcp as the protected resource, at both well-known paths', async () => {
    const expected = {
      resource: `${BASE}/mcp`,
      authorization_servers: [`${BASE}/`],
      scopes_supported: ['docx:document', 'im:message:readonly'],
    };

    // Path-inserted (RFC 9728 s3.1) is what a current client tries first; the
    // bare path is what already-connected clients use. The bare path is a prefix
    // of the other, so mounting order decides whether both actually answer.
    expect(await read('/.well-known/oauth-protected-resource/mcp')).toMatchObject(expected);
    expect(await read('/.well-known/oauth-protected-resource')).toMatchObject(expected);
  });
});
