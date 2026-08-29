import { Express, Request, Response } from 'express';
import { LarkAuthHandler } from '../../src/auth/handler/handler';

// The discovery documents are the only thing a client sees before it decides
// whether it can authenticate at all, and getting them wrong fails silently --
// the client just never comes back. Mount the real routes and read them back.
describe('OAuth discovery metadata', () => {
  const BASE = 'https://mcp.example.com';
  const mounted: Array<{ path: unknown; handler: unknown }> = [];

  const app = {
    use: (path: unknown, handler?: unknown) => mounted.push({ path, handler }),
    get: () => undefined,
  } as unknown as Express;

  // Each metadata route is an express Router that answers GET '/'.
  const read = (path: string) => {
    const entry = mounted.find((m) => m.path === path);
    expect(entry).toBeDefined();
    let body: any;
    (entry!.handler as any)(
      { method: 'GET', url: '/', headers: {} } as Request,
      { setHeader: () => undefined, status: () => ({ json: (b: any) => (body = b) }) } as unknown as Response,
      () => undefined,
    );
    return body;
  };

  beforeAll(() => {
    process.env.PUBLIC_BASE_URL = BASE;
    process.env.LARK_OAUTH_SCOPES = 'docx:document im:message:readonly';

    new LarkAuthHandler(app, {
      port: 3000,
      host: 'localhost',
      domain: 'https://open.larksuite.com',
      appId: 'cli_test',
      appSecret: 'secret',
    }).setupRoutes();
  });

  afterAll(() => {
    delete process.env.PUBLIC_BASE_URL;
    delete process.env.LARK_OAUTH_SCOPES;
  });

  it('advertises a token endpoint a public client can actually use', () => {
    const metadata = read('/.well-known/oauth-authorization-server');

    // /register issues clients with no client_secret, so omitting 'none' here
    // describes a token endpoint they can never satisfy.
    expect(metadata.token_endpoint_auth_methods_supported).toContain('none');
    expect(metadata.code_challenge_methods_supported).toContain('S256');
    expect(metadata.registration_endpoint).toBe(`${BASE}/register`);
    expect(metadata.scopes_supported).toEqual(['docx:document', 'im:message:readonly']);
  });

  it('names /mcp as the protected resource, at both well-known paths', () => {
    const expected = {
      resource: `${BASE}/mcp`,
      authorization_servers: [`${BASE}/`],
      scopes_supported: ['docx:document', 'im:message:readonly'],
    };

    // Path-inserted (RFC 9728 s3.1) is what a current client tries first; the
    // bare path is what already-connected clients use.
    expect(read('/.well-known/oauth-protected-resource/mcp')).toEqual(expected);
    expect(read('/.well-known/oauth-protected-resource')).toEqual(expected);
  });

  // A client that is handed a client_secret it cannot spend has no way to say so
  // -- it just stops -- so the registration has to come back in a shape the token
  // endpoint will actually accept.
  describe('client registration', () => {
    const register = (body: Record<string, unknown>) => {
      const entry = mounted.find((m) => m.path === '/register');
      expect(entry).toBeDefined();
      const req = { method: 'POST', body } as unknown as Request;
      (entry!.handler as any)(req, {} as Response, () => undefined);
      return req.body as Record<string, unknown>;
    };

    it('registers a client that omits the auth method as public', () => {
      // RFC 7591 defaults the omitted field to client_secret_basic, which the
      // token endpoint cannot verify and the metadata does not advertise.
      expect(register({ client_name: 'omitted' }).token_endpoint_auth_method).toBe('none');
    });

    it('registers a client asking for an unsupported method as public', () => {
      expect(register({ token_endpoint_auth_method: 'client_secret_basic' }).token_endpoint_auth_method).toBe('none');
    });

    it('leaves a supported method alone', () => {
      expect(register({ token_endpoint_auth_method: 'client_secret_post' }).token_endpoint_auth_method).toBe(
        'client_secret_post',
      );
      expect(register({ token_endpoint_auth_method: 'none' }).token_endpoint_auth_method).toBe('none');
    });

    it('only registers methods the metadata advertises', () => {
      const advertised = read('/.well-known/oauth-authorization-server').token_endpoint_auth_methods_supported;
      for (const requested of ['client_secret_basic', 'private_key_jwt', undefined]) {
        expect(advertised).toContain(register({ token_endpoint_auth_method: requested }).token_endpoint_auth_method);
      }
    });
  });

  it('mounts them ahead of mcpAuthRouter, which serves the same paths', () => {
    const wellKnown = mounted.filter((m) => String(m.path).startsWith('/.well-known/'));
    const sdkRouter = mounted.findIndex((m) => typeof m.path === 'function');

    expect(wellKnown).toHaveLength(3);
    expect(sdkRouter).toBe(mounted.length - 1);
    // The bare path is a prefix of the path-inserted one, so it has to come second.
    expect(mounted.indexOf(wellKnown[1])).toBeLessThan(mounted.indexOf(wellKnown[2]));
    expect(String(wellKnown[1].path)).toBe('/.well-known/oauth-protected-resource/mcp');
  });
});
