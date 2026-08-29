import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as signBuffer } from 'crypto';
import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  CLIENT_ASSERTION_TYPE,
  clearClientAssertionCaches,
  readAssertionSubject,
  verifyClientAssertion,
} from '../../src/auth/utils/client-assertion';

const CLIENT_ID = 'https://chatgpt.com/oauth/client.json';
const JWKS_URI = 'https://chatgpt.com/oauth/jwks.json';
const TOKEN_ENDPOINT = 'https://mcp.example.com/token';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };

const client = {
  client_id: CLIENT_ID,
  client_name: 'ChatGPT',
  redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
  token_endpoint_auth_method: 'private_key_jwt',
  jwks_uri: JWKS_URI,
} as unknown as OAuthClientInformationFull;

const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');

// A real compact JWS, signed with the key the mocked JWKS publishes. Nothing is
// asserted about a signature the verifier itself produced -- the point is to
// exercise the same path a client's assertion takes.
const makeAssertion = (
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
  key = privateKey,
): string => {
  const now = Math.floor(Date.now() / 1000);
  const head = b64({ alg: 'RS256', kid: 'test-key', typ: 'JWT', ...header });
  const payload = b64({
    iss: CLIENT_ID,
    sub: CLIENT_ID,
    aud: TOKEN_ENDPOINT,
    exp: now + 300,
    iat: now,
    jti: `jti-${Math.random()}`,
    ...claims,
  });
  const signature = signBuffer('RSA-SHA256', Buffer.from(`${head}.${payload}`), key).toString('base64url');
  return `${head}.${payload}.${signature}`;
};

const mockJwks = (keys: unknown[] = [jwk]) => {
  global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ keys }) }) as never;
};

const verify = (assertion: string) => verifyClientAssertion(client, assertion, [TOKEN_ENDPOINT]);

describe('private_key_jwt client assertions', () => {
  beforeEach(() => {
    clearClientAssertionCaches();
    mockJwks();
  });

  it('is the type ChatGPT sends', () => {
    expect(CLIENT_ASSERTION_TYPE).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  });

  it('accepts an assertion signed by a published key', async () => {
    expect(await verify(makeAssertion())).toBeUndefined();
  });

  it('accepts an aud array containing the token endpoint', async () => {
    expect(await verify(makeAssertion({ aud: ['https://elsewhere.example', TOKEN_ENDPOINT] }))).toBeUndefined();
  });

  // The kid is a hint. A document that publishes one key and signs without
  // naming it is still authenticating itself.
  it('falls back to every published key when the kid does not match', async () => {
    expect(await verify(makeAssertion({}, { kid: 'rotated-away' }))).toBeUndefined();
  });

  it('rejects a signature from a key the client does not publish', async () => {
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    expect(await verify(makeAssertion({}, {}, other))).toMatch(/signature does not verify/);
  });

  it('rejects a tampered payload', async () => {
    const [head, , signature] = makeAssertion().split('.');
    const forged = b64({ iss: CLIENT_ID, sub: CLIENT_ID, aud: TOKEN_ENDPOINT, exp: Math.floor(Date.now() / 1000) + 300 });
    expect(await verify(`${head}.${forged}.${signature}`)).toMatch(/signature does not verify/);
  });

  // Without this an assertion minted for one client would authenticate another.
  it('rejects an assertion issued by a different client', async () => {
    const foreign = 'https://chatgpt.com/oauth/other.json';
    expect(await verify(makeAssertion({ iss: foreign, sub: foreign }))).toMatch(/iss\/sub/);
  });

  it('rejects an assertion aimed at another server', async () => {
    expect(await verify(makeAssertion({ aud: 'https://someone-else.example/token' }))).toMatch(/aud/);
  });

  it('rejects an expired assertion', async () => {
    expect(await verify(makeAssertion({ exp: Math.floor(Date.now() / 1000) - 1 }))).toMatch(/expired/);
  });

  it('rejects an assertion that would pin a jti in memory for a year', async () => {
    expect(await verify(makeAssertion({ exp: Math.floor(Date.now() / 1000) + 31536000 }))).toMatch(/too far/);
  });

  it('rejects an algorithm other than RS256', async () => {
    expect(await verify(makeAssertion({}, { alg: 'none' }))).toMatch(/unsupported alg/);
  });

  it('rejects a replay of the same jti', async () => {
    const assertion = makeAssertion({ jti: 'replayed' });
    expect(await verify(assertion)).toBeUndefined();
    expect(await verify(assertion)).toMatch(/already been used/);
  });

  // The jwks_uri comes out of a document a stranger controls, so it is an SSRF
  // target unless it is held to the same allowlist as the document itself.
  it('never fetches a jwks_uri outside the allowlist', async () => {
    const offHost = { ...client, jwks_uri: 'https://evil.example.com/jwks.json' } as OAuthClientInformationFull;
    expect(await verifyClientAssertion(offHost, makeAssertion(), [TOKEN_ENDPOINT])).toMatch(/not allowed/);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('reports a client with no published keys rather than admitting it', async () => {
    mockJwks([]);
    expect(await verify(makeAssertion())).toMatch(/no keys/);
  });

  it('reads the subject of an unverified assertion, and survives rubbish', () => {
    expect(readAssertionSubject(makeAssertion())).toBe(CLIENT_ID);
    expect(readAssertionSubject('not-a-jwt')).toBeUndefined();
  });
});

// The shape ChatGPT actually publishes, so a change in how keys are imported
// fails here rather than in production.
describe("ChatGPT's published JWKS shape", () => {
  const live = {
    kty: 'RSA',
    kid: 'cimd-20260428030119',
    use: 'sig',
    alg: 'RS256',
    n: 'y09nMyYX6LhSgS3YmbLOZrFoR8SffxG0kM5gQ5PKpHVMzbAu__-7rf0_Q_pwhVa9vxJzv3cRkGnXKNWKOHDdEXp8YFPVUql4NcDjDdS_0w0uos8gazoa7Td47qVquxOsG3861l8oKEh-E4r5C_6w6Sx0Rl2WEEs2-dmvn3fwH9PkLCQOo4tsNAEnrW_ge2vQE-pFo-kJp5QRRiX2w0YvaMFtIfEvNbdPSJ3xd7NbGrvRt279HrxgDLGUvpbeWrCsp3D7HdR2QZn-9MZp7CHPlMGtFgN9aIB4Guf7qYlRiC3Ja0ZI22jSMct6xrI-90XX4AK2FhiWmYOmjV_2d3vEVw',
    e: 'AQAB',
  };

  it('imports as a public key', () => {
    expect(createPublicKey({ key: live, format: 'jwk' }).asymmetricKeyType).toBe('rsa');
  });

  it('rejects an assertion signed by anything but the matching private key', async () => {
    clearClientAssertionCaches();
    mockJwks([live]);
    expect(await verify(makeAssertion())).toMatch(/signature does not verify/);
  });
});

// Guards the assumption the whole file rests on: Node can verify RS256 straight
// from a JWK, so no JWT dependency is needed.
it('verifies RS256 from a JWK with nothing but node crypto', () => {
  const message = Buffer.from('signed');
  const signature = signBuffer('RSA-SHA256', message, createPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' })));
  expect(signature.length).toBeGreaterThan(0);
});
