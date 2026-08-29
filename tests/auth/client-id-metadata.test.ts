import {
  isClientIdMetadataUrl,
  resolveClientIdMetadata,
  clearClientIdMetadataCache,
} from '../../src/auth/utils/client-id-metadata';

const CHATGPT = 'https://chatgpt.com/oauth/client.json';

// The live document, as served by chatgpt.com.
const chatgptDocument = {
  client_id: CHATGPT,
  client_uri: 'https://chatgpt.com/',
  redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
  token_endpoint_auth_method: 'private_key_jwt',
  token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
  token_endpoint_auth_signing_alg: 'RS256',
  jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'ChatGPT',
};

const mockFetch = (body: unknown, ok = true, status = 200) => {
  const fetchMock = jest.fn().mockResolvedValue({ ok, status, json: async () => body });
  global.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
};

describe('Client ID Metadata Documents', () => {
  beforeEach(() => clearClientIdMetadataCache());

  describe('isClientIdMetadataUrl', () => {
    it('accepts an https URL with a path', () => {
      expect(isClientIdMetadataUrl(CHATGPT)).toBe(true);
    });

    it('rejects anything else', () => {
      // A registered client's id is a UUID, and must not be treated as a URL.
      expect(isClientIdMetadataUrl('22a16013-1c69-40be-9702-8530ac1916c5')).toBe(false);
      expect(isClientIdMetadataUrl('http://chatgpt.com/oauth/client.json')).toBe(false);
      expect(isClientIdMetadataUrl('https://chatgpt.com')).toBe(false);
      expect(isClientIdMetadataUrl('https://chatgpt.com/')).toBe(false);
    });
  });

  describe('resolveClientIdMetadata', () => {
    it("resolves a document and keeps the method it declares", async () => {
      mockFetch(chatgptDocument);
      const client = await resolveClientIdMetadata(CHATGPT);

      expect(client?.client_id).toBe(CHATGPT);
      expect(client?.redirect_uris).toEqual(['https://chatgpt.com/connector_platform_oauth_redirect']);
      // Rewriting this to 'none' is what left the token endpoint unable to
      // authenticate ChatGPT at all.
      expect(client?.token_endpoint_auth_method).toBe('private_key_jwt');
      expect(client?.client_secret).toBeUndefined();
    });

    // CIMD s2: there is no registration step in which a shared secret could have
    // been agreed, so a document naming one is not describing a usable client.
    it('rejects a document naming a shared-secret method', async () => {
      mockFetch({ ...chatgptDocument, token_endpoint_auth_method: 'client_secret_post' });
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();
    });

    it('rejects private_key_jwt with no key to check it against', async () => {
      const { jwks_uri, ...noKeys } = chatgptDocument;
      mockFetch(noKeys);
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();
    });

    it('caches, so an authorize and a token request cost one fetch', async () => {
      const fetchMock = mockFetch(chatgptDocument);
      await resolveClientIdMetadata(CHATGPT);
      await resolveClientIdMetadata(CHATGPT);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    // Resolving a client_id fetches a URL a stranger chose, so anything off the
    // allowlist must not be requested at all.
    it('never fetches a host outside the allowlist', async () => {
      const fetchMock = mockFetch(chatgptDocument);
      expect(await resolveClientIdMetadata('https://evil.example.com/client.json')).toBeUndefined();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('honours LARK_CIMD_ALLOWED_HOSTS', async () => {
      process.env.LARK_CIMD_ALLOWED_HOSTS = 'client.example.com';
      const document = { ...chatgptDocument, client_id: 'https://client.example.com/c.json' };
      mockFetch(document);
      expect((await resolveClientIdMetadata('https://client.example.com/c.json'))?.client_name).toBe('ChatGPT');
      delete process.env.LARK_CIMD_ALLOWED_HOSTS;
    });

    // Without this check a document hosted anywhere could claim any client_id,
    // which is the whole basis for treating the URL as an identity.
    it('rejects a document whose client_id does not match its URL', async () => {
      mockFetch({ ...chatgptDocument, client_id: 'https://chatgpt.com/oauth/other.json' });
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();
    });

    it('rejects a document missing the required fields', async () => {
      mockFetch({ client_id: CHATGPT, client_name: 'ChatGPT' });
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();

      mockFetch({ client_id: CHATGPT, redirect_uris: ['https://chatgpt.com/cb'] });
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();

      mockFetch({ ...chatgptDocument, redirect_uris: [] });
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();
    });

    it('reports an unreachable or non-JSON document as an unknown client', async () => {
      mockFetch(undefined, false, 404);
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();

      global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as unknown as typeof fetch;
      expect(await resolveClientIdMetadata(CHATGPT)).toBeUndefined();
    });
  });
});
