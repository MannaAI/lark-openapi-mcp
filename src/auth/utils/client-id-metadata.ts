import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { logger } from '../../utils/logger';

// Hosts whose Client ID Metadata Documents this server will fetch. Resolving a
// client_id means making a request to a URL a stranger chose, so the set stays
// closed: an open resolver here is an SSRF hole pointed at whatever the
// container can reach. Override with LARK_CIMD_ALLOWED_HOSTS when another client
// needs to connect.
const DEFAULT_ALLOWED_HOSTS = ['chatgpt.com'];

const allowedHosts = (): string[] => {
  const configured = process.env.LARK_CIMD_ALLOWED_HOSTS?.trim();
  return configured ? configured.split(/[\s,]+/).filter(Boolean) : DEFAULT_ALLOWED_HOSTS;
};

// ponytail: fixed TTL rather than honouring Cache-Control, which the spec only
// asks for with a SHOULD. Revisit if a client starts rotating its document.
const CACHE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5000;

const cache = new Map<string, { client: OAuthClientInformationFull; fetchedAt: number }>();

/** A client_id is a metadata document URL when it is https and has a path (CIMD s2). */
export const isClientIdMetadataUrl = (clientId: string): boolean => {
  try {
    const url = new URL(clientId);
    return url.protocol === 'https:' && url.pathname.length > 1;
  } catch {
    return false;
  }
};

const isAllowedHost = (clientId: string): boolean => {
  const { hostname } = new URL(clientId);
  return allowedHosts().some((host) => hostname === host || hostname.endsWith(`.${host}`));
};

// The document is the client's own description of itself, so nothing in it is
// trusted until it has been checked against the URL it came from.
const validate = (clientId: string, document: unknown): OAuthClientInformationFull | undefined => {
  const metadata = document as Record<string, unknown> | null;
  if (!metadata || typeof metadata !== 'object') {
    logger.error(`[CIMD] ${clientId}: document is not a JSON object`);
    return undefined;
  }
  // Without this a document hosted anywhere could claim any client_id, which is
  // the whole basis for treating the URL as an identity.
  if (metadata.client_id !== clientId) {
    logger.error(`[CIMD] ${clientId}: document declares client_id ${JSON.stringify(metadata.client_id)}`);
    return undefined;
  }
  const redirectUris = metadata.redirect_uris;
  if (!Array.isArray(redirectUris) || !redirectUris.length || !redirectUris.every((u) => typeof u === 'string')) {
    logger.error(`[CIMD] ${clientId}: missing or malformed redirect_uris`);
    return undefined;
  }
  if (typeof metadata.client_name !== 'string') {
    logger.error(`[CIMD] ${clientId}: missing client_name`);
    return undefined;
  }

  return {
    ...(metadata as unknown as OAuthClientInformationFull),
    client_id: clientId,
    // A document may prefer private_key_jwt -- ChatGPT's does -- but this server
    // only verifies credentials out of the request body, so the usable
    // intersection is the public-client method. No secret is stored, so the SDK's
    // token endpoint skips client authentication and PKCE carries the flow.
    token_endpoint_auth_method: 'none',
    client_secret: undefined,
  };
};

/**
 * Resolve an HTTPS client_id to its Client ID Metadata Document (MCP 2026-07-28,
 * draft-ietf-oauth-client-id-metadata-document-00). Returns undefined for
 * anything that fails to fetch or validate, which the caller reports as an
 * unknown client.
 */
export const resolveClientIdMetadata = async (clientId: string): Promise<OAuthClientInformationFull | undefined> => {
  if (!isClientIdMetadataUrl(clientId) || !isAllowedHost(clientId)) {
    return undefined;
  }

  const cached = cache.get(clientId);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.client;
  }

  try {
    const response = await fetch(clientId, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!response.ok) {
      logger.error(`[CIMD] ${clientId}: HTTP ${response.status}`);
      return undefined;
    }
    const client = validate(clientId, await response.json());
    if (client) {
      logger.info(`[CIMD] ${clientId}: resolved as ${client.client_name}`);
      cache.set(clientId, { client, fetchedAt: Date.now() });
    }
    return client;
  } catch (error) {
    logger.error(`[CIMD] ${clientId}: ${error}`);
    return undefined;
  }
};

export const clearClientIdMetadataCache = () => cache.clear();
