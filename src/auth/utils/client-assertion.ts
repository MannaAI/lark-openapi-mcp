import { createPublicKey, verify as verifySignature, JsonWebKey } from 'crypto';
import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { isAllowedCimdHost } from './client-id-metadata';
import { logger } from '../../utils/logger';

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// The only algorithm ChatGPT's document names, and the only one worth accepting
// until something else asks for one: a permissive `alg` list is how JWT
// verification usually goes wrong.
const SUPPORTED_ALG = 'RS256';

const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5000;

// An assertion is single-use (RFC 7523 s3). Keeping the jti until its own expiry
// passes is enough: an assertion that has expired cannot be replayed anyway.
// ponytail: in-process map, so it only covers one replica. railway.toml already
// pins numReplicas = 1 for the token store; a shared store would have to cover
// both.
const seenJtis = new Map<string, number>();

const jwksCache = new Map<string, { keys: JsonWebKey[]; fetchedAt: number }>();

export const clearClientAssertionCaches = () => {
  jwksCache.clear();
  seenJtis.clear();
};

const base64UrlDecode = (segment: string): Buffer => Buffer.from(segment, 'base64url');

/**
 * The `sub` an assertion claims, before anything about it has been verified.
 * RFC 7523 s3 lets a client omit client_id from the request body and be
 * identified by the assertion alone, so this is how the client to check against
 * is found. Nothing here is trusted: it only selects which published keys the
 * signature is then verified against.
 */
export const readAssertionSubject = (assertion: string): string | undefined => {
  try {
    const payload = JSON.parse(base64UrlDecode(assertion.split('.')[1]).toString());
    return typeof payload?.sub === 'string' ? payload.sub : undefined;
  } catch {
    return undefined;
  }
};

const fetchJwks = async (jwksUri: string): Promise<JsonWebKey[] | undefined> => {
  const cached = jwksCache.get(jwksUri);
  if (cached && Date.now() - cached.fetchedAt < JWKS_CACHE_TTL_MS) {
    return cached.keys;
  }

  try {
    const response = await fetch(jwksUri, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!response.ok) {
      logger.error(`[ClientAssertion] ${jwksUri}: HTTP ${response.status}`);
      return undefined;
    }
    const body = (await response.json()) as { keys?: JsonWebKey[] };
    if (!Array.isArray(body?.keys)) {
      logger.error(`[ClientAssertion] ${jwksUri}: no keys array`);
      return undefined;
    }
    jwksCache.set(jwksUri, { keys: body.keys, fetchedAt: Date.now() });
    return body.keys;
  } catch (error) {
    logger.error(`[ClientAssertion] ${jwksUri}: ${error}`);
    return undefined;
  }
};

/**
 * Verify a private_key_jwt client assertion against the keys published by a CIMD
 * client (RFC 7523 s2.2, as required by the Client ID Metadata Document draft
 * whenever a document declares private_key_jwt).
 *
 * `audiences` is every value this server will accept in `aud`. Implementations
 * disagree on whether it is the token endpoint or the issuer, and getting it
 * wrong is silent, so both are accepted rather than guessed at.
 *
 * Returns an error string, or undefined when the assertion is good.
 */
export const verifyClientAssertion = async (
  client: OAuthClientInformationFull,
  assertion: string,
  audiences: string[],
): Promise<string | undefined> => {
  const jwksUri = (client as { jwks_uri?: string }).jwks_uri;
  if (!jwksUri) {
    return 'client has no jwks_uri';
  }
  // The URI comes out of a document a stranger controls, so it is fetched only
  // if it points somewhere the client_id was already allowed to point.
  if (!isAllowedCimdHost(jwksUri)) {
    return `jwks_uri host is not allowed: ${jwksUri}`;
  }

  const parts = assertion.split('.');
  if (parts.length !== 3) {
    return 'assertion is not a compact JWS';
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts;

  let header: { alg?: string; kid?: string };
  let payload: { iss?: string; sub?: string; aud?: string | string[]; exp?: number; nbf?: number; jti?: string };
  try {
    header = JSON.parse(base64UrlDecode(headerSegment).toString());
    payload = JSON.parse(base64UrlDecode(payloadSegment).toString());
  } catch {
    return 'assertion header or payload is not JSON';
  }

  if (header.alg !== SUPPORTED_ALG) {
    return `unsupported alg ${header.alg}`;
  }
  // RFC 7523 s3: the client authenticating itself is both the issuer and the
  // subject. Without this a valid assertion for one client would authenticate
  // another.
  if (payload.iss !== client.client_id || payload.sub !== client.client_id) {
    return `iss/sub do not match client_id`;
  }

  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.some((value) => typeof value === 'string' && audiences.includes(value))) {
    return `aud ${JSON.stringify(payload.aud)} is not this token endpoint`;
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= now) {
    return 'assertion has expired';
  }
  // A far-future exp would pin a jti in memory for as long as it claims, so cap
  // how long an assertion is allowed to stay live.
  if (payload.exp - now > 3600) {
    return 'assertion expires too far in the future';
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now + 60) {
    return 'assertion is not yet valid';
  }

  const keys = await fetchJwks(jwksUri);
  if (!keys?.length) {
    return 'no keys at jwks_uri';
  }
  // kid is a hint, not a guarantee -- a document may publish one key and sign
  // without naming it -- so fall back to trying every signing key.
  const candidates = header.kid ? keys.filter((key) => (key as { kid?: string }).kid === header.kid) : [];
  const toTry = candidates.length ? candidates : keys;

  const signingInput = Buffer.from(`${headerSegment}.${payloadSegment}`);
  const signature = base64UrlDecode(signatureSegment);
  const verified = toTry.some((jwk) => {
    try {
      return verifySignature('RSA-SHA256', signingInput, createPublicKey({ key: jwk, format: 'jwk' }), signature);
    } catch {
      return false;
    }
  });
  if (!verified) {
    return 'signature does not verify against any published key';
  }

  if (payload.jti) {
    for (const [jti, expiresAt] of seenJtis) {
      if (expiresAt <= now) {
        seenJtis.delete(jti);
      }
    }
    if (seenJtis.has(payload.jti)) {
      return 'assertion has already been used';
    }
    seenJtis.set(payload.jti, payload.exp);
  }

  return undefined;
};
