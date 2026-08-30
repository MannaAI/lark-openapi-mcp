import { ENV_PATHS } from '../utils/constants';

export const AUTH_CONFIG = {
  SERVER_NAME: 'lark-mcp',
  AES_KEY_NAME: 'encryption-key',
  STORAGE_DIR: ENV_PATHS.data,
  STORAGE_FILE: 'storage.json',
  ENCRYPTION: {
    ALGORITHM: 'aes-256-cbc' as const,
    KEY_LENGTH: 32, // 256 bits
    IV_LENGTH: 16, // 128 bits
  },
} as const;

export type AuthConfig = typeof AUTH_CONFIG;

// Lark hands back a refresh_token only when the authorization asked for this,
// and without one a user_access_token simply dies two hours in with nothing to
// renew it from. That is not a degraded mode, it is a connector that works once:
// the token expires, the refresh branch is skipped for want of a refresh token,
// and the person is sent to a re-authorization link. Every upstream example
// leads with this scope for the same reason.
const REFRESH_SCOPE = 'offline_access';

// Space- or comma-separated Lark scopes, e.g. "docx:document drive:drive".
// Advertised as scopes_supported, used as the default scope for a client that
// registers without one, and sent with the /my-token handout's authorization.
// Unset means today's behaviour: nothing advertised and no scope recorded, which
// is fine as long as no client ever asks for one -- and is left alone here,
// because narrowing "everything the app is granted" down to a lone
// offline_access would be strictly worse than the gap it closes.
// Keep offline_access in a scope list that is being sent to Lark, so a token
// renewed from a refresh token comes back with a refresh token of its own.
// Nothing in, nothing out: an empty list means "everything the app is granted",
// and narrowing that to a lone offline_access would be worse than the gap it
// closes.
export const withRefreshScope = (scopes?: string[]): string[] | undefined => {
  if (!scopes?.length) {
    return undefined;
  }
  return scopes.includes(REFRESH_SCOPE) ? scopes : [REFRESH_SCOPE, ...scopes];
};

// Added rather than required of the operator: leaving it to LARK_OAUTH_SCOPES
// means one edit to that variable -- narrowing the tools on offer, say -- takes
// the refresh token out with it, and the damage does not show up for two hours.
export const advertisedScopes = (): string[] | undefined => {
  const raw = process.env.LARK_OAUTH_SCOPES?.trim();
  return withRefreshScope(raw ? raw.split(/[\s,]+/).filter(Boolean) : []);
};
