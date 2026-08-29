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

// Space- or comma-separated Lark scopes, e.g. "docx:document drive:drive".
// Advertised as scopes_supported, and used as the default scope for a client
// that registers without one. Unset means today's behaviour: nothing advertised
// and no scope recorded, which is fine as long as no client ever asks for one.
export const advertisedScopes = (): string[] | undefined => {
  const raw = process.env.LARK_OAUTH_SCOPES?.trim();
  const scopes = raw ? raw.split(/[\s,]+/).filter(Boolean) : [];
  return scopes.length ? scopes : undefined;
};
