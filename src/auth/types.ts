import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

export interface StorageData {
  localTokens?: { [appId: string]: string }; // encrypted local tokens by appId
  // A stable name for a rotating token. The Lark access_token behind a handle is
  // replaced every couple of hours by the refresh flow; the handle is not, which
  // is what lets a connector URL keep working after the first refresh.
  handles?: { [handle: string]: string };
  tokens: { [key: string]: AuthInfo }; // encrypted tokens
  clients: { [key: string]: OAuthClientInformationFull }; // encrypted clients
}
