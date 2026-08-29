// Which authorization flow minted a stored token. Recorded because the two
// flows produce tokens Lark treats differently -- an OIDC-minted one answers
// 99991695 on message bodies -- and the store outlives a change of flow, so a
// token has to say where it came from rather than be assumed current.
export const OAUTH2_FLOW = 'oauth2';
export const OIDC_FLOW = 'oidc';

export interface LarkProxyOAuthServerProviderOptions {
  domain: string;
  host: string;
  port: number;
  appId: string;
  appSecret: string;
  callbackUrl: string;
}
