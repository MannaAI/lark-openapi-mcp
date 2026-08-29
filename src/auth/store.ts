import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import fs from 'fs';
import { storageManager } from './utils/storage-manager';
import { advertisedScopes } from './config';
import { StorageData } from './types';
import { logger } from '../utils/logger';

export class AuthStore implements OAuthRegisteredClientsStore {
  private storageDataCache: StorageData = { tokens: {}, clients: {} };
  private codeVerifiers: Map<string, string> = new Map();
  private initializePromise: Promise<void> | undefined;
  private fileWatcher: fs.FSWatcher | undefined;
  private isReloading = false;

  private isInitializedStorageSuccess = false;

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    if (this.initializePromise) {
      return this.initializePromise;
    }

    this.initializePromise = this.performInitialization();

    await this.initializePromise;
  }

  private async performInitialization(): Promise<void> {
    try {
      await this.loadFromStorage();
      logger.info(
        `[AuthStore] Initialized storage successfully with ${Object.keys(this.storageDataCache.tokens).length} tokens`,
      );
      await this.clearExpiredTokens();
      this.setupFileWatcher();
      this.isInitializedStorageSuccess = true;
    } catch (error) {
      logger.error(`[AuthStore] Failed to initialize: ${error}`);
      this.isInitializedStorageSuccess = false;
    }
  }

  private setupFileWatcher(): void {
    try {
      if (fs.existsSync(storageManager.storageFile)) {
        logger.info(`[AuthStore] Setup file watcher for ${storageManager.storageFile}`);
        this.fileWatcher = fs.watch(storageManager.storageFile, () => {
          this.handleFileChange();
        });
      }
    } catch (error) {
      logger.error(`[AuthStore] Failed to setup file watcher: ${error}`);
    }
  }

  private async handleFileChange(): Promise<void> {
    if (this.isReloading) {
      return;
    }

    this.isReloading = true;
    try {
      logger.info(`[AuthStore] Reloading storage from ${storageManager.storageFile}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
      await this.loadFromStorage();
    } catch (error) {
      logger.error(`[AuthStore] Failed to reload storage: ${error}`);
    } finally {
      this.isReloading = false;
    }
  }

  private async loadFromStorage(): Promise<void> {
    const storageData = await storageManager.loadStorageData();
    this.storageDataCache = storageData;
  }

  private async saveToStorage(): Promise<void> {
    if (!this.isInitializedStorageSuccess) {
      return;
    }
    await storageManager.saveStorageData(this.storageDataCache);
  }

  private async clearExpiredTokens(): Promise<void> {
    if (!this.storageDataCache || !this.storageDataCache.tokens) {
      return;
    }
    const now = Date.now() / 1000;
    let hasExpiredTokens = false;

    const expiredTokenKeys: string[] = [];
    for (const [tokenKey, token] of Object.entries(this.storageDataCache.tokens)) {
      // 7 days after expires clear the token
      if (token.expiresAt && token.expiresAt + 7 * 24 * 60 * 60 < now) {
        expiredTokenKeys.push(tokenKey);
      }
    }

    if (expiredTokenKeys.length > 0) {
      for (const tokenKey of expiredTokenKeys) {
        delete this.storageDataCache.tokens[tokenKey];
      }
      hasExpiredTokens = true;
    }

    if (this.storageDataCache.localTokens) {
      const orphanedLocalTokenKeys: string[] = [];
      for (const [appId, tokenKey] of Object.entries(this.storageDataCache.localTokens)) {
        if (!this.storageDataCache.tokens[tokenKey]) {
          orphanedLocalTokenKeys.push(appId);
        }
      }

      if (orphanedLocalTokenKeys.length > 0) {
        for (const appId of orphanedLocalTokenKeys) {
          delete this.storageDataCache.localTokens[appId];
        }
        hasExpiredTokens = true;
      }
    }

    if (hasExpiredTokens) {
      logger.info(`[AuthStore] Cleared expired tokens`);
      await this.saveToStorage();
    }
  }

  async storeToken(token: AuthInfo): Promise<AuthInfo> {
    await this.initialize();
    this.storageDataCache.tokens[token.token] = token;
    await this.saveToStorage();
    return token;
  }

  async removeToken(accessToken: string): Promise<void> {
    await this.initialize();
    delete this.storageDataCache.tokens[accessToken];
    await this.saveToStorage();
  }

  async getToken(accessToken: string): Promise<AuthInfo | undefined> {
    await this.initialize();
    return this.storageDataCache.tokens[accessToken];
  }

  async getTokenByRefreshToken(refreshToken: string): Promise<AuthInfo | undefined> {
    await this.initialize();
    return Object.values(this.storageDataCache.tokens).find((token) => token.extra?.refreshToken === refreshToken);
  }

  async getLocalAccessToken(appId: string): Promise<string | undefined> {
    await this.initialize();

    return this.storageDataCache.localTokens?.[appId];
  }

  async storeLocalAccessToken(accessToken: string, appId: string): Promise<string> {
    await this.initialize();

    if (!this.storageDataCache.localTokens) {
      this.storageDataCache.localTokens = {};
    }
    this.storageDataCache.localTokens[appId] = accessToken;

    await this.saveToStorage();
    return accessToken;
  }

  async removeLocalAccessToken(appId: string): Promise<void> {
    await this.initialize();
    if (this.storageDataCache.localTokens?.[appId]) {
      logger.info(`[AuthStore] Removing local access token for app: ${appId}`);
      const tokenToRemove = this.storageDataCache.localTokens[appId];
      delete this.storageDataCache.tokens[tokenToRemove];
      delete this.storageDataCache.localTokens[appId];
      await this.saveToStorage();
    }
  }

  async removeAllLocalAccessTokens(): Promise<void> {
    await this.initialize();
    logger.info('[AuthStore] Removing all local access tokens');
    if (this.storageDataCache.localTokens) {
      const tokens = Object.values(this.storageDataCache.localTokens);
      for (const token of tokens) {
        if (this.storageDataCache.tokens[token]) {
          delete this.storageDataCache.tokens[token];
        }
      }
    }
    this.storageDataCache.localTokens = {};
    await this.saveToStorage();
  }

  async getAllLocalAccessTokens(): Promise<{ [appId: string]: string }> {
    await this.initialize();
    return this.storageDataCache.localTokens || {};
  }

  // /authorize rejects any scope the client was not registered with, and
  // dynamic registration does not require a client to send one. Without this a
  // client that registers bare and then asks for a scope is bounced with
  // invalid_scope -- back to its own redirect_uri, so the user never reaches
  // Lark and the failure is invisible from here.
  //
  // Applied on read as well as on write: a client that registered before any
  // scope was configured is stored bare forever, and it never re-registers, so
  // backfilling only at registration leaves it permanently unable to ask for a
  // scope -- its consent screen and token carry whatever Lark defaults to
  // rather than what this server advertises.
  private withDefaultScope(client: OAuthClientInformationFull): OAuthClientInformationFull {
    const scopes = advertisedScopes();
    if (client.scope || !scopes?.length) {
      return client;
    }
    return { ...client, scope: scopes.join(' ') };
  }

  async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
    await this.initialize();
    const stored = this.withDefaultScope(client);
    this.storageDataCache.clients[stored.client_id] = stored;
    await this.saveToStorage();
    return stored;
  }

  async getClient(id: string): Promise<OAuthClientInformationFull | undefined> {
    await this.initialize();
    const client = this.storageDataCache.clients[id];
    return client && this.withDefaultScope(client);
  }

  async removeClient(clientId: string): Promise<void> {
    await this.initialize();
    delete this.storageDataCache.clients[clientId];
    await this.saveToStorage();
  }

  storeCodeVerifier(key: string, codeVerifier: string): void {
    this.codeVerifiers.set(key, codeVerifier);
  }

  getCodeVerifier(key: string): string | undefined {
    return this.codeVerifiers.get(key);
  }

  removeCodeVerifier(key: string): void {
    this.codeVerifiers.delete(key);
  }

  clearExpiredCodeVerifiers(): void {
    this.codeVerifiers.clear();
  }

  destroy(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
      this.fileWatcher = undefined;
    }
  }
}

export const authStore = new AuthStore();
