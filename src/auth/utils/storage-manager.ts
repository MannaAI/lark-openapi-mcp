import fs from 'fs';
import path from 'path';
import { EncryptionUtil } from './encryption';
import { AUTH_CONFIG } from '../config';
import { StorageData } from '../types';
import { logger } from '../../utils/logger';

export class StorageManager {
  private encryptionUtil: EncryptionUtil | undefined;
  private initializePromise: Promise<void> | undefined;
  private isInitializedStorageSuccess = false;

  constructor() {
    this.initialize();
  }

  get storageFile(): string {
    return path.join(AUTH_CONFIG.STORAGE_DIR, AUTH_CONFIG.STORAGE_FILE);
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
      await this.initializeEncryption();
      this.ensureStorageDir();
      this.isInitializedStorageSuccess = true;
    } catch (error) {
      // Setting LARK_MCP_ENCRYPTION_KEY is a request for persistent token storage,
      // so a downgrade to the memory store there is a deploy misconfiguration, not
      // the ordinary "no keyring on this machine" case.
      const log = process.env.LARK_MCP_ENCRYPTION_KEY ? logger.error : logger.warn;
      log(`[StorageManager] Failed to initialize: ${error}`);
      log(
        '[StorageManager] ⚠️ Builtin User Access Token Store will be disabled. but you can still use it with memory store',
      );
      this.isInitializedStorageSuccess = false;
    }
  }

  private async initializeEncryption(): Promise<void> {
    // A container has no OS keyring. The Docker image used to shim one in with
    // gnome-keyring, but that shim rewrote its keyring on every boot, so the key
    // changed each start and the storage.json written by the previous boot could
    // no longer be decrypted -- every restart silently logged every user out.
    // An explicit key is what makes stored tokens survive a restart or redeploy.
    // keytar remains the default for local CLI use.
    const envKey = process.env.LARK_MCP_ENCRYPTION_KEY;
    if (envKey) {
      if (!/^[0-9a-fA-F]{64}$/.test(envKey)) {
        throw new Error(
          `LARK_MCP_ENCRYPTION_KEY must be ${AUTH_CONFIG.ENCRYPTION.KEY_LENGTH} bytes as hex ` +
            `(${AUTH_CONFIG.ENCRYPTION.KEY_LENGTH * 2} hex characters); got ${envKey.length}`,
        );
      }
      logger.info('[StorageManager] Using encryption key from LARK_MCP_ENCRYPTION_KEY');
      this.encryptionUtil = new EncryptionUtil(envKey);
      return;
    }

    try {
      const keytar = await import('keytar');
      let key = await keytar.getPassword(AUTH_CONFIG.SERVER_NAME, AUTH_CONFIG.AES_KEY_NAME);
      if (!key) {
        key = EncryptionUtil.generateKey();
        await keytar.setPassword(AUTH_CONFIG.SERVER_NAME, AUTH_CONFIG.AES_KEY_NAME, key);
      }
      this.encryptionUtil = new EncryptionUtil(key);
    } catch (error) {
      logger.warn(`[StorageManager] Failed to initialize encryption: ${error}`);
      throw error;
    }
  }

  private ensureStorageDir(): void {
    if (!fs.existsSync(AUTH_CONFIG.STORAGE_DIR)) {
      fs.mkdirSync(AUTH_CONFIG.STORAGE_DIR, { recursive: true });
    }
  }

  encrypt(data: string): string {
    if (!this.isInitializedStorageSuccess || !this.encryptionUtil) {
      throw new Error('StorageManager not initialized - call initialize() first');
    }
    return this.encryptionUtil.encrypt(data);
  }

  decrypt(encryptedData: string): string {
    if (!this.isInitializedStorageSuccess || !this.encryptionUtil) {
      throw new Error('StorageManager not initialized - call initialize() first');
    }
    return this.encryptionUtil.decrypt(encryptedData);
  }

  async loadStorageData(): Promise<StorageData> {
    await this.initialize();
    if (!this.isInitializedStorageSuccess || !fs.existsSync(this.storageFile)) {
      return { tokens: {}, clients: {} };
    }
    try {
      const data = fs.readFileSync(this.storageFile, 'utf8');
      return data ? JSON.parse(this.decrypt(data)) : { tokens: {}, clients: {} };
    } catch (error) {
      logger.error(`[StorageManager] Failed to load storage data: ${error}`);
      logger.error(
        '[StorageManager] ⚠️ Builtin User Access Token Store will be disabled. but you can still use it with memory store',
      );
      return { tokens: {}, clients: {} };
    }
  }

  async saveStorageData(data: StorageData): Promise<void> {
    if (!this.isInitializedStorageSuccess) {
      return;
    }
    await this.initialize();
    try {
      const encryptedData = this.encrypt(JSON.stringify(data, null, 2));
      fs.writeFileSync(this.storageFile, encryptedData);
    } catch (error) {
      logger.error(`[StorageManager] Failed to save storage data: ${error}`);
      throw error;
    }
  }
}

export const storageManager = new StorageManager();
