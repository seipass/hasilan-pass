const DATABASE_NAME = "hasilan-extension-device-secrets-v1";
const DATABASE_VERSION = 2;
const KEY_STORE = "keys";
const TOKEN_STORE = "tokens";
const RECORD_STORE = "records";
const KEY_ID = "trusted-device-aes-gcm";
const ENVELOPE_VERSION = 1;

interface StoredKey { id: string; key: CryptoKey }
interface StoredEnvelope {
  id: string;
  version?: number;
  keyVersion?: string;
  createdAt?: number;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

export interface ExtensionSessionRecord {
  serverUrl: string;
  email: string;
  accountId: string;
  deviceId: string;
  kdf: unknown;
  protectedUserKey: string;
  /** Optional for migration from records written before key-version binding. */
  keyVersion?: string;
  rememberUnlock: boolean;
  manualLockSuppressed: boolean;
  updatedAt: number;
}

/** Encrypted IndexedDB records shared by the MV3 worker and popup. */
export class DeviceSecretStore {
  async loadRefreshToken(serverUrl: string, deviceId: string): Promise<string | null> {
    return this.loadText(`refresh:${serverUrl}\u0000${deviceId}`);
  }

  async saveRefreshToken(serverUrl: string, deviceId: string, token: string): Promise<void> {
    if (token.length < 32) throw new Error("The refresh token is malformed.");
    await this.saveText(`refresh:${serverUrl}\u0000${deviceId}`, token);
  }

  async removeRefreshToken(serverUrl: string, deviceId: string): Promise<void> {
    await this.remove(`refresh:${serverUrl}\u0000${deviceId}`);
  }

  async loadUnlock(serverUrl: string, accountId: string, deviceId: string, expectedKeyVersion?: string): Promise<Uint8Array | null> {
    return this.loadBytes(unlockId(serverUrl, accountId, deviceId), expectedKeyVersion);
  }

  async saveUnlock(serverUrl: string, accountId: string, deviceId: string, key: Uint8Array, keyVersion?: string): Promise<void> {
    if (key.byteLength !== 64) throw new Error("The wrapped vault key is malformed.");
    await this.saveBytes(unlockId(serverUrl, accountId, deviceId), key, keyVersion);
  }

  async removeUnlock(serverUrl: string, accountId: string, deviceId: string): Promise<void> {
    await this.remove(unlockId(serverUrl, accountId, deviceId));
  }

  async clearUnlocks(): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(RECORD_STORE, "readwrite");
      const store = transaction.objectStore(RECORD_STORE);
      const keys = await result<IDBValidKey[]>(store.getAllKeys());
      for (const key of keys) {
        if (typeof key === "string" && key.startsWith("unlock:")) store.delete(key);
      }
      await done(transaction);
    } finally {
      database.close();
    }
  }

  async loadSession(): Promise<ExtensionSessionRecord | null> {
    const text = await this.loadText("session");
    if (text === null) return null;
    try {
      const value = JSON.parse(text) as Partial<ExtensionSessionRecord>;
      const valid = !(
        typeof value.serverUrl !== "string" || typeof value.email !== "string" || typeof value.accountId !== "string"
        || typeof value.deviceId !== "string" || typeof value.protectedUserKey !== "string"
        || value.kdf === null || typeof value.kdf !== "object" || Array.isArray(value.kdf)
        || (value.keyVersion !== undefined && typeof value.keyVersion !== "string")
        || typeof value.rememberUnlock !== "boolean" || typeof value.manualLockSuppressed !== "boolean"
        || typeof value.updatedAt !== "number"
      );
      if (!valid) {
        await this.remove("session").catch(() => undefined);
        return null;
      }
      return value as ExtensionSessionRecord;
    } catch {
      await this.remove("session").catch(() => undefined);
      return null;
    }
  }

  async saveSession(session: ExtensionSessionRecord): Promise<void> {
    await this.saveText("session", JSON.stringify(session));
  }

  async removeSession(): Promise<void> {
    await this.remove("session");
  }

  private async loadText(id: string): Promise<string | null> {
    const bytes = await this.loadBytes(id);
    if (bytes === null) return null;
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return null; } finally { bytes.fill(0); }
  }

  private async saveText(id: string, text: string): Promise<void> {
    const bytes = new TextEncoder().encode(text);
    try { await this.saveBytes(id, bytes); } finally { bytes.fill(0); }
  }

  async loadBytes(id: string, expectedKeyVersion?: string): Promise<Uint8Array | null> {
    if (crypto.subtle === undefined) return null;
    const database = await openDatabase();
    try {
      const transaction = database.transaction([KEY_STORE, TOKEN_STORE, RECORD_STORE], "readonly");
      const [storedKey, stored] = await Promise.all([
        result<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID)),
        result<StoredEnvelope | undefined>(transaction.objectStore(RECORD_STORE).get(id)),
        done(transaction),
      ]);
      if (
        storedKey === undefined
        || stored === undefined
        || (stored.version !== undefined && stored.version !== ENVELOPE_VERSION)
        || (expectedKeyVersion !== undefined
          && stored.keyVersion !== undefined
          && stored.keyVersion !== expectedKeyVersion)
      ) return null;
      try {
        // Authenticate key-version metadata as AAD. Records from the pre-versioned schema omit
        // it and continue to use the legacy AAD until the next successful unlock rewrites them.
        const authenticatedData = aad(id, stored.keyVersion);
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: stored.iv, additionalData: authenticatedData.buffer as ArrayBuffer },
          storedKey.key,
          stored.ciphertext,
        );
        return new Uint8Array(plaintext);
      } catch {
        await this.remove(id).catch(() => undefined);
        return null;
      }
    } finally { database.close(); }
  }

  async saveBytes(id: string, bytes: Uint8Array, keyVersion?: string): Promise<void> {
    if (crypto.subtle === undefined) throw new Error("Secure device storage is unavailable.");
    const key = await getOrCreateKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const authenticatedData = aad(id, keyVersion);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: authenticatedData.buffer as ArrayBuffer },
      key,
      bytes as unknown as BufferSource,
    );
    const database = await openDatabase();
    try {
      const transaction = database.transaction(RECORD_STORE, "readwrite");
      transaction.objectStore(RECORD_STORE).put({
        id,
        version: ENVELOPE_VERSION,
        ...(keyVersion === undefined ? {} : { keyVersion }),
        createdAt: Date.now(),
        iv: new Uint8Array(iv).buffer,
        ciphertext,
      } satisfies StoredEnvelope);
      await done(transaction);
    } finally { database.close(); }
  }

  async remove(id: string): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction([TOKEN_STORE, RECORD_STORE], "readwrite");
      transaction.objectStore(TOKEN_STORE).delete(id);
      transaction.objectStore(RECORD_STORE).delete(id);
      await done(transaction);
    } finally { database.close(); }
  }
}

/** Server MFA trust remains separate from the extension session envelope. */
export class TrustedDeviceStore {
  async load(serverUrl: string, email: string, deviceId: string): Promise<string | null> {
    const database = await openDatabase();
    const id = tokenId(serverUrl, email, deviceId);
    try {
      const transaction = database.transaction([KEY_STORE, TOKEN_STORE], "readonly");
      const [storedKey, stored] = await Promise.all([
        result<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID)),
        result<StoredEnvelope | undefined>(transaction.objectStore(TOKEN_STORE).get(id)),
        done(transaction),
      ]);
      if (storedKey === undefined || stored === undefined) return null;
      try {
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.iv, additionalData: new TextEncoder().encode(id).buffer as ArrayBuffer }, storedKey.key, stored.ciphertext);
        return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      } catch {
        await removeToken(id).catch(() => undefined);
        return null;
      }
    } finally { database.close(); }
  }

  async save(serverUrl: string, email: string, deviceId: string, token: string): Promise<void> {
    if (token.length < 32) throw new Error("The trusted-device token is malformed.");
    const key = await getOrCreateKey();
    const id = tokenId(serverUrl, email, deviceId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: new TextEncoder().encode(id).buffer as ArrayBuffer }, key, new TextEncoder().encode(token));
    const database = await openDatabase();
    try {
      const transaction = database.transaction(TOKEN_STORE, "readwrite");
      transaction.objectStore(TOKEN_STORE).put({ id, version: ENVELOPE_VERSION, iv: new Uint8Array(iv).buffer, ciphertext } satisfies StoredEnvelope);
      await done(transaction);
    } finally { database.close(); }
  }

  async remove(serverUrl: string, email: string, deviceId: string): Promise<void> { await removeToken(tokenId(serverUrl, email, deviceId)); }
}

function unlockId(serverUrl: string, accountId: string, deviceId: string): string {
  return `unlock:${serverUrl}\u0000${accountId}\u0000${deviceId}`;
}

function tokenId(serverUrl: string, email: string, deviceId: string): string {
  return `${serverUrl}\u0000${email.trim().toLowerCase()}\u0000${deviceId}`;
}

function aad(id: string, keyVersion?: string): Uint8Array {
  return new TextEncoder().encode(
    `hasilan-pass/extension-device-unlock/v${ENVELOPE_VERSION}/${id}${keyVersion === undefined ? "" : `/key/${keyVersion}`}`,
  );
}

/** A non-secret identifier that invalidates remembered unlock after key/KDF rotation. */
export async function keyVersionFor(protectedUserKey: string, kdf: unknown): Promise<string> {
  const input = new TextEncoder().encode(JSON.stringify({ protectedUserKey, kdf }));
  const digest = await crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function removeToken(id: string): Promise<void> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(TOKEN_STORE, "readwrite");
    transaction.objectStore(TOKEN_STORE).delete(id);
    await done(transaction);
  } finally { database.close(); }
}

async function getOrCreateKey(): Promise<CryptoKey> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(KEY_STORE, "readonly");
    const stored = await result<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID));
    await done(transaction);
    if (stored !== undefined) return stored.key;
  } finally { database.close(); }
  const generated = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const writable = await openDatabase();
  try {
    const transaction = writable.transaction(KEY_STORE, "readwrite");
    transaction.objectStore(KEY_STORE).put({ id: KEY_ID, key: generated } satisfies StoredKey);
    await done(transaction);
  } finally { writable.close(); }
  return generated;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(KEY_STORE)) database.createObjectStore(KEY_STORE, { keyPath: "id" });
      if (!database.objectStoreNames.contains(TOKEN_STORE)) database.createObjectStore(TOKEN_STORE, { keyPath: "id" });
      if (!database.objectStoreNames.contains(RECORD_STORE)) database.createObjectStore(RECORD_STORE, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open extension device-secret storage."));
    request.onblocked = () => reject(new Error("Extension device-secret storage is blocked."));
  });
}

function result<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Extension device-secret request failed."));
  });
}

function done(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Extension device-secret transaction failed."));
    transaction.onabort = () => reject(transaction.error ?? new Error("Extension device-secret transaction aborted."));
  });
}
