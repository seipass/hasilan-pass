/**
 * Device-bound WebCrypto storage.
 *
 * IndexedDB contains only a non-extractable AES-GCM CryptoKey and encrypted
 * envelopes.  The key, plaintext trusted-device token, session metadata, and
 * wrapped vault key are never written to localStorage/sessionStorage.
 */
const DATABASE_NAME = "hasilan-pass-device-secrets-v1";
const DATABASE_VERSION = 2;
const KEY_STORE = "keys";
const TOKEN_STORE = "tokens";
const RECORD_STORE = "records";
const KEY_ID = "trusted-device-aes-gcm";
const ENVELOPE_VERSION = 1;

interface StoredKey {
  id: string;
  key: CryptoKey;
}

interface StoredEnvelope {
  id: string;
  /** Version was absent from the original trusted-device records. */
  version?: number;
  /** Fingerprint of the account's current protected user-key/KDF tuple. */
  keyVersion?: string;
  createdAt?: number;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

export interface WebSessionRecord {
  accountId: string;
  email: string;
  deviceId: string;
  csrfToken: string;
  kdf: unknown;
  protectedUserKey: string;
  /** Optional for migration from records written before key-version binding. */
  keyVersion?: string;
  rememberUnlock: boolean;
  manualLockSuppressed: boolean;
  updatedAt: number;
}

export class DeviceUnlockStore {
  async loadUnlock(accountId: string, deviceId: string, expectedKeyVersion?: string): Promise<Uint8Array | null> {
    const id = unlockId(accountId, deviceId);
    return this.loadBytes(id, id, expectedKeyVersion);
  }

  async saveUnlock(accountId: string, deviceId: string, keyBytes: Uint8Array, keyVersion?: string): Promise<void> {
    if (keyBytes.byteLength !== 64) throw new Error("The wrapped vault key is malformed.");
    const id = unlockId(accountId, deviceId);
    await this.saveBytes(id, id, keyBytes, keyVersion);
  }

  async removeUnlock(accountId: string, deviceId: string): Promise<void> {
    await this.removeRecord(unlockId(accountId, deviceId));
  }

  async clearUnlocks(): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(RECORD_STORE, "readwrite");
      const store = transaction.objectStore(RECORD_STORE);
      const keys = await requestResult<IDBValidKey[]>(store.getAllKeys());
      for (const key of keys) {
        if (typeof key === "string" && key.startsWith("unlock:")) store.delete(key);
      }
      await transactionDone(transaction);
    } finally {
      database.close();
    }
  }

  async loadSession(): Promise<WebSessionRecord | null> {
    const id = "web-session";
    const bytes = await this.loadBytes(id, id);
    if (bytes === null) return null;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const value = JSON.parse(text) as Partial<WebSessionRecord>;
      const valid = !(
        typeof value.accountId !== "string"
        || typeof value.email !== "string"
        || typeof value.deviceId !== "string"
        || typeof value.csrfToken !== "string"
        || value.kdf === null
        || typeof value.kdf !== "object"
        || Array.isArray(value.kdf)
        || typeof value.protectedUserKey !== "string"
        || (value.keyVersion !== undefined && typeof value.keyVersion !== "string")
        || typeof value.rememberUnlock !== "boolean"
        || typeof value.manualLockSuppressed !== "boolean"
        || typeof value.updatedAt !== "number"
      );
      if (!valid) {
        await this.removeRecord(id).catch(() => undefined);
        return null;
      }
      return value as WebSessionRecord;
    } catch {
      await this.removeRecord(id).catch(() => undefined);
      return null;
    } finally {
      bytes.fill(0);
    }
  }

  async saveSession(session: WebSessionRecord): Promise<void> {
    const bytes = new TextEncoder().encode(JSON.stringify(session));
    try {
      await this.saveBytes("web-session", "web-session", bytes);
    } finally {
      bytes.fill(0);
    }
  }

  async setManualLockSuppressed(suppressed: boolean): Promise<void> {
    const session = await this.loadSession();
    if (session === null) return;
    await this.saveSession({ ...session, manualLockSuppressed: suppressed, updatedAt: Date.now() });
  }

  async removeSession(): Promise<void> {
    await this.removeRecord("web-session");
  }

  async loadBytes(id: string, aadId: string, expectedKeyVersion?: string): Promise<Uint8Array | null> {
    return this.loadFromStore(RECORD_STORE, id, aadId, undefined, expectedKeyVersion);
  }

  async loadTokenBytes(id: string): Promise<Uint8Array | null> {
    // Keep the original raw-id AAD for MFA trusted-device records so users do not
    // lose an already-enrolled browser when the unlock/session envelope is added.
    return this.loadFromStore(TOKEN_STORE, id, id, tokenAad(id));
  }

  private async loadFromStore(
    storeName: string,
    id: string,
    aadId: string,
    additionalData?: Uint8Array,
    expectedKeyVersion?: string,
  ): Promise<Uint8Array | null> {
    if (crypto.subtle === undefined) return null;
    const database = await openDatabase();
    try {
      const transaction = database.transaction([KEY_STORE, TOKEN_STORE, RECORD_STORE], "readonly");
      const [storedKey, storedEnvelope] = await Promise.all([
        requestResult<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID)),
        requestResult<StoredEnvelope | undefined>(transaction.objectStore(storeName).get(id)),
        transactionDone(transaction),
      ]);
      if (
        storedKey === undefined
        || storedEnvelope === undefined
        || (storedEnvelope.version !== undefined && storedEnvelope.version !== ENVELOPE_VERSION)
        || (expectedKeyVersion !== undefined
          && storedEnvelope.keyVersion !== undefined
          && storedEnvelope.keyVersion !== expectedKeyVersion)
      ) return null;
      try {
        // New envelopes authenticate their key-version metadata as AAD. Legacy records without
        // that field retain the original AAD so they can be migrated after a successful unlock.
        const authenticatedData = additionalData ?? aad(aadId, storedEnvelope.keyVersion);
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: storedEnvelope.iv, additionalData: authenticatedData.buffer as ArrayBuffer },
          storedKey.key,
          storedEnvelope.ciphertext,
        );
        return new Uint8Array(plaintext);
      } catch {
        await this.removeRecord(id).catch(() => undefined);
        return null;
      }
    } finally {
      database.close();
    }
  }

  async saveBytes(id: string, aadId: string, plaintext: Uint8Array, keyVersion?: string): Promise<void> {
    await this.saveToStore(RECORD_STORE, id, aadId, plaintext, undefined, keyVersion);
  }

  async saveTokenBytes(id: string, plaintext: Uint8Array): Promise<void> {
    await this.saveToStore(TOKEN_STORE, id, id, plaintext, tokenAad(id));
  }

  private async saveToStore(
    storeName: string,
    id: string,
    aadId: string,
    plaintext: Uint8Array,
    additionalData?: Uint8Array,
    keyVersion?: string,
  ): Promise<void> {
    if (crypto.subtle === undefined) throw new Error("Secure device storage is unavailable.");
    const key = await getOrCreateKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const authenticatedData = additionalData ?? aad(aadId, keyVersion);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: authenticatedData.buffer as ArrayBuffer },
      key,
      plaintext as unknown as BufferSource,
    );
    const database = await openDatabase();
    try {
      const transaction = database.transaction(storeName, "readwrite");
      transaction.objectStore(storeName).put({
        id,
        version: ENVELOPE_VERSION,
        ...(keyVersion === undefined ? {} : { keyVersion }),
        createdAt: Date.now(),
        iv: new Uint8Array(iv).buffer,
        ciphertext,
      } satisfies StoredEnvelope);
      await transactionDone(transaction);
    } finally {
      database.close();
    }
  }

  async removeRecord(id: string): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction([TOKEN_STORE, RECORD_STORE], "readwrite");
      transaction.objectStore(TOKEN_STORE).delete(id);
      transaction.objectStore(RECORD_STORE).delete(id);
      await transactionDone(transaction);
    } finally {
      database.close();
    }
  }
}

/** Backwards-compatible store for the server-issued MFA trusted-device token. */
export class TrustedDeviceStore {
  private readonly store = new DeviceUnlockStore();

  async load(email: string, deviceId: string): Promise<string | null> {
    const bytes = await this.store.loadTokenBytes(tokenId(email, deviceId));
    if (bytes === null) return null;
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return null;
    } finally {
      bytes.fill(0);
    }
  }

  async save(email: string, deviceId: string, token: string): Promise<void> {
    if (token.length < 32) throw new Error("Secure trusted-device storage is unavailable.");
    const bytes = new TextEncoder().encode(token);
    try {
      await this.store.saveTokenBytes(tokenId(email, deviceId), bytes);
    } finally {
      bytes.fill(0);
    }
  }

  async remove(email: string, deviceId: string): Promise<void> {
    await this.store.removeRecord(tokenId(email, deviceId));
  }
}

async function getOrCreateKey(): Promise<CryptoKey> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(KEY_STORE, "readonly");
    const stored = await requestResult<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID));
    await transactionDone(transaction);
    if (stored !== undefined) return stored.key;
  } finally {
    database.close();
  }

  const generated = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const writable = await openDatabase();
  try {
    const transaction = writable.transaction(KEY_STORE, "readwrite");
    transaction.objectStore(KEY_STORE).put({ id: KEY_ID, key: generated } satisfies StoredKey);
    await transactionDone(transaction);
  } finally {
    writable.close();
  }
  return generated;
}

function tokenId(email: string, deviceId: string): string {
  return `${email.trim().toLowerCase()}\u0000${deviceId}`;
}

function unlockId(accountId: string, deviceId: string): string {
  return `unlock:${accountId}\u0000${deviceId}`;
}

function aad(id: string, keyVersion?: string): Uint8Array {
  return new TextEncoder().encode(
    `hasilan-pass/device-unlock/v${ENVELOPE_VERSION}/${id}${keyVersion === undefined ? "" : `/key/${keyVersion}`}`,
  );
}

function tokenAad(id: string): Uint8Array {
  return new TextEncoder().encode(id);
}

/** A non-secret identifier that invalidates remembered unlock after key/KDF rotation. */
export async function keyVersionFor(protectedUserKey: string, kdf: unknown): Promise<string> {
  const input = new TextEncoder().encode(JSON.stringify({ protectedUserKey, kdf }));
  const digest = await crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
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
    request.onerror = () => reject(request.error ?? new Error("Could not open device-secret storage."));
    request.onblocked = () => reject(new Error("Device-secret storage upgrade is blocked."));
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Device-secret request failed."));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Device-secret transaction failed."));
    transaction.onabort = () => reject(transaction.error ?? new Error("Device-secret transaction aborted."));
  });
}
