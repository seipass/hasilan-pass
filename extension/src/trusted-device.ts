const DATABASE_NAME = "hasilan-extension-device-secrets-v1";
const KEY_STORE = "keys";
const TOKEN_STORE = "tokens";
const KEY_ID = "trusted-device-aes-gcm";

interface StoredKey {
  id: string;
  key: CryptoKey;
}

interface StoredToken {
  id: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

export class TrustedDeviceStore {
  async load(serverUrl: string, email: string, deviceId: string): Promise<string | null> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction([KEY_STORE, TOKEN_STORE], "readonly");
      const [storedKey, storedToken] = await Promise.all([
        result<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID)),
        result<StoredToken | undefined>(transaction.objectStore(TOKEN_STORE).get(tokenId(serverUrl, email, deviceId))),
        done(transaction),
      ]);
      if (storedKey === undefined || storedToken === undefined) return null;
      try {
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: storedToken.iv, additionalData: new TextEncoder().encode(storedToken.id) },
          storedKey.key,
          storedToken.ciphertext,
        );
        return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      } catch {
        await this.remove(serverUrl, email, deviceId).catch(() => undefined);
        return null;
      }
    } finally {
      database.close();
    }
  }

  async save(serverUrl: string, email: string, deviceId: string, token: string): Promise<void> {
    if (token.length < 32) throw new Error("The trusted-device token is malformed.");
    const key = await getOrCreateKey();
    const id = tokenId(serverUrl, email, deviceId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(id) },
      key,
      new TextEncoder().encode(token),
    );
    const database = await openDatabase();
    try {
      const transaction = database.transaction(TOKEN_STORE, "readwrite");
      transaction.objectStore(TOKEN_STORE).put({
        id,
        iv: new Uint8Array(iv).buffer,
        ciphertext,
      } satisfies StoredToken);
      await done(transaction);
    } finally {
      database.close();
    }
  }

  async remove(serverUrl: string, email: string, deviceId: string): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(TOKEN_STORE, "readwrite");
      transaction.objectStore(TOKEN_STORE).delete(tokenId(serverUrl, email, deviceId));
      await done(transaction);
    } finally {
      database.close();
    }
  }
}

async function getOrCreateKey(): Promise<CryptoKey> {
  const database = await openDatabase();
  try {
    const transaction = database.transaction(KEY_STORE, "readonly");
    const stored = await result<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID));
    await done(transaction);
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
    await done(transaction);
  } finally {
    writable.close();
  }
  return generated;
}

function tokenId(serverUrl: string, email: string, deviceId: string): string {
  return `${serverUrl}\u0000${email.trim().toLowerCase()}\u0000${deviceId}`;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(KEY_STORE)) {
        request.result.createObjectStore(KEY_STORE, { keyPath: "id" });
      }
      if (!request.result.objectStoreNames.contains(TOKEN_STORE)) {
        request.result.createObjectStore(TOKEN_STORE, { keyPath: "id" });
      }
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
