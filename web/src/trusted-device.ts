const DATABASE_NAME = "hasilan-pass-device-secrets-v1";
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
  async load(email: string, deviceId: string): Promise<string | null> {
    if (crypto.subtle === undefined) return null;
    const database = await openDatabase();
    try {
      const transaction = database.transaction([KEY_STORE, TOKEN_STORE], "readonly");
      const [storedKey, storedToken] = await Promise.all([
        requestResult<StoredKey | undefined>(transaction.objectStore(KEY_STORE).get(KEY_ID)),
        requestResult<StoredToken | undefined>(transaction.objectStore(TOKEN_STORE).get(tokenId(email, deviceId))),
        transactionDone(transaction),
      ]);
      if (storedKey === undefined || storedToken === undefined) return null;
      try {
        const plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: storedToken.iv,
            additionalData: new TextEncoder().encode(storedToken.id),
          },
          storedKey.key,
          storedToken.ciphertext,
        );
        return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      } catch {
        await this.remove(email, deviceId).catch(() => undefined);
        return null;
      }
    } finally {
      database.close();
    }
  }

  async save(email: string, deviceId: string, token: string): Promise<void> {
    if (crypto.subtle === undefined || token.length < 32) {
      throw new Error("Secure trusted-device storage is unavailable.");
    }
    const key = await getOrCreateKey();
    const id = tokenId(email, deviceId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const storedIv = new Uint8Array(iv).buffer;
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(id) },
      key,
      new TextEncoder().encode(token),
    );
    const database = await openDatabase();
    try {
      const transaction = database.transaction(TOKEN_STORE, "readwrite");
      transaction.objectStore(TOKEN_STORE).put({ id, iv: storedIv, ciphertext } satisfies StoredToken);
      await transactionDone(transaction);
    } finally {
      database.close();
    }
  }

  async remove(email: string, deviceId: string): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(TOKEN_STORE, "readwrite");
      transaction.objectStore(TOKEN_STORE).delete(tokenId(email, deviceId));
      await transactionDone(transaction);
    } finally {
      database.close();
    }
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

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(KEY_STORE)) {
        database.createObjectStore(KEY_STORE, { keyPath: "id" });
      }
      if (!database.objectStoreNames.contains(TOKEN_STORE)) {
        database.createObjectStore(TOKEN_STORE, { keyPath: "id" });
      }
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
