import type { EncryptedObject, SyncResponse } from "./types";

const OBJECT_STORE = "objects";
const META_STORE = "meta";
const CURSOR_KEY = "cursor";

interface CachedMeta {
  key: string;
  value: string;
}

export interface CacheSnapshot {
  objects: EncryptedObject[];
  cursor: string | null;
}

export class EncryptedVaultCache {
  readonly #databaseName: string;

  constructor(accountId: string) {
    if (!/^[0-9a-f-]{36}$/iu.test(accountId)) {
      throw new Error("Invalid account cache scope.");
    }
    this.#databaseName = `hasilan-pass-v1-${accountId}`;
  }

  async load(): Promise<CacheSnapshot> {
    const database = await this.#open();
    try {
      const transaction = database.transaction([OBJECT_STORE, META_STORE], "readonly");
      const objectsRequest = transaction.objectStore(OBJECT_STORE).getAll();
      const cursorRequest = transaction.objectStore(META_STORE).get(CURSOR_KEY);
      const [objects, cursor] = await Promise.all([
        requestResult<EncryptedObject[]>(objectsRequest),
        requestResult<CachedMeta | undefined>(cursorRequest),
        transactionDone(transaction),
      ]);
      return { objects, cursor: cursor?.value ?? null };
    } finally {
      database.close();
    }
  }

  async applySyncPage(page: SyncResponse): Promise<void> {
    const database = await this.#open();
    try {
      const transaction = database.transaction([OBJECT_STORE, META_STORE], "readwrite");
      const objects = transaction.objectStore(OBJECT_STORE);
      for (const change of page.changes) {
        if (change.object === null) {
          objects.delete(change.objectId);
        } else {
          objects.put(change.object);
        }
      }
      transaction.objectStore(META_STORE).put({ key: CURSOR_KEY, value: page.nextCursor });
      await transactionDone(transaction);
    } finally {
      database.close();
    }
  }

  async saveObject(object: EncryptedObject): Promise<void> {
    const database = await this.#open();
    try {
      const transaction = database.transaction(OBJECT_STORE, "readwrite");
      transaction.objectStore(OBJECT_STORE).put(object);
      await transactionDone(transaction);
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.#databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error("Could not clear vault cache."));
      request.onblocked = () => reject(new Error("Vault cache is in use in another tab."));
    });
  }

  async #open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.#databaseName, 1);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(OBJECT_STORE)) {
          database.createObjectStore(OBJECT_STORE, { keyPath: "id" });
        }
        if (!database.objectStoreNames.contains(META_STORE)) {
          database.createObjectStore(META_STORE, { keyPath: "key" });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Could not open vault cache."));
      request.onblocked = () => reject(new Error("Vault cache upgrade is blocked."));
    });
  }
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Vault cache request failed."));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Vault cache transaction failed."));
    transaction.onabort = () => reject(transaction.error ?? new Error("Vault cache transaction aborted."));
  });
}

