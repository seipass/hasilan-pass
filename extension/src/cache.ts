import type { EncryptedObject, SyncResponse } from "./types";

const OBJECTS = "objects";
const META = "meta";

export class ExtensionCipherCache {
  readonly #name: string;

  constructor(serverUrl: string, accountId: string) {
    if (!/^[0-9a-f-]{36}$/iu.test(accountId)) throw new Error("Invalid encrypted cache scope.");
    const scope = new TextEncoder().encode(`${serverUrl}|${accountId}`);
    this.#name = `hasilan-extension-v1-${hex(scope)}`;
  }

  async load(): Promise<{ objects: EncryptedObject[]; cursor: string | null }> {
    const database = await this.#open();
    try {
      const transaction = database.transaction([OBJECTS, META], "readonly");
      const objectsRequest = transaction.objectStore(OBJECTS).getAll();
      const cursorRequest = transaction.objectStore(META).get("cursor");
      const [objects, cursor] = await Promise.all([
        result<EncryptedObject[]>(objectsRequest),
        result<{ key: string; value: string } | undefined>(cursorRequest),
        done(transaction),
      ]);
      return { objects, cursor: cursor?.value ?? null };
    } finally {
      database.close();
    }
  }

  async apply(page: SyncResponse): Promise<void> {
    const database = await this.#open();
    try {
      const transaction = database.transaction([OBJECTS, META], "readwrite");
      const store = transaction.objectStore(OBJECTS);
      for (const change of page.changes) {
        if (change.object === null) store.delete(change.objectId);
        else store.put(change.object);
      }
      transaction.objectStore(META).put({ key: "cursor", value: page.nextCursor });
      await done(transaction);
    } finally {
      database.close();
    }
  }

  async save(object: EncryptedObject): Promise<void> {
    const database = await this.#open();
    try {
      const transaction = database.transaction(OBJECTS, "readwrite");
      transaction.objectStore(OBJECTS).put(object);
      await done(transaction);
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.#name);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error("Could not clear encrypted cache."));
      request.onblocked = () => reject(new Error("Encrypted cache is open in another extension context."));
    });
  }

  async #open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.#name, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(OBJECTS)) request.result.createObjectStore(OBJECTS, { keyPath: "id" });
        if (!request.result.objectStoreNames.contains(META)) request.result.createObjectStore(META, { keyPath: "key" });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Could not open encrypted cache."));
    });
  }
}

function result<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Encrypted cache request failed."));
  });
}

function done(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error("Encrypted cache transaction aborted."));
    transaction.onerror = () => reject(transaction.error ?? new Error("Encrypted cache transaction failed."));
  });
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}
