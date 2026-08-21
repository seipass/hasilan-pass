import "fake-indexeddb/auto";

import { beforeEach, describe, expect, it } from "vitest";

import { DeviceSecretStore, TrustedDeviceStore } from "./trusted-device";

describe("extension device-secret storage", () => {
  beforeEach(async () => {
    await deleteDatabase("hasilan-extension-device-secrets-v1");
  });

  it("encrypts refresh/session and unlock records separately", async () => {
    const store = new DeviceSecretStore();
    const key = crypto.getRandomValues(new Uint8Array(64));
    await store.saveRefreshToken("https://vault.example.test", "device-a", "refresh-token-with-more-than-32-bytes-0001");
    await store.saveUnlock("https://vault.example.test", "account-a", "device-a", key, "version-a");
    await store.saveSession({
      serverUrl: "https://vault.example.test",
      email: "alice@example.test",
      accountId: "account-a",
      deviceId: "device-a",
      kdf: { kdfType: "argon2id", iterations: 6, memoryMib: 32, parallelism: 4 },
      protectedUserKey: "2.wrapped|ciphertext|mac",
      keyVersion: "version-a",
      rememberUnlock: true,
      manualLockSuppressed: false,
      updatedAt: Date.now(),
    });
    expect(await store.loadRefreshToken("https://vault.example.test", "device-a")).toContain("refresh-token");
    expect([...await store.loadUnlock("https://vault.example.test", "account-a", "device-a", "version-a") ?? []]).toEqual([...key]);
    const records = await readAll("records");
    expect(JSON.stringify(records)).not.toContain("refresh-token");
    expect(JSON.stringify(records)).not.toContain(String.fromCharCode(...key.slice(0, 8)));
    key.fill(0);
  });

  it("rejects an unlock envelope after key-version rotation", async () => {
    const store = new DeviceSecretStore();
    await store.saveUnlock("https://vault.example.test", "account-a", "device-a", new Uint8Array(64), "version-a");
    expect(await store.loadUnlock("https://vault.example.test", "account-a", "device-a", "version-b")).toBeNull();
  });

  it("authenticates key-version metadata instead of trusting a mutable field", async () => {
    const store = new DeviceSecretStore();
    await store.saveUnlock("https://vault.example.test", "account-a", "device-a", new Uint8Array(64), "version-a");
    const records = await readAll("records") as Array<Record<string, unknown>>;
    const record = records.find((value) => typeof value.id === "string" && value.id.startsWith("unlock:"));
    expect(record).toBeDefined();
    if (record !== undefined) {
      const { keyVersion: _removed, ...legacyMetadata } = record;
      await putRecord(legacyMetadata);
    }
    expect(await store.loadUnlock("https://vault.example.test", "account-a", "device-a")).toBeNull();
  });

  it("keeps legacy trusted-device tokens in their separate token store", async () => {
    const trusted = new TrustedDeviceStore();
    await trusted.save("https://vault.example.test", "alice@example.test", "device-a", "trusted-token-with-more-than-32-bytes-0001");
    expect(await trusted.load("https://vault.example.test", "alice@example.test", "device-a")).toContain("trusted-token");
    expect(await new DeviceSecretStore().loadSession()).toBeNull();
  });

  it("fails closed when an unlock envelope is corrupted", async () => {
    const store = new DeviceSecretStore();
    await store.saveUnlock("https://vault.example.test", "account-a", "device-a", new Uint8Array(64));
    const records = await readAll("records") as Array<{ id: string; ciphertext: ArrayBuffer }>;
    const record = records.find((value) => value.id.startsWith("unlock:"));
    expect(record).toBeDefined();
    if (record !== undefined) {
      const ciphertext = new Uint8Array(record.ciphertext);
      ciphertext[0] = (ciphertext[0] ?? 0) ^ 0xff;
      await putRecord({ ...record, ciphertext: ciphertext.buffer });
    }
    expect(await store.loadUnlock("https://vault.example.test", "account-a", "device-a")).toBeNull();
  });

  it("keeps manual lock state separate from remembered-unlock preference", async () => {
    const store = new DeviceSecretStore();
    await store.saveSession({
      serverUrl: "https://vault.example.test",
      email: "alice@example.test",
      accountId: "account-a",
      deviceId: "device-a",
      kdf: { kdfType: "argon2id" },
      protectedUserKey: "protected-key",
      rememberUnlock: true,
      manualLockSuppressed: false,
      updatedAt: Date.now(),
    });
    await store.saveUnlock("https://vault.example.test", "account-a", "device-a", new Uint8Array(64), "version-a");
    await store.saveSession({ ...(await store.loadSession())!, manualLockSuppressed: true });
    expect((await store.loadSession())?.manualLockSuppressed).toBe(true);
    await store.saveSession({ ...(await store.loadSession())!, rememberUnlock: false });
    await store.removeUnlock("https://vault.example.test", "account-a", "device-a");
    expect(await store.loadUnlock("https://vault.example.test", "account-a", "device-a")).toBeNull();
    expect((await store.loadSession())?.rememberUnlock).toBe(false);
    await store.removeSession();
    expect(await store.loadSession()).toBeNull();
  });
});

async function deleteDatabase(name: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
}

async function readAll(storeName: string): Promise<unknown[]> {
  const database = await openDatabase();
  try {
    return await new Promise<unknown[]>((resolve, reject) => {
      const request = database.transaction(storeName, "readonly").objectStore(storeName).getAll();
      request.onsuccess = () => resolve(request.result as unknown[]);
      request.onerror = () => reject(request.error);
    });
  } finally {
    database.close();
  }
}

async function putRecord(value: unknown): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction("records", "readwrite");
      transaction.objectStore("records").put(value);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally {
    database.close();
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("hasilan-extension-device-secrets-v1", 2);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains("keys")) database.createObjectStore("keys", { keyPath: "id" });
      if (!database.objectStoreNames.contains("tokens")) database.createObjectStore("tokens", { keyPath: "id" });
      if (!database.objectStoreNames.contains("records")) database.createObjectStore("records", { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
