import "fake-indexeddb/auto";

import { beforeEach, describe, expect, it } from "vitest";

import { DeviceUnlockStore, TrustedDeviceStore } from "./trusted-device";

describe("device-bound unlock storage", () => {
  beforeEach(async () => {
    await deleteDatabase("hasilan-pass-device-secrets-v1");
  });

  it("round-trips a wrapped user key without placing it in storage plaintext", async () => {
    const store = new DeviceUnlockStore();
    const key = crypto.getRandomValues(new Uint8Array(64));
    await store.saveUnlock("account-a", "device-a", key, "version-a");
    const loaded = await store.loadUnlock("account-a", "device-a", "version-a");
    expect(loaded).not.toBeNull();
    expect([...loaded ?? []]).toEqual([...key]);
    const raw = await readAllRecords("records");
    expect(JSON.stringify(raw)).not.toContain(String.fromCharCode(...key.slice(0, 8)));
    loaded?.fill(0);
    key.fill(0);
  });

  it("rejects a remembered key after the protected user-key version changes", async () => {
    const store = new DeviceUnlockStore();
    await store.saveUnlock("account-a", "device-a", new Uint8Array(64), "version-a");
    expect(await store.loadUnlock("account-a", "device-a", "version-b")).toBeNull();
  });

  it("authenticates the key-version metadata instead of trusting a mutable field", async () => {
    const store = new DeviceUnlockStore();
    await store.saveUnlock("account-a", "device-a", new Uint8Array(64), "version-a");
    const records = await readAllRecords("records") as Array<Record<string, unknown>>;
    const record = records.find((value) => typeof value.id === "string" && value.id.startsWith("unlock:"));
    expect(record).toBeDefined();
    if (record !== undefined) {
      const { keyVersion: _removed, ...legacyMetadata } = record;
      await putRecord(legacyMetadata);
    }
    expect(await store.loadUnlock("account-a", "device-a")).toBeNull();
  });

  it("separates trusted MFA tokens from account unlock records", async () => {
    const trusted = new TrustedDeviceStore();
    await trusted.save("alice@example.test", "device-a", "trusted-token-with-more-than-32-bytes-0001");
    expect(await trusted.load("alice@example.test", "device-a")).toContain("trusted-token");
    const unlock = new DeviceUnlockStore();
    expect(await unlock.loadUnlock("account-a", "device-a")).toBeNull();
  });

  it("fails closed after an authenticated envelope is corrupted", async () => {
    const store = new DeviceUnlockStore();
    await store.saveUnlock("account-a", "device-a", new Uint8Array(64));
    const records = await readAllRecords("records") as Array<{ id: string; ciphertext: ArrayBuffer }>;
    const record = records.find((value) => value.id.startsWith("unlock:"));
    expect(record).toBeDefined();
    if (record !== undefined) {
      const bytes = new Uint8Array(record.ciphertext);
      if (bytes.length > 0) bytes[0] = (bytes[0] ?? 0) ^ 0xff;
      await putRecord({ ...record, ciphertext: bytes.buffer });
    }
    expect(await store.loadUnlock("account-a", "device-a")).toBeNull();
  });

  it("keeps manual lock state separate from remembered-unlock preference", async () => {
    const store = new DeviceUnlockStore();
    await store.saveSession({
      accountId: "account-a",
      email: "alice@example.test",
      deviceId: "device-a",
      csrfToken: "csrf-token",
      kdf: { kdfType: "argon2id" },
      protectedUserKey: "protected-key",
      rememberUnlock: true,
      manualLockSuppressed: false,
      updatedAt: Date.now(),
    });
    await store.saveUnlock("account-a", "device-a", new Uint8Array(64), "version-a");
    await store.setManualLockSuppressed(true);
    expect((await store.loadSession())?.manualLockSuppressed).toBe(true);
    await store.saveSession({ ...(await store.loadSession())!, rememberUnlock: false });
    await store.removeUnlock("account-a", "device-a");
    expect(await store.loadUnlock("account-a", "device-a")).toBeNull();
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

async function readAllRecords(storeName: string): Promise<unknown[]> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("hasilan-pass-device-secrets-v1", 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
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
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("hasilan-pass-device-secrets-v1", 2);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
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
