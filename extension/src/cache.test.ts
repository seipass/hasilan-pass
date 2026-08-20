import "fake-indexeddb/auto";

import { describe, expect, it } from "vitest";

import { ExtensionCipherCache } from "./cache";
import type { EncryptedObject, SyncResponse } from "./types";

describe("ExtensionCipherCache", () => {
  it("persists only opaque encrypted objects and the authenticated cursor", async () => {
    const accountId = crypto.randomUUID();
    const cache = new ExtensionCipherCache("https://vault.example.test", accountId);
    const object: EncryptedObject = {
      id: crypto.randomUUID(),
      kind: "cipher",
      ownerType: "user",
      ownerId: accountId,
      collectionIds: [],
      format: "hp.v1",
      wrappedKey: "2.aW5pdGlhbGl6YXRpb24=|Y2lwaGVydGV4dA==|bWFj",
      payload: "2.bm9uY2U=|b3BhcXVlLXBheWxvYWQ=|bWFj",
      objectRevision: 1,
      accountRevision: 1,
      createdAt: "2026-08-12T00:00:00Z",
      updatedAt: "2026-08-12T00:00:00Z",
      deletedAt: null,
    };
    const page: SyncResponse = {
      changes: [{ revision: 1, operation: "upsert", objectId: object.id, object }],
      nextCursor: "opaque-cursor",
      hasMore: false,
    };

    await cache.apply(page);
    expect(await cache.load()).toEqual({ objects: [object], cursor: "opaque-cursor" });
    expect(JSON.stringify(await cache.load())).not.toContain("master password");
    await cache.clear();
  });

  it("rejects an invalid account scope", () => {
    expect(() => new ExtensionCipherCache("https://vault.example.test", "../shared"))
      .toThrow("Invalid encrypted cache scope");
  });
});
