import "fake-indexeddb/auto";

import { describe, expect, it } from "vitest";

import { EncryptedVaultCache } from "./cache";
import type { EncryptedObject, SyncResponse } from "./types";

describe("EncryptedVaultCache", () => {
  it("persists only the opaque synchronized object and cursor", async () => {
    const accountId = crypto.randomUUID();
    const cache = new EncryptedVaultCache(accountId);
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
      nextCursor: "authenticated-opaque-cursor",
      hasMore: false,
    };

    await cache.applySyncPage(page);
    const snapshot = await cache.load();

    expect(snapshot).toEqual({ objects: [object], cursor: "authenticated-opaque-cursor" });
    expect(JSON.stringify(snapshot)).not.toContain("correct horse battery staple");
    await cache.clear();
  });
});

