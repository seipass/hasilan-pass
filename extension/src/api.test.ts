import { afterEach, describe, expect, it, vi } from "vitest";

import { ExtensionApi, normalizeServerUrl } from "./api";
import type { TokenResponse } from "./types";

const firstSession: TokenResponse = {
  accountId: "00000000-0000-4000-8000-000000000001",
  accessToken: "first-access-token",
  refreshToken: "first-refresh-token",
  tokenType: "Bearer",
  expiresIn: 900,
  protectedUserKey: "2.wrapped|ciphertext|mac",
  kdf: { kdfType: "argon2id", iterations: 6, memoryMib: 32, parallelism: 4 },
  sessionId: "00000000-0000-4000-8000-000000000002",
  deviceId: "00000000-0000-4000-8000-000000000003",
  trustedDeviceToken: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ExtensionApi", () => {
  it("keeps tokens in memory and attaches them only to authenticated calls", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstSession))
      .mockResolvedValueOnce(jsonResponse({ changes: [], nextCursor: "0", hasMore: false }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ExtensionApi();
    client.configure("https://vault.example.test/path/");

    await client.login('{"opaque":"login"}');
    await client.sync(null);

    expect(new Headers(fetchMock.mock.calls[0]?.[1]?.headers).has("Authorization")).toBe(false);
    expect(new Headers(fetchMock.mock.calls[1]?.[1]?.headers).get("Authorization")).toBe("Bearer first-access-token");
    expect(client.accountId).toBe(firstSession.accountId);
  });

  it("coalesces refresh and retries once with the rotated access token", async () => {
    const rotated = { ...firstSession, accessToken: "rotated-access-token", refreshToken: "rotated-refresh-token" };
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstSession))
      .mockResolvedValueOnce(jsonResponse({ code: "unauthorized" }, 401))
      .mockResolvedValueOnce(jsonResponse(rotated))
      .mockResolvedValueOnce(jsonResponse({ changes: [], nextCursor: "1", hasMore: false }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ExtensionApi();
    client.configure("https://vault.example.test");
    await client.login('{"opaque":"login"}');

    await client.sync(null);

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls[2]?.[1]?.body).toBe(JSON.stringify({ refreshToken: "first-refresh-token" }));
    expect(new Headers(fetchMock.mock.calls[3]?.[1]?.headers).get("Authorization")).toBe("Bearer rotated-access-token");
  });

  it("retries an opaque attachment frame after token rotation", async () => {
    const rotated = { ...firstSession, accessToken: "rotated-access-token", refreshToken: "rotated-refresh-token" };
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstSession))
      .mockResolvedValueOnce(jsonResponse({ code: "unauthorized" }, 401))
      .mockResolvedValueOnce(jsonResponse(rotated))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ExtensionApi();
    client.configure("https://vault.example.test");
    await client.login('{"opaque":"login"}');

    await client.putAttachmentChunk("attachment-id", 3, new Uint8Array([1, 2, 3]));

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls[1]?.[0]).toBe("https://vault.example.test/api/v1/attachments/attachment-id/chunks/3");
    expect(new Headers(fetchMock.mock.calls[3]?.[1]?.headers).get("Authorization")).toBe("Bearer rotated-access-token");
    expect(new Headers(fetchMock.mock.calls[3]?.[1]?.headers).get("Content-Type")).toBe("application/octet-stream");
  });
});

describe("normalizeServerUrl", () => {
  it("accepts HTTPS and local HTTP while removing a path", () => {
    expect(normalizeServerUrl(" https://vault.example.test/base/ ")).toBe("https://vault.example.test");
    expect(normalizeServerUrl("http://127.0.0.1:8080/api")).toBe("http://127.0.0.1:8080");
  });

  it.each([
    "http://vault.example.test",
    "ftp://vault.example.test",
    "https://user:secret@vault.example.test",
    "https://vault.example.test?token=secret",
    "https://vault.example.test/#fragment",
  ])("rejects unsafe server URL %s", (value) => {
    expect(() => normalizeServerUrl(value)).toThrow();
  });
});

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}
