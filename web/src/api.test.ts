import { describe, expect, it, vi } from "vitest";

import { ApiClient } from "./api";
import type { WebSessionRecord } from "./trusted-device";
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
const firstWebSession = { ...firstSession, refreshToken: "" };
const firstCsrf = "first_csrf_token_0123456789abcdef";
const rotatedCsrf = "rotated_csrf_token_0123456789abcd";

describe("ApiClient", () => {
  it("keeps tokens in memory and attaches the access token only to authenticated calls", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstWebSession, 200, firstCsrf))
      .mockResolvedValueOnce(jsonResponse([]));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient();

    await client.login({
      email: "alice@example.test",
      authProof: "proof",
      device: { identifier: crypto.randomUUID(), name: "test", deviceType: "web" },
      totpCode: null,
      recoveryCode: null,
      trustedDeviceToken: null,
      rememberDevice: false,
    });
    await client.listDevices();

    const loginInit = fetchMock.mock.calls[0]?.[1];
    const devicesInit = fetchMock.mock.calls[1]?.[1];
    expect(new Headers(loginInit?.headers).has("Authorization")).toBe(false);
    expect(new Headers(loginInit?.headers).get("X-Hasilan-Web-Session")).toBe("1");
    expect(loginInit?.credentials).toBe("same-origin");
    expect(new Headers(devicesInit?.headers).get("Authorization")).toBe("Bearer first-access-token");
    expect(JSON.stringify(localStorage)).not.toContain("first-access-token");
    expect(JSON.stringify(sessionStorage)).not.toContain("first-refresh-token");
  });

  it("rotates a refresh token once and retries with the new access token", async () => {
    const rotated = { ...firstWebSession, accessToken: "rotated-access-token" };
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstWebSession, 200, firstCsrf))
      .mockResolvedValueOnce(jsonResponse({ code: "unauthorized", message: "Unauthorized", requestId: null }, 401))
      .mockResolvedValueOnce(jsonResponse(rotated, 200, rotatedCsrf))
      .mockResolvedValueOnce(jsonResponse([]));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient();
    await client.login({
      email: "alice@example.test",
      authProof: "proof",
      device: { identifier: crypto.randomUUID(), name: "test", deviceType: "web" },
      totpCode: null,
      recoveryCode: null,
      trustedDeviceToken: null,
      rememberDevice: false,
    });

    await client.listSessions();

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(fetchMock.mock.calls[2]?.[1]?.body).toBe(JSON.stringify({ refreshToken: "" }));
    expect(new Headers(fetchMock.mock.calls[2]?.[1]?.headers).get("X-CSRF-Token")).toBe(firstCsrf);
    expect(new Headers(fetchMock.mock.calls[2]?.[1]?.headers).get("X-Hasilan-Web-Session")).toBe("1");
    expect(new Headers(fetchMock.mock.calls[3]?.[1]?.headers).get("Authorization")).toBe("Bearer rotated-access-token");
  });

  it("resumes with the HttpOnly cookie and keeps the access token out of storage", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstWebSession, 200, rotatedCsrf));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient();
    const record: WebSessionRecord = {
      accountId: firstSession.accountId,
      email: "alice@example.test",
      deviceId: firstSession.deviceId,
      csrfToken: firstCsrf,
      kdf: firstSession.kdf,
      protectedUserKey: firstSession.protectedUserKey,
      rememberUnlock: false,
      manualLockSuppressed: false,
      updatedAt: Date.now(),
    };
    await client.restoreWebSession(record);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.credentials).toBe("same-origin");
    expect(new Headers(init?.headers).get("X-Hasilan-Web-Session")).toBe("1");
    expect(new Headers(init?.headers).get("X-CSRF-Token")).toBe(firstCsrf);
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
    expect(JSON.stringify(localStorage)).not.toContain("first-access-token");
    expect(client.csrfToken).toBe(rotatedCsrf);
  });

  it("keeps the in-memory session when refresh cannot reach the server", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstWebSession, 200, firstCsrf))
      .mockResolvedValueOnce(jsonResponse({ code: "unauthorized", message: "Unauthorized", requestId: null }, 401))
      .mockRejectedValueOnce(new TypeError("offline"));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient();
    const lost = vi.fn();
    client.setSessionLostHandler(lost);
    await client.login({
      email: "alice@example.test",
      authProof: "proof",
      device: { identifier: crypto.randomUUID(), name: "test", deviceType: "web" },
      totpCode: null,
      recoveryCode: null,
      trustedDeviceToken: null,
      rememberDevice: false,
    });

    await expect(client.listSessions()).rejects.toThrow("offline");
    expect(client.session).not.toBeNull();
    expect(lost).not.toHaveBeenCalled();
  });

  it("reports the rejected session identity before clearing it", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(firstWebSession, 200, firstCsrf))
      .mockResolvedValueOnce(jsonResponse({ code: "unauthorized", message: "Unauthorized", requestId: null }, 401))
      .mockResolvedValueOnce(jsonResponse({ code: "unauthorized", message: "Unauthorized", requestId: null }, 401));
    vi.stubGlobal("fetch", fetchMock);
    const client = new ApiClient();
    const lost = vi.fn();
    client.setSessionLostHandler(lost);
    await client.login({
      email: "alice@example.test",
      authProof: "proof",
      device: { identifier: crypto.randomUUID(), name: "test", deviceType: "web" },
      totpCode: null,
      recoveryCode: null,
      trustedDeviceToken: null,
      rememberDevice: false,
    });

    await expect(client.listSessions()).rejects.toThrow("Unauthorized");
    expect(lost).toHaveBeenCalledWith(expect.objectContaining({
      accountId: firstSession.accountId,
      deviceId: firstSession.deviceId,
    }));
    expect(client.session).toBeNull();
  });
});

function jsonResponse(value: unknown, status = 200, csrf?: string): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...(csrf === undefined ? {} : { "X-CSRF-Token": csrf }),
    },
  });
}
