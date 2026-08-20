import type {
  AttachmentResponse,
  EncryptedObject,
  KdfSettings,
  OrganizationResponse,
  SharingKeyMaterial,
  SharingKeyResponse,
  SyncResponse,
  TokenResponse,
  WebauthnChallengeResponse,
} from "./types";

interface ErrorBody {
  code?: string;
  message?: string;
  requestId?: string | null;
}

export class ExtensionApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ExtensionApiError";
    this.status = status;
    this.code = code;
  }
}

export class ExtensionApi {
  #serverUrl: string | null = null;
  #session: TokenResponse | null = null;
  #refreshing: Promise<void> | null = null;
  #onSessionLost: (() => void) | null = null;

  get accountId(): string | null {
    return this.#session?.accountId ?? null;
  }

  get session(): TokenResponse | null {
    return this.#session;
  }

  configure(serverUrl: string): void {
    this.#serverUrl = normalizeServerUrl(serverUrl);
  }

  setSessionLostHandler(handler: () => void): void {
    this.#onSessionLost = handler;
  }

  clearSession(): void {
    this.#session = null;
  }

  async prelogin(email: string): Promise<KdfSettings> {
    const response = await this.#request<{ kdf: KdfSettings }>("/auth/prelogin", "POST", JSON.stringify({ email }), false);
    return response.kdf;
  }

  async register(body: string): Promise<void> {
    await this.#request("/auth/register", "POST", body, false);
  }

  async login(body: string): Promise<TokenResponse> {
    const session = await this.#request<TokenResponse>("/auth/login", "POST", body, false);
    this.#session = session;
    return session;
  }

  async startWebauthnMfaLogin(body: string): Promise<WebauthnChallengeResponse> {
    return this.#request("/auth/login/webauthn/start", "POST", body, false);
  }

  async startPasskeyLogin(body: string): Promise<WebauthnChallengeResponse> {
    return this.#request("/auth/passkey/start", "POST", body, false);
  }

  async finishWebauthnLogin(body: string): Promise<TokenResponse> {
    const session = await this.#request<TokenResponse>("/auth/webauthn/finish", "POST", body, false);
    this.#session = session;
    return session;
  }

  async sync(cursor: string | null): Promise<SyncResponse> {
    const query = new URLSearchParams({ limit: "500" });
    if (cursor !== null) query.set("cursor", cursor);
    return this.#request(`/sync?${query.toString()}`, "GET", undefined, true);
  }

  async putObject(id: string, body: string): Promise<EncryptedObject> {
    return this.#request(`/vault/objects/${encodeURIComponent(id)}`, "PUT", body, true);
  }

  async deleteObject(id: string, body: string): Promise<EncryptedObject> {
    return this.#request(`/vault/objects/${encodeURIComponent(id)}`, "DELETE", body, true);
  }

  async initiateAttachment(body: string): Promise<AttachmentResponse> {
    return this.#request("/attachments", "POST", body, true);
  }

  async attachmentStatus(id: string): Promise<AttachmentResponse> {
    return this.#request(`/attachments/${encodeURIComponent(id)}`, "GET", undefined, true);
  }

  async putAttachmentChunk(id: string, index: number, ciphertext: Uint8Array): Promise<void> {
    await this.#binaryRequest(`/attachments/${encodeURIComponent(id)}/chunks/${index}`, "PUT", ciphertext);
  }

  async completeAttachment(id: string, objectRevision: number): Promise<AttachmentResponse> {
    return this.#request(
      `/attachments/${encodeURIComponent(id)}/complete`,
      "POST",
      JSON.stringify({ objectRevision }),
      true,
    );
  }

  async attachmentChunk(id: string, index: number): Promise<Uint8Array> {
    const response = await this.#binaryRequest(
      `/attachments/${encodeURIComponent(id)}/chunks/${index}`,
      "GET",
    );
    return new Uint8Array(await response.arrayBuffer());
  }

  async deleteAttachment(id: string): Promise<void> {
    await this.#request(`/attachments/${encodeURIComponent(id)}`, "DELETE", undefined, true);
  }

  async sharingKey(): Promise<SharingKeyResponse> {
    return this.#request("/account/sharing-key", "GET", undefined, true);
  }

  async putSharingKey(material: SharingKeyMaterial): Promise<SharingKeyResponse> {
    return this.#request(
      "/account/sharing-key",
      "PUT",
      JSON.stringify(material),
      true,
    );
  }

  async organizations(): Promise<OrganizationResponse[]> {
    return this.#request("/organizations", "GET", undefined, true);
  }

  async logout(): Promise<void> {
    const refreshToken = this.#session?.refreshToken ?? null;
    try {
      if (this.#session !== null) {
        await this.#request("/auth/logout", "POST", JSON.stringify({ refreshToken }), true, false);
      }
    } finally {
      this.clearSession();
    }
  }

  async refresh(): Promise<void> {
    if (this.#refreshing !== null) return this.#refreshing;
    const refreshToken = this.#session?.refreshToken;
    if (refreshToken === undefined) throw new Error("The extension session is locked.");
    this.#refreshing = (async () => {
      try {
        const session = await this.#request<TokenResponse>(
          "/auth/refresh",
          "POST",
          JSON.stringify({ refreshToken }),
          false,
        );
        this.#session = session;
      } catch (error) {
        this.#session = null;
        this.#onSessionLost?.();
        throw error;
      } finally {
        this.#refreshing = null;
      }
    })();
    return this.#refreshing;
  }

  async #request<T>(
    path: string,
    method: "GET" | "POST" | "PUT" | "DELETE",
    body: string | undefined,
    authenticated: boolean,
    retry = true,
  ): Promise<T> {
    if (this.#serverUrl === null) throw new Error("Configure a Hasilan Pass server first.");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    let response: Response;
    try {
      response = await fetch(`${this.#serverUrl}/api/v1${path}`, {
        method,
        headers: {
          Accept: "application/json",
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(authenticated && this.#session !== null
            ? { Authorization: `Bearer ${this.#session.accessToken}` }
            : {}),
        },
        ...(body === undefined ? {} : { body }),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
    if (response.status === 401 && authenticated && retry && this.#session !== null) {
      await this.refresh();
      return this.#request(path, method, body, authenticated, false);
    }
    if (!response.ok) throw await responseError(response);
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  async #binaryRequest(
    path: string,
    method: "GET" | "PUT",
    body?: Uint8Array,
    retry = true,
  ): Promise<Response> {
    if (this.#serverUrl === null) throw new Error("Configure a Hasilan Pass server first.");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    let response: Response;
    try {
      response = await fetch(`${this.#serverUrl}/api/v1${path}`, {
        method,
        headers: {
          Accept: "application/octet-stream",
          ...(body === undefined ? {} : { "Content-Type": "application/octet-stream" }),
          ...(this.#session === null ? {} : { Authorization: `Bearer ${this.#session.accessToken}` }),
        },
        ...(body === undefined ? {} : { body: body as BodyInit }),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
    if (response.status === 401 && retry && this.#session !== null) {
      await this.refresh();
      return this.#binaryRequest(path, method, body, false);
    }
    if (!response.ok) throw await responseError(response);
    return response;
  }
}

export function normalizeServerUrl(value: string): string {
  const url = new URL(value.trim());
  if (!matchesSecureServerPolicy(url)) {
    throw new Error("Use an HTTPS server URL (HTTP is allowed only for localhost development).");
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new Error("The server URL must not contain credentials, query parameters, or a fragment.");
  }
  url.pathname = "";
  return url.origin;
}

function matchesSecureServerPolicy(url: URL): boolean {
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:") return false;
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
}

async function responseError(response: Response): Promise<ExtensionApiError> {
  let body: ErrorBody = {};
  try {
    body = (await response.json()) as ErrorBody;
  } catch {
    // Reverse proxies do not always preserve structured API error bodies.
  }
  return new ExtensionApiError(
    response.status,
    typeof body.code === "string" ? body.code : "request_failed",
    typeof body.message === "string" ? body.message : `Server request failed (${response.status}).`,
  );
}
