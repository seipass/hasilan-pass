import type {
  ApiErrorBody,
  AttachmentResponse,
  DeviceResponse,
  EncryptedObject,
  KdfSettings,
  LoginRequest,
  MfaEnableResponse,
  MfaStatusResponse,
  RegisterRequest,
  SharingKeyMaterial,
  SharingKeyResponse,
  OrganizationResponse,
  OrganizationRole,
  OrganizationMemberResponse,
  OrganizationInviteResponse,
  CollectionResponse,
  TotpSetupStartResponse,
  WebauthnChallengeResponse,
  SessionResponse,
  SyncResponse,
  TokenResponse,
} from "./types";

const API_PREFIX = "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.name = "ApiError";
    this.status = status;
    this.code = body.code;
    this.requestId = body.requestId;
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: string;
  authenticated?: boolean;
  retryAfterRefresh?: boolean;
  webSession?: boolean;
  csrf?: boolean;
  captureCsrf?: boolean;
}

export class ApiClient {
  #session: TokenResponse | null = null;
  #refreshing: Promise<void> | null = null;
  #onSessionLost: (() => void) | null = null;
  #csrfToken: string | null = null;

  get session(): TokenResponse | null {
    return this.#session;
  }

  setSessionLostHandler(handler: () => void): void {
    this.#onSessionLost = handler;
  }

  clearSession(): void {
    this.#session = null;
    this.#csrfToken = null;
  }

  adoptSession(session: TokenResponse): void {
    this.#session = session;
  }

  async prelogin(email: string): Promise<KdfSettings> {
    const response = await this.#request<{ kdf: KdfSettings }>("/auth/prelogin", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
    return response.kdf;
  }

  async register(request: RegisterRequest): Promise<{ accountId: string }> {
    return this.#request("/auth/register", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  async login(request: LoginRequest): Promise<TokenResponse> {
    const session = await this.#request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(request),
      webSession: true,
      captureCsrf: true,
    });
    this.adoptSession(session);
    return session;
  }

  async startWebauthnMfaLogin(request: {
    email: string;
    authProof: string;
    device: DeviceResponseRequest;
  }): Promise<WebauthnChallengeResponse> {
    return this.#request("/auth/login/webauthn/start", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  async startPasskeyLogin(request: {
    email: string;
    device: DeviceResponseRequest;
  }): Promise<WebauthnChallengeResponse> {
    return this.#request("/auth/passkey/start", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  async finishWebauthnLogin(request: {
    ceremonyId: string;
    credential: Record<string, unknown>;
    rememberDevice: boolean;
  }): Promise<TokenResponse> {
    const session = await this.#request<TokenResponse>("/auth/webauthn/finish", {
      method: "POST",
      body: JSON.stringify(request),
      webSession: true,
      captureCsrf: true,
    });
    this.adoptSession(session);
    return session;
  }

  async refresh(): Promise<void> {
    if (this.#refreshing !== null) {
      return this.#refreshing;
    }
    if (this.#session === null || this.#csrfToken === null) {
      throw new Error("No active session to refresh.");
    }
    this.#refreshing = (async () => {
      try {
        const session = await this.#request<TokenResponse>("/auth/refresh", {
          method: "POST",
          body: JSON.stringify({ refreshToken: "" }),
          webSession: true,
          csrf: true,
          captureCsrf: true,
        });
        this.adoptSession(session);
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

  async logout(): Promise<void> {
    try {
      if (this.#session !== null) {
        await this.#request<void>("/auth/logout", {
          method: "POST",
          body: JSON.stringify({ refreshToken: null }),
          authenticated: true,
          retryAfterRefresh: false,
          webSession: true,
          csrf: true,
        });
      }
    } finally {
      this.clearSession();
    }
  }

  async sync(cursor: string | null): Promise<SyncResponse> {
    const query = new URLSearchParams({ limit: "500" });
    if (cursor !== null) {
      query.set("cursor", cursor);
    }
    return this.#request(`/sync?${query.toString()}`, { authenticated: true });
  }

  async putEncryptedObject(id: string, requestJson: string): Promise<EncryptedObject> {
    return this.#request(`/vault/objects/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: requestJson,
      authenticated: true,
    });
  }

  async deleteEncryptedObject(id: string, requestJson: string): Promise<EncryptedObject> {
    return this.#request(`/vault/objects/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: requestJson,
      authenticated: true,
    });
  }

  async initiateAttachment(requestJson: string): Promise<AttachmentResponse> {
    return this.#request("/attachments", {
      method: "POST",
      body: requestJson,
      authenticated: true,
    });
  }

  async attachmentStatus(id: string): Promise<AttachmentResponse> {
    return this.#request(`/attachments/${encodeURIComponent(id)}`, { authenticated: true });
  }

  async listAttachments(objectId: string): Promise<AttachmentResponse[]> {
    return this.#request(`/vault/objects/${encodeURIComponent(objectId)}/attachments`, {
      authenticated: true,
    });
  }

  async putAttachmentChunk(id: string, index: number, ciphertext: Uint8Array): Promise<void> {
    await this.#binaryRequest(
      `/attachments/${encodeURIComponent(id)}/chunks/${index}`,
      "PUT",
      ciphertext,
    );
  }

  async completeAttachment(id: string, objectRevision: number): Promise<AttachmentResponse> {
    return this.#request(`/attachments/${encodeURIComponent(id)}/complete`, {
      method: "POST",
      body: JSON.stringify({ objectRevision }),
      authenticated: true,
    });
  }

  async attachmentChunk(id: string, index: number): Promise<Uint8Array> {
    const response = await this.#binaryRequest(
      `/attachments/${encodeURIComponent(id)}/chunks/${index}`,
      "GET",
    );
    return new Uint8Array(await response.arrayBuffer());
  }

  async deleteAttachment(id: string): Promise<void> {
    await this.#request(`/attachments/${encodeURIComponent(id)}`, {
      method: "DELETE",
      authenticated: true,
    });
  }

  async sharingKey(): Promise<SharingKeyResponse> {
    return this.#request("/account/sharing-key", { authenticated: true });
  }

  async putSharingKey(material: SharingKeyMaterial): Promise<SharingKeyResponse> {
    return this.#request("/account/sharing-key", {
      method: "PUT",
      body: JSON.stringify(material),
      authenticated: true,
    });
  }

  async lookupSharingKey(email: string): Promise<SharingKeyResponse> {
    const query = new URLSearchParams({ email });
    return this.#request(`/directory/sharing-key?${query.toString()}`, { authenticated: true });
  }

  async listOrganizations(): Promise<OrganizationResponse[]> {
    return this.#request("/organizations", { authenticated: true });
  }

  async createOrganization(request: {
    id: string;
    name: string;
    encryptedOrganizationKey: string;
  }): Promise<OrganizationResponse> {
    return this.#request("/organizations", {
      method: "POST",
      body: JSON.stringify(request),
      authenticated: true,
    });
  }

  async inviteOrganizationMember(
    organizationId: string,
    request: { email: string; role: OrganizationRole; encryptedOrganizationKey: string },
  ): Promise<OrganizationInviteResponse> {
    return this.#request(`/organizations/${encodeURIComponent(organizationId)}/invitations`, {
      method: "POST",
      body: JSON.stringify(request),
      authenticated: true,
    });
  }

  async acceptOrganizationInvitation(invitationToken: string): Promise<OrganizationMemberResponse> {
    return this.#request("/organizations/invitations/accept", {
      method: "POST",
      body: JSON.stringify({ invitationToken }),
      authenticated: true,
    });
  }

  async listOrganizationMembers(organizationId: string): Promise<OrganizationMemberResponse[]> {
    return this.#request(`/organizations/${encodeURIComponent(organizationId)}/members`, {
      authenticated: true,
    });
  }

  async confirmOrganizationMember(
    organizationId: string,
    memberId: string,
  ): Promise<OrganizationMemberResponse> {
    return this.#request(
      `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(memberId)}/confirm`,
      { method: "POST", authenticated: true },
    );
  }

  async changeOrganizationMemberRole(
    organizationId: string,
    memberId: string,
    role: OrganizationRole,
  ): Promise<OrganizationMemberResponse> {
    return this.#request(
      `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(memberId)}/role`,
      { method: "PUT", body: JSON.stringify({ role }), authenticated: true },
    );
  }

  async removeOrganizationMember(organizationId: string, memberId: string): Promise<void> {
    await this.#request(
      `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(memberId)}`,
      { method: "DELETE", authenticated: true },
    );
  }

  async listCollections(organizationId: string): Promise<CollectionResponse[]> {
    return this.#request(`/organizations/${encodeURIComponent(organizationId)}/collections`, {
      authenticated: true,
    });
  }

  async createCollection(organizationId: string, name: string): Promise<CollectionResponse> {
    return this.#request(`/organizations/${encodeURIComponent(organizationId)}/collections`, {
      method: "POST",
      body: JSON.stringify({ name }),
      authenticated: true,
    });
  }

  async putCollectionAccess(
    organizationId: string,
    collectionId: string,
    request: {
      memberId: string;
      readOnly: boolean;
      hidePasswords: boolean;
      manage: boolean;
    },
  ): Promise<void> {
    await this.#request(
      `/organizations/${encodeURIComponent(organizationId)}/collections/${encodeURIComponent(collectionId)}/access/${encodeURIComponent(request.memberId)}`,
      { method: "PUT", body: JSON.stringify(request), authenticated: true },
    );
  }

  async deleteCollectionAccess(
    organizationId: string,
    collectionId: string,
    memberId: string,
  ): Promise<void> {
    await this.#request(
      `/organizations/${encodeURIComponent(organizationId)}/collections/${encodeURIComponent(collectionId)}/access/${encodeURIComponent(memberId)}`,
      { method: "DELETE", authenticated: true },
    );
  }

  async listSessions(): Promise<SessionResponse[]> {
    return this.#request("/account/sessions", { authenticated: true });
  }

  async revokeSession(id: string): Promise<void> {
    await this.#request(`/account/sessions/${encodeURIComponent(id)}`, {
      method: "DELETE",
      authenticated: true,
    });
  }

  async listDevices(): Promise<DeviceResponse[]> {
    return this.#request("/account/devices", { authenticated: true });
  }

  async accountSecurity(): Promise<MfaStatusResponse> {
    return this.#request("/account/security", { authenticated: true });
  }

  async startTotpSetup(authProof: string): Promise<TotpSetupStartResponse> {
    return this.#request("/account/security/totp/start", {
      method: "POST",
      body: JSON.stringify({ authProof }),
      authenticated: true,
    });
  }

  async finishTotpSetup(setupId: string, code: string): Promise<MfaEnableResponse> {
    return this.#request("/account/security/totp/finish", {
      method: "POST",
      body: JSON.stringify({ setupId, code }),
      authenticated: true,
    });
  }

  async disableTotp(authProof: string): Promise<void> {
    await this.#request("/account/security/totp", {
      method: "DELETE",
      body: JSON.stringify({ authProof }),
      authenticated: true,
    });
  }

  async rotateRecoveryCodes(authProof: string): Promise<{ codes: string[] }> {
    return this.#request("/account/security/recovery-codes/rotate", {
      method: "POST",
      body: JSON.stringify({ authProof }),
      authenticated: true,
    });
  }

  async startWebauthnRegistration(
    authProof: string,
    name: string,
  ): Promise<WebauthnChallengeResponse> {
    return this.#request("/account/security/webauthn/start", {
      method: "POST",
      body: JSON.stringify({ authProof, name }),
      authenticated: true,
    });
  }

  async finishWebauthnRegistration(
    ceremonyId: string,
    credential: Record<string, unknown>,
  ): Promise<MfaEnableResponse> {
    return this.#request("/account/security/webauthn/finish", {
      method: "POST",
      body: JSON.stringify({ ceremonyId, credential }),
      authenticated: true,
    });
  }

  async deleteWebauthnCredential(id: string): Promise<void> {
    await this.#request(`/account/security/webauthn/${encodeURIComponent(id)}`, {
      method: "DELETE",
      authenticated: true,
    });
  }

  async revokeDeviceTrust(id: string): Promise<void> {
    await this.#request(`/account/devices/${encodeURIComponent(id)}/trust`, {
      method: "DELETE",
      authenticated: true,
    });
  }

  async #request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const authenticated = options.authenticated ?? false;
    if (options.csrf === true && this.#csrfToken === null) {
      throw new Error("The Web session CSRF token is unavailable.");
    }
    const response = await fetch(`${API_PREFIX}${path}`, {
      method: options.method ?? "GET",
      headers: {
        Accept: "application/json",
        ...(options.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(authenticated && this.#session !== null
          ? { Authorization: `Bearer ${this.#session.accessToken}` }
          : {}),
        ...(options.webSession === true ? { "X-Hasilan-Web-Session": "1" } : {}),
        ...(options.csrf === true && this.#csrfToken !== null
          ? { "X-CSRF-Token": this.#csrfToken }
          : {}),
      },
      ...(options.body === undefined ? {} : { body: options.body }),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(30_000),
    });

    if (
      response.status === 401 &&
      authenticated &&
      (options.retryAfterRefresh ?? true) &&
      this.#session !== null
    ) {
      await this.refresh();
      return this.#request(path, { ...options, retryAfterRefresh: false });
    }

    if (!response.ok) {
      throw await apiError(response);
    }
    if (options.captureCsrf === true) {
      const csrfToken = response.headers.get("x-csrf-token");
      if (csrfToken === null || !/^[A-Za-z0-9_-]{32,256}$/u.test(csrfToken)) {
        throw new Error("The server did not establish a valid Web session.");
      }
      this.#csrfToken = csrfToken;
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  async #binaryRequest(
    path: string,
    method: "GET" | "PUT",
    body?: Uint8Array,
    retryAfterRefresh = true,
  ): Promise<Response> {
    const response = await fetch(`${API_PREFIX}${path}`, {
      method,
      headers: {
        Accept: "application/octet-stream",
        ...(body === undefined ? {} : { "Content-Type": "application/octet-stream" }),
        ...(this.#session === null ? {} : { Authorization: `Bearer ${this.#session.accessToken}` }),
      },
      ...(body === undefined ? {} : { body: body as BodyInit }),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(120_000),
    });
    if (response.status === 401 && retryAfterRefresh && this.#session !== null) {
      await this.refresh();
      return this.#binaryRequest(path, method, body, false);
    }
    if (!response.ok) throw await apiError(response);
    return response;
  }
}

type DeviceResponseRequest = LoginRequest["device"];

async function apiError(response: Response): Promise<ApiError> {
  let body: ApiErrorBody = {
    code: "request_failed",
    message: `Request failed (${response.status}).`,
    requestId: response.headers.get("x-request-id"),
  };
  try {
    const parsed = (await response.json()) as Partial<ApiErrorBody>;
    if (typeof parsed.code === "string" && typeof parsed.message === "string") {
      body = {
        code: parsed.code,
        message: parsed.message,
        requestId:
          typeof parsed.requestId === "string" ? parsed.requestId : body.requestId,
      };
    }
  } catch {
    // A proxy may have replaced the structured API body; retain the safe fallback.
  }
  return new ApiError(response.status, body);
}
