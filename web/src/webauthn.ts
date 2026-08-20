type JsonObject = Record<string, unknown>;

export async function createWebauthnCredential(options: JsonObject): Promise<JsonObject> {
  ensureWebauthnAvailable();
  const publicKey = decodeCreationOptions(options);
  const created = await navigator.credentials.create({ publicKey });
  if (!(created instanceof PublicKeyCredential)) {
    throw new Error("The authenticator did not return a public-key credential.");
  }
  const response = created.response as AuthenticatorAttestationResponse;
  const transports = typeof response.getTransports === "function" ? response.getTransports() : [];
  return {
    id: created.id,
    rawId: encodeBase64Url(created.rawId),
    response: {
      attestationObject: encodeBase64Url(response.attestationObject),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      transports,
    },
    type: created.type,
    extensions: encodeExtensionValue(created.getClientExtensionResults()),
  };
}

export async function getWebauthnCredential(options: JsonObject): Promise<JsonObject> {
  ensureWebauthnAvailable();
  const { publicKey, mediation } = decodeRequestOptions(options);
  const requested = await navigator.credentials.get({
    publicKey,
    ...(mediation === undefined ? {} : { mediation }),
  });
  if (!(requested instanceof PublicKeyCredential)) {
    throw new Error("The authenticator did not return a public-key credential.");
  }
  const response = requested.response as AuthenticatorAssertionResponse;
  return {
    id: requested.id,
    rawId: encodeBase64Url(requested.rawId),
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle === null ? null : encodeBase64Url(response.userHandle),
    },
    type: requested.type,
    extensions: encodeExtensionValue(requested.getClientExtensionResults()),
  };
}

function decodeCreationOptions(options: JsonObject): PublicKeyCredentialCreationOptions {
  const outer = cloneObject(options);
  const publicKey = object(outer.publicKey, "WebAuthn creation options are malformed.");
  publicKey.challenge = decodeMember(publicKey.challenge);
  const user = object(publicKey.user, "WebAuthn user options are malformed.");
  user.id = decodeMember(user.id);
  publicKey.user = user;
  if (Array.isArray(publicKey.excludeCredentials)) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map(decodeDescriptor);
  }
  return publicKey as unknown as PublicKeyCredentialCreationOptions;
}

function decodeRequestOptions(options: JsonObject): {
  publicKey: PublicKeyCredentialRequestOptions;
  mediation: CredentialMediationRequirement | undefined;
} {
  const outer = cloneObject(options);
  const publicKey = object(outer.publicKey, "WebAuthn request options are malformed.");
  publicKey.challenge = decodeMember(publicKey.challenge);
  if (Array.isArray(publicKey.allowCredentials)) {
    publicKey.allowCredentials = publicKey.allowCredentials.map(decodeDescriptor);
  }
  const mediation = typeof outer.mediation === "string"
    ? outer.mediation as CredentialMediationRequirement
    : undefined;
  return { publicKey: publicKey as unknown as PublicKeyCredentialRequestOptions, mediation };
}

function decodeDescriptor(value: unknown): JsonObject {
  const descriptor = object(value, "WebAuthn credential descriptor is malformed.");
  descriptor.id = decodeMember(descriptor.id);
  return descriptor;
}

function decodeMember(value: unknown): ArrayBuffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error("WebAuthn binary data is malformed.");
  }
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = atob(padded);
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  return bytes.buffer;
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function encodeExtensionValue(value: unknown): unknown {
  if (value instanceof ArrayBuffer) return encodeBase64Url(value);
  if (ArrayBuffer.isView(value)) {
    const bytes = new Uint8Array(value.byteLength);
    bytes.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    return encodeBase64Url(bytes.buffer);
  }
  if (Array.isArray(value)) return value.map(encodeExtensionValue);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([key, member]) => [key, encodeExtensionValue(member)]),
    );
  }
  return value;
}

function ensureWebauthnAvailable(): void {
  if (!window.isSecureContext || navigator.credentials === undefined || typeof PublicKeyCredential === "undefined") {
    throw new Error("Passkeys require a secure browser context with WebAuthn support.");
  }
}

function object(value: unknown, message: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(message);
  return value as JsonObject;
}

function cloneObject(value: JsonObject): JsonObject {
  return object(JSON.parse(JSON.stringify(value)) as unknown, "WebAuthn options are malformed.");
}
