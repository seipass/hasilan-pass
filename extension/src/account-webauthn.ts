type JsonObject = Record<string, unknown>;

/** Executes a native account WebAuthn assertion from an extension page. */
export async function getAccountWebauthnCredential(options: JsonObject): Promise<JsonObject> {
  if (!window.isSecureContext || navigator.credentials === undefined || typeof PublicKeyCredential === "undefined") {
    throw new Error("This browser does not expose WebAuthn to the extension.");
  }
  const outer = cloneObject(options);
  const publicKey = object(outer.publicKey, "The server returned malformed WebAuthn options.");
  publicKey.challenge = decodeMember(publicKey.challenge);
  if (Array.isArray(publicKey.allowCredentials)) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((value) => {
      const descriptor = object(value, "A WebAuthn credential descriptor is malformed.");
      descriptor.id = decodeMember(descriptor.id);
      return descriptor;
    });
  }
  const mediation = typeof outer.mediation === "string"
    ? outer.mediation as CredentialMediationRequirement
    : undefined;
  const requested = await navigator.credentials.get({
    publicKey: publicKey as unknown as PublicKeyCredentialRequestOptions,
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

function decodeMember(value: unknown): ArrayBuffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value) || value.length > 8_192) {
    throw new Error("WebAuthn binary data is malformed.");
  }
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0)).buffer;
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function encodeExtensionValue(value: unknown): unknown {
  if (value instanceof ArrayBuffer) return encodeBase64Url(value);
  if (ArrayBuffer.isView(value)) {
    const copy = new Uint8Array(value.byteLength);
    copy.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    return encodeBase64Url(copy.buffer);
  }
  if (Array.isArray(value)) return value.map(encodeExtensionValue);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, member]) => [key, encodeExtensionValue(member)]));
  }
  return value;
}

function object(value: unknown, message: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(message);
  return value as JsonObject;
}

function cloneObject(value: JsonObject): JsonObject {
  return object(JSON.parse(JSON.stringify(value)) as unknown, "The WebAuthn options are malformed.");
}
