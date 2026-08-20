(() => {
  const PAGE_CHANNEL = "hasilan-pass-webauthn-page-v1";
  type BridgeResult =
    | { status: "fallback" }
    | { status: "error"; name: string; message: string }
    | { status: "created"; result: CreationResult }
    | { status: "asserted"; result: AssertionResult };
  interface CreationResult {
    credentialId: string;
    clientDataJSON: string;
    attestationObject: string;
    authenticatorData: string;
    publicKey: string;
    publicKeyAlgorithm: number;
    transports: string[];
    extensions: { credProps: { rk: boolean } };
  }
  interface AssertionResult {
    credentialId: string;
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  }

  const marker = "__hasilanPassWebauthnV1";
  const marked = globalThis as typeof globalThis & { [marker]?: boolean };
  if (marked[marker] === true || location.protocol === "chrome-extension:" || location.protocol === "moz-extension:") return;
  marked[marker] = true;

  const credentials = navigator.credentials;
  if (credentials === undefined) return;
  const nativeCreate = credentials.create.bind(credentials);
  const nativeGet = credentials.get.bind(credentials);

  try {
    credentials.create = async (options?: CredentialCreationOptions): Promise<Credential | null> => {
      if (options?.publicKey === undefined) return nativeCreate(options);
      const request = serializeCreation(options.publicKey);
      const response = await bridge("create", request, options.signal, options.publicKey.timeout);
      if (response.status === "fallback") return nativeCreate(options);
      if (response.status === "error") throw new DOMException(response.message, response.name);
      if (response.status !== "created") throw new DOMException("Invalid passkey response.", "UnknownError");
      return registrationCredential(response.result);
    };
    credentials.get = async (options?: CredentialRequestOptions): Promise<Credential | null> => {
      if (options?.publicKey === undefined || options.mediation === "conditional") return nativeGet(options);
      const request = serializeAssertion(options.publicKey, options.mediation);
      const response = await bridge("get", request, options.signal, options.publicKey.timeout);
      if (response.status === "fallback") return nativeGet(options);
      if (response.status === "error") throw new DOMException(response.message, response.name);
      if (response.status !== "asserted") throw new DOMException("Invalid passkey response.", "UnknownError");
      return assertionCredential(response.result);
    };
  } catch {
    credentials.create = nativeCreate;
    credentials.get = nativeGet;
  }

  function serializeCreation(options: PublicKeyCredentialCreationOptions): Record<string, unknown> {
    return {
      challenge: encode(options.challenge),
      rp: { id: options.rp.id, name: options.rp.name },
      user: {
        id: encode(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams.map((parameter) => ({
        alg: Number(parameter.alg),
        type: parameter.type,
      })),
      excludeCredentials: options.excludeCredentials?.map(descriptor) ?? [],
      authenticatorSelection: options.authenticatorSelection === undefined ? undefined : {
        authenticatorAttachment: options.authenticatorSelection.authenticatorAttachment,
        requireResidentKey: options.authenticatorSelection.requireResidentKey,
        residentKey: options.authenticatorSelection.residentKey,
        userVerification: options.authenticatorSelection.userVerification,
      },
      attestation: options.attestation,
      extensions: { credProps: options.extensions?.credProps === true },
    };
  }

  function serializeAssertion(
    options: PublicKeyCredentialRequestOptions,
    mediation: CredentialMediationRequirement | undefined,
  ): Record<string, unknown> {
    return {
      challenge: encode(options.challenge),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map(descriptor) ?? [],
      userVerification: options.userVerification,
      mediation,
    };
  }

  function descriptor(value: PublicKeyCredentialDescriptor): Record<string, unknown> {
    return {
      id: encode(value.id),
      type: value.type,
      transports: value.transports ?? [],
    };
  }

  function bridge(
    type: "create" | "get",
    options: Record<string, unknown>,
    signal: AbortSignal | undefined,
    requestedTimeout: number | undefined,
  ): Promise<BridgeResult> {
    if (signal?.aborted === true) return Promise.reject(abortError());
    const channel = new MessageChannel();
    const timeout = Math.min(Math.max(requestedTimeout ?? 180_000, 30_000), 300_000);
    return new Promise<BridgeResult>((resolve, reject) => {
      let finished = false;
      const timer = globalThis.setTimeout(() => finish(() => reject(new DOMException(
        "The operation either timed out or was not allowed.",
        "NotAllowedError",
      ))), timeout);
      const abort = () => finish(() => reject(abortError()));
      const finish = (complete: () => void) => {
        if (finished) return;
        finished = true;
        globalThis.clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        channel.port1.close();
        complete();
      };
      signal?.addEventListener("abort", abort, { once: true });
      channel.port1.onmessage = (event: MessageEvent<BridgeResult>) => finish(() => resolve(event.data));
      window.postMessage({ channel: PAGE_CHANNEL, type, options }, location.origin, [channel.port2]);
    });
  }

  function registrationCredential(result: CreationResult): PublicKeyCredential {
    const response = {
      clientDataJSON: decode(result.clientDataJSON),
      attestationObject: decode(result.attestationObject),
      getAuthenticatorData: () => decode(result.authenticatorData),
      getPublicKey: () => decode(result.publicKey),
      getPublicKeyAlgorithm: () => result.publicKeyAlgorithm,
      getTransports: () => [...result.transports],
    } as AuthenticatorAttestationResponse;
    setPrototype(response, globalThis.AuthenticatorAttestationResponse?.prototype);
    const credential = {
      id: result.credentialId,
      rawId: decode(result.credentialId),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => result.extensions,
      toJSON: () => ({
        id: result.credentialId,
        rawId: result.credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: result.clientDataJSON,
          attestationObject: result.attestationObject,
          authenticatorData: result.authenticatorData,
          publicKey: result.publicKey,
          publicKeyAlgorithm: result.publicKeyAlgorithm,
          transports: result.transports,
        },
        clientExtensionResults: result.extensions,
      }),
    } as PublicKeyCredential;
    setPrototype(credential, globalThis.PublicKeyCredential?.prototype);
    return credential;
  }

  function assertionCredential(result: AssertionResult): PublicKeyCredential {
    const response = {
      clientDataJSON: decode(result.clientDataJSON),
      authenticatorData: decode(result.authenticatorData),
      signature: decode(result.signature),
      userHandle: result.userHandle === null ? null : decode(result.userHandle),
    } as AuthenticatorAssertionResponse;
    setPrototype(response, globalThis.AuthenticatorAssertionResponse?.prototype);
    const credential = {
      id: result.credentialId,
      rawId: decode(result.credentialId),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: result.credentialId,
        rawId: result.credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: result.clientDataJSON,
          authenticatorData: result.authenticatorData,
          signature: result.signature,
          userHandle: result.userHandle,
        },
        clientExtensionResults: {},
      }),
    } as PublicKeyCredential;
    setPrototype(credential, globalThis.PublicKeyCredential?.prototype);
    return credential;
  }

  function encode(source: BufferSource): string {
    const bytes = source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  }

  function decode(value: string): ArrayBuffer {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return bytes.buffer;
  }

  function setPrototype(value: object, prototype: object | undefined): void {
    if (prototype === undefined) return;
    try {
      Object.setPrototypeOf(value, prototype);
    } catch {
      // The structural WebAuthn response remains usable when a browser freezes prototypes.
    }
  }

  function abortError(): DOMException {
    return new DOMException("The operation was aborted.", "AbortError");
  }
})();
