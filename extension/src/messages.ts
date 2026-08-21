import type { LoginDraft, PasskeyAssertionOptionsJson, PasskeyCreationOptionsJson } from "./types";

export const MESSAGE_CHANNEL = "hasilan-pass-extension-v1" as const;

export type ExtensionRequest =
  | { channel: typeof MESSAGE_CHANNEL; type: "GET_STATE" }
  | { channel: typeof MESSAGE_CHANNEL; type: "LOGIN"; serverUrl: string; email: string; password: string; secondFactor: string | null; rememberDevice: boolean; rememberUnlock: boolean }
  | { channel: typeof MESSAGE_CHANNEL; type: "UNLOCK"; email: string; password: string; rememberUnlock: boolean }
  | { channel: typeof MESSAGE_CHANNEL; type: "REGISTER"; serverUrl: string; email: string; password: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "START_ACCOUNT_WEBAUTHN"; mode: "passkey" | "mfa"; serverUrl: string; email: string; password: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "FINISH_ACCOUNT_WEBAUTHN"; ceremonyId: string; credential: Record<string, unknown>; rememberDevice: boolean; rememberUnlock: boolean }
  | { channel: typeof MESSAGE_CHANNEL; type: "LOCK" }
  | { channel: typeof MESSAGE_CHANNEL; type: "SET_AUTO_LOCK"; minutes: number | null }
  | { channel: typeof MESSAGE_CHANNEL; type: "SET_REMEMBER_UNLOCK"; enabled: boolean }
  | { channel: typeof MESSAGE_CHANNEL; type: "LOGOUT" }
  | { channel: typeof MESSAGE_CHANNEL; type: "SYNC" }
  | { channel: typeof MESSAGE_CHANNEL; type: "LIST_ITEMS"; query: string; category: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "GET_ITEM"; id: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "CREATE_LOGIN"; draft: LoginDraft }
  | { channel: typeof MESSAGE_CHANNEL; type: "UPDATE_LOGIN"; id: string; draft: LoginDraft }
  | { channel: typeof MESSAGE_CHANNEL; type: "DELETE_ITEM"; id: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "ATTACHMENT_BEGIN"; itemId: string; attachmentId: string | null; fileName: string; mediaType: string; size: number }
  | { channel: typeof MESSAGE_CHANNEL; type: "ATTACHMENT_UPLOAD_CHUNK"; itemId: string; attachmentId: string; index: number; plaintext: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "ATTACHMENT_COMPLETE"; itemId: string; attachmentId: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "ATTACHMENT_DOWNLOAD_CHUNK"; itemId: string; attachmentId: string; index: number }
  | { channel: typeof MESSAGE_CHANNEL; type: "ATTACHMENT_REMOVE"; itemId: string; attachmentId: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "TOTP"; id: string; unixSeconds: number }
  | { channel: typeof MESSAGE_CHANNEL; type: "GENERATE_PASSWORD"; options: Record<string, unknown> }
  | { channel: typeof MESSAGE_CHANNEL; type: "GENERATE_USERNAME"; options: Record<string, unknown> }
  | { channel: typeof MESSAGE_CHANNEL; type: "CREDENTIALS_FOR_PAGE"; pageUrl: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "FILL_CREDENTIAL"; id: string; pageUrl: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "CAPTURE_CREDENTIAL"; pageUrl: string; username: string | null; password: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "SAVE_PENDING"; existingId: string | null }
  | { channel: typeof MESSAGE_CHANNEL; type: "DISMISS_PENDING" }
  | { channel: typeof MESSAGE_CHANNEL; type: "REGISTER_SITE"; matchPattern: string; tabId: number }
  | { channel: typeof MESSAGE_CHANNEL; type: "PASSKEY_CREATE"; pageUrl: string; options: PasskeyCreationOptionsJson }
  | { channel: typeof MESSAGE_CHANNEL; type: "PASSKEY_GET"; pageUrl: string; options: PasskeyAssertionOptionsJson }
  | { channel: typeof MESSAGE_CHANNEL; type: "GET_PASSKEY_PROMPT"; requestId: string }
  | { channel: typeof MESSAGE_CHANNEL; type: "RESPOND_PASSKEY_PROMPT"; requestId: string; decision: "approve" | "cancel" | "fallback"; itemId: string | null; credentialId: string | null; masterPassword: string };

export type ExtensionResponse<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: string };

export function request<T extends Omit<ExtensionRequest, "channel">>(request: T): T & { channel: typeof MESSAGE_CHANNEL } {
  return { ...request, channel: MESSAGE_CHANNEL };
}

export function isExtensionRequest(value: unknown): value is ExtensionRequest {
  return typeof value === "object" && value !== null && "channel" in value && value.channel === MESSAGE_CHANNEL && "type" in value;
}
