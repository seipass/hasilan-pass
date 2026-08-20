export interface KdfSettings {
  kdfType: "pbkdf2" | "argon2id";
  iterations: number;
  memoryMib: number | null;
  parallelism: number | null;
}

export interface TokenResponse {
  accountId: string;
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  protectedUserKey: string;
  kdf: KdfSettings;
  sessionId: string;
  deviceId: string;
  trustedDeviceToken: string | null;
}

export interface WebauthnChallengeResponse {
  ceremonyId: string;
  options: Record<string, unknown>;
}

export interface EncryptedObject {
  id: string;
  kind: "cipher" | "folder" | "organizationKey";
  ownerType: "user" | "organization";
  ownerId: string;
  collectionIds: string[];
  format: string;
  wrappedKey: string;
  payload: string;
  objectRevision: number;
  accountRevision: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

export interface SyncResponse {
  changes: Array<{
    revision: number;
    operation: "upsert" | "delete";
    objectId: string;
    object: EncryptedObject | null;
  }>;
  nextCursor: string;
  hasMore: boolean;
}

export interface ItemSummary {
  id: string;
  name: string;
  itemType: number;
  username: string | null;
  primaryUri: string | null;
  favorite: boolean;
  deletedDate: string | null;
  hasTotp: boolean;
  passkeyCount: number;
  objectRevision: number | null;
  organizationId: string | null;
  collectionIds: string[];
}

export interface SharingKeyMaterial {
  publicKey: string;
  protectedPrivateKey: string;
}

export interface SharingKeyResponse {
  accountId: string;
  publicKey: string;
  protectedPrivateKey: string | null;
}

export interface OrganizationResponse {
  id: string;
  memberId: string;
  name: string;
  role: "owner" | "admin" | "manager" | "user";
  status: "invited" | "accepted" | "confirmed" | "removed";
  encryptedOrganizationKey: string | null;
  createdAt: string;
}

export interface CredentialSummary {
  id: string;
  name: string;
  username: string | null;
  hasPassword: boolean;
  hasTotp: boolean;
}

export interface FillCredential {
  id: string;
  username: string | null;
  password: string | null;
  totp: string | null;
}

export interface LoginDraft {
  name: string;
  username: string | null;
  password: string | null;
  uri: string | null;
  totp: string | null;
  notes: string | null;
  favorite: boolean;
}

export interface LoginValue {
  username: string | null;
  password: string | null;
  uris: Array<{ uri: string; match: string | null }>;
  totp: string | null;
  [key: string]: unknown;
}

export interface VaultItem {
  id: string;
  organizationId: string | null;
  collectionIds: string[];
  name: string;
  notes: string | null;
  favorite: boolean;
  deletedDate: string | null;
  attachments: AttachmentMetadata[];
  data: { kind: string; value: Record<string, unknown> };
  [key: string]: unknown;
}

export interface AttachmentMetadata {
  id: string;
  fileName: string;
  mediaType: string;
  size: number;
  chunkSize: number;
  chunkCount: number;
  ciphertextSize: number;
  format: "hp-attachment.v1";
  key: string;
  fileNonce: string;
}

export interface AttachmentInitiateRequest {
  id: string;
  objectId: string;
  objectRevision: number;
  format: "hp-attachment.v1";
  chunkSize: number;
  chunkCount: number;
  ciphertextSize: number;
}

export interface AttachmentResponse extends AttachmentInitiateRequest {
  state: "uploading" | "complete";
  uploadedRanges: Array<{ start: number; endExclusive: number }>;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
  expiresAt: string | null;
}

export interface PendingCredentialSummary {
  pageUrl: string;
  name: string;
  username: string | null;
  capturedAt: number;
  matches: CredentialSummary[];
}

export interface ExtensionState {
  unlocked: boolean;
  serverUrl: string | null;
  email: string | null;
  accountId: string | null;
  itemCount: number;
  pending: PendingCredentialSummary | null;
}

export interface PasskeyCredentialDescriptorJson {
  id: string;
  type?: "public-key";
  transports?: string[];
}

export interface PasskeyCreationOptionsJson {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ alg: number; type: "public-key" }>;
  excludeCredentials: PasskeyCredentialDescriptorJson[];
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    requireResidentKey?: boolean;
    residentKey?: string;
    userVerification?: string;
  };
  attestation?: string;
  extensions: { credProps?: boolean };
}

export interface PasskeyAssertionOptionsJson {
  challenge: string;
  rpId?: string;
  allowCredentials: PasskeyCredentialDescriptorJson[];
  userVerification?: string;
  mediation?: string;
}

export interface PasskeyTarget {
  itemId: string;
  name: string;
  username: string | null;
}

export interface PasskeyCandidate {
  itemId: string;
  credentialId: string;
  itemName: string;
  userName: string | null;
  userDisplayName: string | null;
}

export interface PasskeyPrompt {
  requestId: string;
  kind: "create" | "get";
  origin: string;
  rpId: string;
  rpName: string;
  userName: string | null;
  userDisplayName: string | null;
  targets: PasskeyTarget[];
  candidates: PasskeyCandidate[];
}

export type PasskeyBridgeResult =
  | { status: "fallback" }
  | { status: "error"; name: string; message: string }
  | {
      status: "created";
      result: {
        credentialId: string;
        clientDataJSON: string;
        attestationObject: string;
        authenticatorData: string;
        publicKey: string;
        publicKeyAlgorithm: number;
        transports: string[];
        extensions: { credProps: { rk: boolean } };
      };
    }
  | {
      status: "asserted";
      result: {
        credentialId: string;
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle: string | null;
      };
    };
