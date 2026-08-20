export type KdfType = "pbkdf2" | "argon2id";

export interface KdfSettings {
  kdfType: KdfType;
  iterations: number;
  memoryMib: number | null;
  parallelism: number | null;
}

export interface DeviceRequest {
  identifier: string;
  name: string;
  deviceType: "web" | "extension" | "desktop";
}

export interface RegistrationMaterial {
  authProof: string;
  protectedUserKey: string;
}

export interface RegisterRequest {
  email: string;
  authProof: string;
  protectedUserKey: string;
  kdf: KdfSettings;
  device: DeviceRequest;
}

export interface LoginRequest {
  email: string;
  authProof: string;
  device: DeviceRequest;
  totpCode: string | null;
  recoveryCode: string | null;
  trustedDeviceToken: string | null;
  rememberDevice: boolean;
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
  expiresAt: string;
}

export interface MfaEnableResponse {
  recoveryCodes: string[];
}

export interface TotpSetupStartResponse {
  setupId: string;
  secret: string;
  otpauthUri: string;
  expiresAt: string;
}

export interface WebauthnCredentialResponse {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface MfaStatusResponse {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
  webauthnCredentials: WebauthnCredentialResponse[];
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

export interface SyncChange {
  revision: number;
  operation: "upsert" | "delete";
  objectId: string;
  object: EncryptedObject | null;
}

export interface SyncResponse {
  changes: SyncChange[];
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

export interface LoginValue {
  username: string | null;
  password: string | null;
  uris: Array<{ uri: string; match: string | null }>;
  totp: string | null;
  fido2Credentials: Array<Record<string, unknown>>;
  passwordRevisionDate: string | null;
  autofillOnPageLoad: boolean | null;
  [key: string]: unknown;
}

export interface VaultItem {
  schemaVersion: number;
  id: string;
  folderId: string | null;
  organizationId: string | null;
  collectionIds: string[];
  name: string;
  notes: string | null;
  favorite: boolean;
  reprompt: number;
  fields: Array<Record<string, unknown>>;
  passwordHistory: Array<Record<string, unknown>>;
  attachments: AttachmentMetadata[];
  data: { kind: string; value: Record<string, unknown> };
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
  archivedDate: string | null;
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

export interface LoginDraft {
  name: string;
  username: string | null;
  password: string | null;
  uri: string | null;
  totp: string | null;
  notes: string | null;
  favorite: boolean;
}

export type EditableItemKind = "login" | "secureNote" | "card" | "identity" | "sshKey";

export type GenericEditableItemKind = Exclude<EditableItemKind, "login">;

export interface CardDraftValue {
  cardholderName: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
  brand: string | null;
  number: string | null;
}

export interface IdentityDraftValue {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  ssn: string | null;
  username: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
}

export interface SshKeyDraftValue {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
}

export interface EditableItemDraft {
  name: string;
  notes: string | null;
  favorite: boolean;
  data:
    | { kind: "secureNote"; value: Record<string, never> }
    | { kind: "card"; value: CardDraftValue }
    | { kind: "identity"; value: IdentityDraftValue }
    | { kind: "sshKey"; value: SshKeyDraftValue };
}

export interface TotpCode {
  code: string;
  remainingSeconds: number;
  issuer: string | null;
  accountName: string | null;
  period: number;
  digits: number;
  algorithm: "SHA1" | "SHA256" | "SHA512";
}

export interface ImportResult {
  itemCount: number;
  folderCount: number;
  collectionCount: number;
  itemIds: string[];
  folderIds: string[];
}

export interface FolderSummary {
  id: string;
  name: string;
}

export interface SessionResponse {
  id: string;
  deviceId: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  revokedAt: string | null;
  current: boolean;
}

export interface DeviceResponse {
  id: string;
  identifier: string;
  name: string;
  deviceType: string;
  trusted: boolean;
  trustedUntil: string | null;
  createdAt: string;
  lastSeenAt: string;
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

export type OrganizationRole = "owner" | "admin" | "manager" | "user";
export type MembershipStatus = "invited" | "accepted" | "confirmed" | "removed";

export interface OrganizationResponse {
  id: string;
  memberId: string;
  name: string;
  role: OrganizationRole;
  status: MembershipStatus;
  encryptedOrganizationKey: string | null;
  createdAt: string;
}

export interface OrganizationMemberResponse {
  id: string;
  accountId: string | null;
  email: string;
  role: OrganizationRole;
  status: MembershipStatus;
  encryptedOrganizationKey: string | null;
  invitedAt: string;
  acceptedAt: string | null;
  confirmedAt: string | null;
}

export interface OrganizationInviteResponse {
  memberId: string;
  invitationToken: string | null;
  expiresAt: string;
  delivery: "manual" | "smtp";
}

export interface CollectionResponse {
  id: string;
  organizationId: string;
  name: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
  createdAt: string;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  requestId: string | null;
}
