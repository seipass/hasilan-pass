import { invoke } from "@tauri-apps/api/core";

export interface ProfileSummary {
  scope: string;
  serverUrl: string;
  email: string;
  active: boolean;
}

export interface DesktopStatus {
  unlocked: boolean;
  online: boolean;
  serverUrl: string | null;
  email: string | null;
  itemCount: number;
  pendingCount: number;
  conflictCount: number;
  autoLockMinutes: number;
  lastSyncAt: string | null;
  profiles: ProfileSummary[];
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
  pending: boolean;
  conflicted: boolean;
  organizationId: string | null;
  collectionIds: string[];
}

export type OrganizationRole = "owner" | "admin" | "manager" | "user";

export interface OrganizationSummary {
  id: string;
  name: string;
  role: OrganizationRole;
}

export interface OrganizationCollectionSummary {
  id: string;
  organizationId: string;
  name: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface OrganizationCatalog {
  organizations: OrganizationSummary[];
  collections: OrganizationCollectionSummary[];
  folders: FolderSummary[];
}

export interface FolderSummary {
  id: string;
  name: string;
}

export interface LoginUri {
  uri: string;
  match: string | null;
}

export interface Fido2Credential {
  credentialId: string;
  rpId: string;
  rpName: string | null;
  userName: string | null;
  userDisplayName: string | null;
  creationDate: string;
  discoverable: boolean;
  transports: string[];
  [key: string]: unknown;
}

export interface LoginValue {
  username: string | null;
  password: string | null;
  uris: LoginUri[];
  totp: string | null;
  fido2Credentials: Fido2Credential[];
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
  fields: Array<{ name: string | null; value: string | null; fieldType: number; linkedId: number | null }>;
  passwordHistory: Array<{ password: string; lastUsedDate: string }>;
  attachments: AttachmentMetadata[];
  data: { kind: string; value: Record<string, unknown> };
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
  archivedDate: string | null;
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
}

export interface AttachmentRemoval {
  item: VaultItem;
  cleanupPending: boolean;
}

export interface LoginDraft {
  id: string | null;
  name: string;
  username: string | null;
  password: string | null;
  uri: string | null;
  totp: string | null;
  notes: string | null;
  favorite: boolean;
  folderId: string | null;
  fields: VaultItem["fields"];
  organizationId: string | null;
  collectionIds: string[];
}

export interface FolderDraft {
  id: string | null;
  name: string;
}

export interface ItemDraft {
  id: string | null;
  name: string;
  notes: string | null;
  favorite: boolean;
  folderId: string | null;
  fields: VaultItem["fields"];
  data: VaultItem["data"];
  organizationId: string | null;
  collectionIds: string[];
}

export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  minimumNumbers: number;
  minimumSymbols: number;
  excludeAmbiguous: boolean;
}

export interface PassphraseOptions {
  wordCount: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export interface TotpView {
  code: string;
  remainingSeconds: number;
}

export interface BiometricStatus {
  enabled: boolean;
  available: boolean;
  storageHardwareBacked: boolean;
  biometricHardwareBacked: boolean;
  storageStrongBoxBacked: boolean;
  biometricStrongBoxBacked: boolean;
  strongBoxAvailable: boolean;
}

export interface ClipboardPolicy {
  clearAfterSeconds: number;
}

export interface AccountWebauthnCredential {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface AccountMfaStatus {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
  webauthnCredentials: AccountWebauthnCredential[];
}

export interface AccountSession {
  id: string;
  deviceId: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  revokedAt: string | null;
  current: boolean;
}

export interface AccountDevice {
  id: string;
  identifier: string;
  name: string;
  deviceType: string;
  trusted: boolean;
  trustedUntil: string | null;
  createdAt: string;
  lastSeenAt: string;
}

export interface AccountSecuritySnapshot {
  mfa: AccountMfaStatus;
  sessions: AccountSession[];
  devices: AccountDevice[];
}

export interface AccountTotpSetup {
  setupId: string;
  secret: string;
  otpauthUri: string;
  expiresAt: string;
}

export interface MfaEnableResult {
  recoveryCodes: string[];
}

export interface ImportSummary {
  itemCount: number;
  folderCount: number;
  collectionCount: number;
}

export interface ConflictSummary {
  id: string;
  localName: string;
  serverName: string;
}

export const desktop = {
  status: () => invoke<DesktopStatus>("status"),
  register: (serverUrl: string, email: string, masterPassword: string) =>
    invoke<DesktopStatus>("register", { serverUrl, email, masterPassword }),
  login: (
    serverUrl: string,
    email: string,
    masterPassword: string,
    totpCode: string | null,
    recoveryCode: string | null,
  ) => invoke<DesktopStatus>("login", { serverUrl, email, masterPassword, totpCode, recoveryCode }),
  loginWithAccountPasskey: (serverUrl: string, email: string, masterPassword: string) =>
    invoke<DesktopStatus>("login_with_account_passkey", { serverUrl, email, masterPassword }),
  lock: () => invoke<DesktopStatus>("lock"),
  logout: () => invoke<DesktopStatus>("logout"),
  sync: () => invoke<DesktopStatus>("sync_now"),
  touch: () => invoke<void>("touch"),
  listItems: (query: string, category: string) =>
    invoke<ItemSummary[]>("list_items", { query, category }),
  organizationCatalog: () => invoke<OrganizationCatalog>("organization_catalog"),
  getItem: (id: string) => invoke<VaultItem>("get_item", { id }),
  saveLogin: (draft: LoginDraft) => invoke<VaultItem>("save_login", { draft }),
  saveItem: (draft: ItemDraft) => invoke<VaultItem>("save_item", { draft }),
  saveFolder: (draft: FolderDraft) => invoke<FolderSummary>("save_folder", { draft }),
  deleteFolder: (id: string) => invoke<DesktopStatus>("delete_folder", { id }),
  deleteItem: (id: string) => invoke<DesktopStatus>("delete_item", { id }),
  removePasskey: (itemId: string, credentialId: string) =>
    invoke<VaultItem>("remove_passkey", { itemId, credentialId }),
  uploadAttachment: (itemId: string, attachmentId: string | null) =>
    invoke<VaultItem | null>("upload_attachment", { itemId, attachmentId }),
  downloadAttachment: (itemId: string, attachmentId: string) =>
    invoke<string | null>("download_attachment", { itemId, attachmentId }),
  removeAttachment: (itemId: string, attachmentId: string) =>
    invoke<AttachmentRemoval>("remove_attachment", { itemId, attachmentId }),
  generatePassword: (options: PasswordOptions) =>
    invoke<string>("generate_password", { options }),
  generatePassphrase: (options: PassphraseOptions) =>
    invoke<string>("generate_passphrase", { options }),
  totp: (id: string, unixSeconds: number) =>
    invoke<TotpView>("totp_for_item", { id, unixSeconds }),
  importBitwarden: () => invoke<ImportSummary | null>("import_bitwarden_json"),
  exportBitwarden: () => invoke<string | null>("export_bitwarden_json"),
  conflicts: () => invoke<ConflictSummary[]>("list_conflicts"),
  resolveConflict: (id: string, keepLocal: boolean) =>
    invoke<DesktopStatus>("resolve_conflict", { id, keepLocal }),
  selectProfile: (scope: string) => invoke<DesktopStatus>("select_profile", { scope }),
  setAutoLock: (minutes: number) =>
    invoke<DesktopStatus>("set_auto_lock_minutes", { minutes }),
  copySecret: (value: string) => invoke<void>("copy_secret", { value }),
  clipboardPolicy: () => invoke<ClipboardPolicy>("clipboard_policy"),
  setClipboardPolicy: (clearAfterSeconds: number) =>
    invoke<ClipboardPolicy>("set_clipboard_policy", { clearAfterSeconds }),
  biometricStatus: () => invoke<BiometricStatus>("biometric_status"),
  enableBiometricUnlock: () => invoke<BiometricStatus>("enable_biometric_unlock"),
  disableBiometricUnlock: () => invoke<BiometricStatus>("disable_biometric_unlock"),
  openAutofillSettings: () => invoke<void>("open_autofill_settings"),
  openCredentialProviderSettings: () => invoke<void>("open_credential_provider_settings"),
  scanTotp: () => invoke<{ value: string }>("scan_totp").then((result) => result.value),
  accountSecurity: () => invoke<AccountSecuritySnapshot>("account_security"),
  startAccountTotpSetup: (masterPassword: string) =>
    invoke<AccountTotpSetup>("start_account_totp_setup", { masterPassword }),
  finishAccountTotpSetup: (setupId: string, code: string) =>
    invoke<MfaEnableResult>("finish_account_totp_setup", { setupId, code }),
  disableAccountTotp: (masterPassword: string) =>
    invoke<void>("disable_account_totp", { masterPassword }),
  rotateAccountRecoveryCodes: (masterPassword: string) =>
    invoke<{ codes: string[] }>("rotate_account_recovery_codes", { masterPassword }),
  registerAccountPasskey: (masterPassword: string, name: string) =>
    invoke<MfaEnableResult>("register_account_passkey", { masterPassword, name }),
  removeAccountPasskey: (id: string) => invoke<void>("remove_account_passkey", { id }),
  revokeAccountDeviceTrust: (id: string) => invoke<void>("revoke_account_device_trust", { id }),
  revokeAccountSession: (id: string) => invoke<DesktopStatus>("revoke_account_session", { id }),
};

export function loginValue(item: VaultItem | null): LoginValue | null {
  if (item?.data.kind !== "login") return null;
  return item.data.value as unknown as LoginValue;
}
