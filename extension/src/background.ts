import browser from "webextension-polyfill";
import type Browser from "webextension-polyfill";

import { ExtensionApi, ExtensionApiError, normalizeServerUrl } from "./api";
import { ATTACHMENT_CHUNK_SIZE, decodeBase64Url, encodeBase64Url } from "./attachment-transfer";
import { ExtensionCipherCache } from "./cache";
import { isExtensionRequest, type ExtensionRequest, type ExtensionResponse } from "./messages";
import { createRuntime, type ExtensionVaultRuntime } from "./runtime";
import {
  effectiveAutoLock,
  normalizeAutoLock,
  persistedAutoLock,
  type AutoLockSetting,
} from "./settings";
import { DeviceSecretStore, TrustedDeviceStore, keyVersionFor } from "./trusted-device";
import type {
  AttachmentInitiateRequest,
  AttachmentMetadata,
  AttachmentResponse,
  CredentialSummary,
  ExtensionState,
  FillCredential,
  ItemSummary,
  KdfSettings,
  LoginDraft,
  PasskeyAssertionOptionsJson,
  PasskeyBridgeResult,
  PasskeyCandidate,
  PasskeyCreationOptionsJson,
  PasskeyPrompt,
  PasskeyTarget,
  PendingCredentialSummary,
  TokenResponse,
  SharingKeyMaterial,
  VaultItem,
  WebauthnChallengeResponse,
} from "./types";

const SETTINGS_KEY = "hasilan-extension-settings-v1";
const LOCK_ALARM = "hasilan-extension-auto-lock";
const PENDING_LIFETIME_MS = 2 * 60_000;
const CONTENT_SCRIPT = "assets/content.js";
const PASSKEY_PAGE_SCRIPT = "assets/passkey-page.js";
const DEFAULT_KDF: KdfSettings = {
  kdfType: "argon2id",
  iterations: 6,
  memoryMib: 32,
  parallelism: 4,
};

interface StoredSettings {
  serverUrl: string;
  email: string;
  deviceIdentifier: string;
  /** `null` means never auto-lock; omitted in the pre-setting schema. */
  autoLockMinutes?: AutoLockSetting;
}

interface PendingCredential {
  pageUrl: string;
  name: string;
  username: string | null;
  password: string;
  capturedAt: number;
  matches: CredentialSummary[];
}

interface UnlockContext {
  email: string;
  kdf: KdfSettings;
  protectedUserKey: string;
}

interface PasskeyApproval {
  decision: "approve" | "cancel" | "fallback";
  itemId: string | null;
  credentialId: string | null;
}

interface PendingPasskeyPrompt {
  prompt: PasskeyPrompt;
  resolve: (approval: PasskeyApproval) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
  windowId: number | null;
}

interface PendingAccountWebauthn {
  ceremonyId: string;
  serverUrl: string;
  email: string;
  deviceIdentifier: string;
  startedAt: number;
}

const runtimePromise = createRuntime();
const api = new ExtensionApi();
const trustedDevices = new TrustedDeviceStore();
const deviceSecrets = new DeviceSecretStore();
let settings: StoredSettings | null = null;
let cache: ExtensionCipherCache | null = null;
let cursor: string | null = null;
let pending: PendingCredential | null = null;
let unlockContext: UnlockContext | null = null;
let rememberedUnlockEnabled = false;
const passkeyPrompts = new Map<string, PendingPasskeyPrompt>();
let pendingAccountWebauthn: PendingAccountWebauthn | null = null;

api.setSessionLostHandler(() => {
  void handleSessionLost();
});

api.setSessionChangedHandler((session) => {
  void persistRefreshToken(session, api.serverUrl ?? undefined);
});

void initializeSettings();
const persistentRestore = restorePersistentSession().catch(() => undefined);

browser.runtime.onMessage.addListener((message: unknown, sender: Browser.Runtime.MessageSender) => {
  if (!isExtensionRequest(message)) return undefined;
  return handleMessage(message, sender)
    .then((data): ExtensionResponse => ({ ok: true, data }))
    .catch((error: unknown): ExtensionResponse => ({ ok: false, error: errorMessage(error) }));
});

browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) void lock(false);
});

browser.runtime.onInstalled.addListener(() => {
  void browser.contextMenus.removeAll().then(() => browser.contextMenus.create({
    id: "hasilan-fill",
    title: "Fill with Hasilan Pass",
    contexts: ["editable", "page"],
  }));
});

browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== "hasilan-fill" || tab?.id === undefined) return;
  void openMenuInTab(tab.id);
});

browser.permissions.onRemoved.addListener(() => {
  void pruneRegistrations();
});

browser.windows.onRemoved.addListener((windowId) => {
  for (const [requestId, state] of passkeyPrompts) {
    if (state.windowId === windowId) settlePasskeyPrompt(requestId, { decision: "cancel", itemId: null, credentialId: null });
  }
});

async function handleMessage(message: ExtensionRequest, sender: Browser.Runtime.MessageSender): Promise<unknown> {
  const runtime = await runtimePromise;
  await initializeSettings();
  await persistentRestore;
  switch (message.type) {
    case "GET_STATE":
      return state(runtime);
    case "LOGIN": {
      try {
        return await login(
          runtime,
          message.serverUrl,
          message.email,
          message.password,
          message.secondFactor,
          message.rememberDevice,
          message.rememberUnlock,
        );
      } finally {
        message.password = "";
      }
    }
    case "UNLOCK":
      try {
        return await unlock(runtime, message.email, message.password, message.rememberUnlock);
      } finally {
        message.password = "";
      }
    case "REGISTER": {
      try {
        return await register(runtime, message.serverUrl, message.email, message.password);
      } finally {
        message.password = "";
      }
    }
    case "START_ACCOUNT_WEBAUTHN": {
      try {
        return await startAccountWebauthn(
          runtime,
          message.mode,
          message.serverUrl,
          message.email,
          message.password,
        );
      } finally {
        message.password = "";
      }
    }
    case "FINISH_ACCOUNT_WEBAUTHN":
      return finishAccountWebauthn(
        runtime,
        message.ceremonyId,
        message.credential,
        message.rememberDevice,
        message.rememberUnlock,
      );
    case "LOCK":
      await lock(true);
      return null;
    case "SET_AUTO_LOCK":
      return setAutoLock(message.minutes, runtime);
    case "SET_REMEMBER_UNLOCK":
      return setRememberUnlock(message.enabled, runtime);
    case "LOGOUT":
      await logout();
      return null;
    case "SYNC":
      requireUnlocked(runtime);
      await touch();
      await initializeOrganizationKeys(runtime);
      await sync(runtime);
      return state(runtime);
    case "LIST_ITEMS":
      requireUnlocked(runtime);
      await touch();
      return parse<ItemSummary[]>(runtime.listItems(message.query, message.category));
    case "GET_ITEM":
      requireUnlocked(runtime);
      await touch();
      return parse<VaultItem>(runtime.getItem(message.id));
    case "CREATE_LOGIN":
      requireUnlocked(runtime);
      await touch();
      return saveNewLogin(runtime, message.draft);
    case "UPDATE_LOGIN":
      requireUnlocked(runtime);
      await touch();
      runtime.updateLogin(message.id, JSON.stringify(message.draft));
      await upload(runtime, message.id);
      return parse<VaultItem>(runtime.getItem(message.id));
    case "DELETE_ITEM":
      requireUnlocked(runtime);
      await touch();
      return deleteItem(runtime, message.id);
    case "ATTACHMENT_BEGIN":
      assertExtensionPage(sender);
      requireUnlocked(runtime);
      await touch();
      return beginAttachment(
        runtime,
        message.itemId,
        message.attachmentId,
        message.fileName,
        message.mediaType,
        message.size,
      );
    case "ATTACHMENT_UPLOAD_CHUNK":
      assertExtensionPage(sender);
      requireUnlocked(runtime);
      await touch();
      try {
        await uploadAttachmentChunk(
          runtime,
          message.itemId,
          message.attachmentId,
          message.index,
          message.plaintext,
        );
      } finally {
        message.plaintext = "";
      }
      return null;
    case "ATTACHMENT_COMPLETE":
      assertExtensionPage(sender);
      requireUnlocked(runtime);
      await touch();
      return completeAttachment(runtime, message.itemId, message.attachmentId);
    case "ATTACHMENT_DOWNLOAD_CHUNK":
      assertExtensionPage(sender);
      requireUnlocked(runtime);
      await touch();
      return downloadAttachmentChunk(runtime, message.itemId, message.attachmentId, message.index);
    case "ATTACHMENT_REMOVE":
      assertExtensionPage(sender);
      requireUnlocked(runtime);
      await touch();
      return removeAttachment(runtime, message.itemId, message.attachmentId);
    case "TOTP":
      requireUnlocked(runtime);
      await touch();
      return parse<unknown>(runtime.totpForItem(message.id, BigInt(message.unixSeconds)));
    case "GENERATE_PASSWORD":
      await touch();
      return runtime.generatePassword(JSON.stringify(message.options));
    case "GENERATE_USERNAME":
      await touch();
      return runtime.generateUsername(JSON.stringify(message.options));
    case "CREDENTIALS_FOR_PAGE":
      assertContentPage(sender, message.pageUrl);
      requireUnlocked(runtime);
      await touch();
      return parse<CredentialSummary[]>(runtime.credentialsForUrl(message.pageUrl));
    case "FILL_CREDENTIAL":
      assertContentPage(sender, message.pageUrl);
      requireUnlocked(runtime);
      await touch();
      return parse<FillCredential>(
        runtime.credentialForFill(message.id, message.pageUrl, BigInt(Math.floor(Date.now() / 1_000))),
      );
    case "CAPTURE_CREDENTIAL":
      assertContentPage(sender, message.pageUrl);
      requireUnlocked(runtime);
      await capture(runtime, message.pageUrl, message.username, message.password);
      message.password = "";
      return pendingSummary();
    case "SAVE_PENDING":
      requireUnlocked(runtime);
      await touch();
      return savePending(runtime, message.existingId);
    case "DISMISS_PENDING":
      clearPending();
      return null;
    case "REGISTER_SITE":
      await registerSite(message.matchPattern, message.tabId);
      return null;
    case "PASSKEY_CREATE":
      return createSitePasskey(runtime, sender, message.pageUrl, message.options);
    case "PASSKEY_GET":
      return assertSitePasskey(runtime, sender, message.pageUrl, message.options);
    case "GET_PASSKEY_PROMPT":
      assertExtensionPage(sender);
      return passkeyPrompts.get(message.requestId)?.prompt ?? null;
    case "RESPOND_PASSKEY_PROMPT":
      assertExtensionPage(sender);
      try {
        await respondToPasskeyPrompt(runtime, message);
      } finally {
        message.masterPassword = "";
      }
      return null;
  }
}

async function login(
  runtime: ExtensionVaultRuntime,
  serverUrlInput: string,
  emailInput: string,
  passwordInput: string,
  secondFactor: string | null,
  rememberDevice: boolean,
  rememberUnlock: boolean,
): Promise<ExtensionState> {
  await logout();
  const serverUrl = normalizeServerUrl(serverUrlInput);
  const email = emailInput.trim().toLowerCase();
  let password = passwordInput;
  api.configure(serverUrl);
  const kdf = await api.prelogin(email);
  const authProof = runtime.prepareLogin(email, password, JSON.stringify(kdf));
  password = "";
  const device = await deviceRequest();
  const normalizedFactor = optional(secondFactor);
  const totpCode = normalizedFactor !== null && /^[0-9 -]{6,12}$/u.test(normalizedFactor)
    ? normalizedFactor
    : null;
  const recoveryCode = normalizedFactor !== null && totpCode === null ? normalizedFactor : null;
  const trustedDeviceToken = normalizedFactor === null
    ? await trustedDevices.load(serverUrl, email, device.identifier).catch(() => null)
    : null;
  let session: TokenResponse;
  try {
    session = await api.login(JSON.stringify({
      email,
      authProof,
      device,
      totpCode,
      recoveryCode,
      trustedDeviceToken,
      rememberDevice,
    }));
    runtime.finishLogin(session.protectedUserKey);
    unlockContext = {
      email,
      kdf: session.kdf,
      protectedUserKey: session.protectedUserKey,
    };
    await persistUnlockAndSession(session, serverUrl, email, rememberUnlock, false, runtime);
    if (session.trustedDeviceToken !== null) {
      await trustedDevices.save(serverUrl, email, device.identifier, session.trustedDeviceToken);
    }
  } catch (error) {
    if (error instanceof ExtensionApiError && error.code === "mfa_required" && trustedDeviceToken !== null) {
      await trustedDevices.remove(serverUrl, email, device.identifier).catch(() => undefined);
    }
    runtime.lock();
    api.clearSession();
    throw error;
  }
  await saveSettings(serverUrl, email);
  await persistRefreshToken(session, serverUrl);
  await persistUnlockAndSession(session, serverUrl, email, rememberUnlock, false, runtime);
  await enterVault(runtime, serverUrl, session.accountId);
  return state(runtime);
}

async function register(
  runtime: ExtensionVaultRuntime,
  serverUrlInput: string,
  emailInput: string,
  passwordInput: string,
): Promise<ExtensionState> {
  if (passwordInput.length < 12) throw new Error("Use at least 12 characters for the master password.");
  await logout();
  const serverUrl = normalizeServerUrl(serverUrlInput);
  const email = emailInput.trim().toLowerCase();
  let password = passwordInput;
  api.configure(serverUrl);
  const material = parse<{ authProof: string; protectedUserKey: string }>(
    runtime.prepareRegistration(email, password, JSON.stringify(DEFAULT_KDF)),
  );
  password = "";
  const device = await deviceRequest();
  await api.register(JSON.stringify({
    email,
    authProof: material.authProof,
    protectedUserKey: material.protectedUserKey,
    kdf: DEFAULT_KDF,
    device,
  }));
  const session = await api.login(JSON.stringify({
    email,
    authProof: material.authProof,
    device,
    totpCode: null,
    recoveryCode: null,
    trustedDeviceToken: null,
    rememberDevice: false,
  }));
  unlockContext = {
    email,
    kdf: session.kdf,
    protectedUserKey: session.protectedUserKey,
  };
  await persistRefreshToken(session, serverUrl);
  await persistUnlockAndSession(session, serverUrl, email, false, false, runtime);
  await saveSettings(serverUrl, email);
  await enterVault(runtime, serverUrl, session.accountId);
  return state(runtime);
}

async function startAccountWebauthn(
  runtime: ExtensionVaultRuntime,
  mode: "passkey" | "mfa",
  serverUrlInput: string,
  emailInput: string,
  passwordInput: string,
): Promise<WebauthnChallengeResponse> {
  await logout();
  const serverUrl = normalizeServerUrl(serverUrlInput);
  const email = emailInput.trim().toLowerCase();
  let password = passwordInput;
  api.configure(serverUrl);
  try {
    const kdf = await api.prelogin(email);
    const authProof = runtime.prepareLogin(email, password, JSON.stringify(kdf));
    password = "";
    const device = await deviceRequest();
    const challenge = mode === "mfa"
      ? await api.startWebauthnMfaLogin(JSON.stringify({ email, authProof, device }))
      : await api.startPasskeyLogin(JSON.stringify({ email, device }));
    pendingAccountWebauthn = {
      ceremonyId: challenge.ceremonyId,
      serverUrl,
      email,
      deviceIdentifier: device.identifier,
      startedAt: Date.now(),
    };
    return challenge;
  } catch (error) {
    password = "";
    runtime.lock();
    api.clearSession();
    throw error;
  }
}

async function finishAccountWebauthn(
  runtime: ExtensionVaultRuntime,
  ceremonyId: string,
  credential: Record<string, unknown>,
  rememberDevice: boolean,
  rememberUnlock: boolean,
): Promise<ExtensionState> {
  const pendingLogin = pendingAccountWebauthn;
  if (
    pendingLogin === null
    || pendingLogin.ceremonyId !== ceremonyId
    || Date.now() - pendingLogin.startedAt > 5 * 60_000
  ) {
    pendingAccountWebauthn = null;
    runtime.lock();
    throw new Error("The account WebAuthn request expired. Start again.");
  }
  try {
    const session = await api.finishWebauthnLogin(JSON.stringify({
      ceremonyId,
      credential,
      rememberDevice,
    }));
    try {
      runtime.finishLogin(session.protectedUserKey);
    } catch {
      await api.logout().catch(() => undefined);
      runtime.lock();
      throw new Error("The master password could not unlock this account's encrypted vault.");
    }
    unlockContext = {
      email: pendingLogin.email,
      kdf: session.kdf,
      protectedUserKey: session.protectedUserKey,
    };
    await persistRefreshToken(session, pendingLogin.serverUrl);
    await persistUnlockAndSession(session, pendingLogin.serverUrl, pendingLogin.email, rememberUnlock, false, runtime);
    if (session.trustedDeviceToken !== null) {
      await trustedDevices.save(
        pendingLogin.serverUrl,
        pendingLogin.email,
        pendingLogin.deviceIdentifier,
        session.trustedDeviceToken,
      );
    }
    await saveSettings(pendingLogin.serverUrl, pendingLogin.email);
    await enterVault(runtime, pendingLogin.serverUrl, session.accountId);
    return state(runtime);
  } finally {
    pendingAccountWebauthn = null;
  }
}

async function unlock(
  runtime: ExtensionVaultRuntime,
  emailInput: string,
  passwordInput: string,
  rememberUnlock: boolean,
): Promise<ExtensionState> {
  const session = api.session;
  if (session === null || settings === null || unlockContext === null) {
    throw new Error("The extension session is unavailable. Sign in again.");
  }
  const email = emailInput.trim().toLowerCase();
  if (email !== unlockContext.email) throw new Error("Use the email address for this account.");
  let password = passwordInput;
  try {
    runtime.prepareLogin(email, password, JSON.stringify(unlockContext.kdf));
    password = "";
    runtime.finishLogin(unlockContext.protectedUserKey);
    await persistUnlockAndSession(session, settings.serverUrl, email, rememberUnlock, false, runtime);
    await enterVault(runtime, settings.serverUrl, session.accountId);
    return state(runtime);
  } finally {
    password = "";
  }
}

async function persistUnlockAndSession(
  session: TokenResponse,
  serverUrl: string,
  email: string,
  rememberUnlock: boolean,
  manualLockSuppressed: boolean,
  runtime: ExtensionVaultRuntime,
): Promise<void> {
  const keyVersion = await keyVersionFor(session.protectedUserKey, session.kdf);
  if (rememberUnlock) {
    const key = runtime.exportUserKey();
    try {
      await deviceSecrets.saveUnlock(serverUrl, session.accountId, session.deviceId, key, keyVersion);
    } finally {
      key.fill(0);
    }
  } else {
    await deviceSecrets.removeUnlock(serverUrl, session.accountId, session.deviceId).catch(() => undefined);
  }
  await deviceSecrets.saveSession({
    serverUrl,
    email: email.trim().toLowerCase(),
    accountId: session.accountId,
    deviceId: session.deviceId,
    kdf: session.kdf,
    protectedUserKey: session.protectedUserKey,
    keyVersion,
    rememberUnlock,
    manualLockSuppressed,
    updatedAt: Date.now(),
  });
  rememberedUnlockEnabled = rememberUnlock;
}

async function persistRefreshToken(session: TokenResponse, serverUrlOverride?: string): Promise<void> {
  const serverUrl = serverUrlOverride ?? settings?.serverUrl;
  if (serverUrl === null || serverUrl === undefined) return;
  await deviceSecrets.saveRefreshToken(serverUrl, session.deviceId, session.refreshToken).catch(() => undefined);
}

async function restorePersistentSession(): Promise<void> {
  const runtime = await runtimePromise;
  await initializeSettings();
  const record = await deviceSecrets.loadSession().catch(() => null);
  if (record === null) {
    await deviceSecrets.clearUnlocks().catch(() => undefined);
    rememberedUnlockEnabled = false;
    return;
  }
  const refreshToken = await deviceSecrets.loadRefreshToken(record.serverUrl, record.deviceId).catch(() => null);
  if (refreshToken === null) {
    await deviceSecrets.removeUnlock(record.serverUrl, record.accountId, record.deviceId).catch(() => undefined);
    await deviceSecrets.removeSession().catch(() => undefined);
    rememberedUnlockEnabled = false;
    return;
  }
  try {
    const session = await api.restoreWithRefreshToken(record.serverUrl, refreshToken);
    if (session.accountId !== record.accountId || session.deviceId !== record.deviceId) {
      throw new Error("The remembered session belongs to another account or device.");
    }
    const sessionKeyVersion = await keyVersionFor(session.protectedUserKey, session.kdf);
    const rememberedKeyCurrent = record.keyVersion === undefined || record.keyVersion === sessionKeyVersion;
    const shouldRememberUnlock = record.rememberUnlock && rememberedKeyCurrent;
    unlockContext = { email: record.email, kdf: session.kdf, protectedUserKey: session.protectedUserKey };
    settings = {
      serverUrl: record.serverUrl,
      email: record.email,
      deviceIdentifier: (settings?.deviceIdentifier ?? (await deviceRequest()).identifier),
      autoLockMinutes: effectiveAutoLock(settings?.autoLockMinutes),
    };
    await persistRefreshToken(session, record.serverUrl);
    await deviceSecrets.saveSession({
      ...record,
      deviceId: session.deviceId,
      kdf: session.kdf,
      protectedUserKey: session.protectedUserKey,
      keyVersion: sessionKeyVersion,
      rememberUnlock: shouldRememberUnlock,
      updatedAt: Date.now(),
    });
    rememberedUnlockEnabled = shouldRememberUnlock;
    if (record.rememberUnlock && !rememberedKeyCurrent) {
      await deviceSecrets.removeUnlock(record.serverUrl, record.accountId, record.deviceId).catch(() => undefined);
    }
    if (shouldRememberUnlock && !record.manualLockSuppressed) {
      const key = await deviceSecrets.loadUnlock(record.serverUrl, record.accountId, session.deviceId, sessionKeyVersion);
      if (key === null) throw new Error("The remembered device unlock is unavailable.");
      try {
        runtime.unlockWithUserKey(key);
        await deviceSecrets.saveUnlock(record.serverUrl, record.accountId, session.deviceId, key, sessionKeyVersion);
      } finally { key.fill(0); }
      await enterVault(runtime, record.serverUrl, record.accountId);
    }
  } catch (error) {
    runtime.lock();
    api.clearSession();
    // Only an explicit server rejection invalidates the durable session. Network/server
    // failures keep encrypted records for a later worker restart; local envelope corruption
    // removes the unlock envelope but does not require throwing away the server session.
    const serverRejected = (error instanceof ExtensionApiError && (error.status === 401 || error.status === 403))
      || (error instanceof Error && error.message.startsWith("The remembered session belongs"));
    if (serverRejected || !(error instanceof ExtensionApiError)) {
      await deviceSecrets.removeUnlock(record.serverUrl, record.accountId, record.deviceId).catch(() => undefined);
    }
    if (serverRejected) {
      await deviceSecrets.removeRefreshToken(record.serverUrl, record.deviceId).catch(() => undefined);
      await deviceSecrets.removeSession().catch(() => undefined);
      rememberedUnlockEnabled = false;
    } else if (!(error instanceof ExtensionApiError)) {
      // A local envelope failure is not a server logout, but the unusable remembered-unlock
      // preference should be disabled so the next worker restart falls back to password unlock.
      await deviceSecrets.saveSession({
        ...record,
        rememberUnlock: false,
        manualLockSuppressed: false,
        updatedAt: Date.now(),
      }).catch(() => undefined);
      rememberedUnlockEnabled = false;
    }
  }
}

async function handleSessionLost(): Promise<void> {
  const record = await deviceSecrets.loadSession().catch(() => null);
  await lock(false);
  api.clearSession();
  if (record !== null) {
    await deviceSecrets.removeRefreshToken(record.serverUrl, record.deviceId).catch(() => undefined);
    await deviceSecrets.removeUnlock(record.serverUrl, record.accountId, record.deviceId).catch(() => undefined);
  }
  await deviceSecrets.removeSession().catch(() => undefined);
  rememberedUnlockEnabled = false;
}

async function enterVault(runtime: ExtensionVaultRuntime, serverUrl: string, accountId: string): Promise<void> {
  await initializeOrganizationKeys(runtime);
  cache = new ExtensionCipherCache(serverUrl, accountId);
  cursor = null;
  let validCache = true;
  try {
    const snapshot = await cache.load();
    for (const object of snapshot.objects) {
      try {
        runtime.acceptObject(JSON.stringify(object));
      } catch {
        validCache = false;
        break;
      }
    }
    if (validCache) cursor = snapshot.cursor;
  } catch {
    validCache = false;
  }
  if (!validCache) {
    cursor = null;
    await cache.clear().catch(() => undefined);
  }
  await sync(runtime);
  await touch();
}

async function initializeOrganizationKeys(runtime: ExtensionVaultRuntime): Promise<void> {
  let sharingKey;
  try {
    sharingKey = await api.sharingKey();
  } catch (error) {
    if (!(error instanceof ExtensionApiError) || error.code !== "sharing_key_not_found") throw error;
    const generated = parse<SharingKeyMaterial>(runtime.generateSharingKey());
    try {
      sharingKey = await api.putSharingKey(generated);
    } catch (installError) {
      if (!(installError instanceof ExtensionApiError) || installError.code !== "sharing_key_exists") {
        throw installError;
      }
      sharingKey = await api.sharingKey();
    }
  }
  if (sharingKey.protectedPrivateKey === null) {
    throw new Error("The account sharing private key is unavailable.");
  }
  runtime.installSharingKey(sharingKey.publicKey, sharingKey.protectedPrivateKey);
  const organizations = await api.organizations();
  runtime.retainOrganizationAccess(JSON.stringify(
    organizations
      .filter((organization) => organization.status === "accepted" || organization.status === "confirmed")
      .map((organization) => organization.id),
  ));
  runtime.clearOrganizationKeys();
  for (const organization of organizations) {
    if (
      (organization.status === "accepted" || organization.status === "confirmed")
      && organization.encryptedOrganizationKey !== null
    ) {
      runtime.openOrganizationKey(organization.id, organization.encryptedOrganizationKey);
    }
  }
}

async function sync(runtime: ExtensionVaultRuntime): Promise<void> {
  if (cache === null) throw new Error("The encrypted cache is unavailable.");
  let pages = 0;
  while (true) {
    const previous = cursor;
    const page = await api.sync(previous);
    runtime.applySyncPage(JSON.stringify(page));
    await cache.apply(page);
    cursor = page.nextCursor;
    pages += 1;
    if (!page.hasMore) return;
    if (page.nextCursor === previous || pages > 1_000) throw new Error("The sync feed did not advance.");
  }
}

async function saveNewLogin(runtime: ExtensionVaultRuntime, draft: LoginDraft): Promise<VaultItem> {
  const id = runtime.createLogin(JSON.stringify(draft));
  await upload(runtime, id);
  return parse<VaultItem>(runtime.getItem(id));
}

async function upload(runtime: ExtensionVaultRuntime, id: string): Promise<void> {
  const accountId = api.accountId;
  if (accountId === null) throw new Error("The extension session is locked.");
  const object = await api.putObject(id, runtime.buildPutRequest(id, accountId));
  runtime.acceptObject(JSON.stringify(object));
  await cache?.save(object);
}

async function deleteItem(runtime: ExtensionVaultRuntime, id: string): Promise<VaultItem> {
  const object = await api.deleteObject(id, runtime.buildDeleteRequest(id));
  runtime.acceptObject(JSON.stringify(object));
  await cache?.save(object);
  return parse<VaultItem>(runtime.getItem(id));
}

async function beginAttachment(
  runtime: ExtensionVaultRuntime,
  itemId: string,
  attachmentId: string | null,
  fileName: string,
  mediaType: string,
  size: number,
): Promise<{ metadata: AttachmentMetadata; status: AttachmentResponse; item: VaultItem }> {
  if (!Number.isSafeInteger(size) || size < 0) throw new Error("The attachment length is invalid.");
  let metadata: AttachmentMetadata;
  if (attachmentId === null) {
    metadata = parse<AttachmentMetadata>(runtime.createAttachment(
      itemId,
      fileName,
      mediaType || "application/octet-stream",
      BigInt(size),
      ATTACHMENT_CHUNK_SIZE,
    ));
    try {
      await upload(runtime, itemId);
    } catch (error) {
      runtime.discardItemChanges(itemId);
      throw error;
    }
  } else {
    metadata = attachmentMetadata(runtime, itemId, attachmentId);
    if (metadata.fileName !== fileName || metadata.size !== size) {
      throw new Error("Choose the same filename and byte length to resume this encrypted upload.");
    }
  }

  const request = parse<AttachmentInitiateRequest>(
    runtime.attachmentInitiateRequest(itemId, metadata.id),
  );
  let status: AttachmentResponse;
  try {
    status = await api.attachmentStatus(metadata.id);
  } catch (error) {
    if (!(error instanceof ExtensionApiError) || error.status !== 404) throw error;
    status = await api.initiateAttachment(JSON.stringify(request));
  }
  return {
    metadata,
    status,
    item: parse<VaultItem>(runtime.getItem(itemId)),
  };
}

async function uploadAttachmentChunk(
  runtime: ExtensionVaultRuntime,
  itemId: string,
  attachmentId: string,
  index: number,
  encodedPlaintext: string,
): Promise<void> {
  attachmentMetadata(runtime, itemId, attachmentId);
  if (!Number.isSafeInteger(index) || index < 0) throw new Error("The attachment frame index is invalid.");
  const plaintext = decodeBase64Url(encodedPlaintext);
  let ciphertext: Uint8Array | null = null;
  try {
    ciphertext = runtime.encryptAttachmentChunk(itemId, attachmentId, index, plaintext);
    await api.putAttachmentChunk(attachmentId, index, ciphertext);
  } finally {
    plaintext.fill(0);
    ciphertext?.fill(0);
  }
}

async function completeAttachment(
  runtime: ExtensionVaultRuntime,
  itemId: string,
  attachmentId: string,
): Promise<AttachmentResponse> {
  attachmentMetadata(runtime, itemId, attachmentId);
  const request = parse<AttachmentInitiateRequest>(
    runtime.attachmentInitiateRequest(itemId, attachmentId),
  );
  return api.completeAttachment(attachmentId, request.objectRevision);
}

async function downloadAttachmentChunk(
  runtime: ExtensionVaultRuntime,
  itemId: string,
  attachmentId: string,
  index: number,
): Promise<string> {
  attachmentMetadata(runtime, itemId, attachmentId);
  if (!Number.isSafeInteger(index) || index < 0) throw new Error("The attachment frame index is invalid.");
  const ciphertext = await api.attachmentChunk(attachmentId, index);
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = runtime.decryptAttachmentChunk(itemId, attachmentId, index, ciphertext);
    return encodeBase64Url(plaintext);
  } finally {
    ciphertext.fill(0);
    plaintext?.fill(0);
  }
}

async function removeAttachment(
  runtime: ExtensionVaultRuntime,
  itemId: string,
  attachmentId: string,
): Promise<{ item: VaultItem; cleanupWarning: boolean }> {
  attachmentMetadata(runtime, itemId, attachmentId);
  runtime.removeAttachment(itemId, attachmentId);
  try {
    await upload(runtime, itemId);
  } catch (error) {
    runtime.discardItemChanges(itemId);
    throw error;
  }
  let cleanupWarning = false;
  try {
    await api.deleteAttachment(attachmentId);
  } catch (error) {
    if (!(error instanceof ExtensionApiError) || error.status !== 404) cleanupWarning = true;
  }
  return {
    item: parse<VaultItem>(runtime.getItem(itemId)),
    cleanupWarning,
  };
}

function attachmentMetadata(
  runtime: ExtensionVaultRuntime,
  itemId: string,
  attachmentId: string,
): AttachmentMetadata {
  const item = parse<VaultItem>(runtime.getItem(itemId));
  const attachment = item.attachments.find((candidate) => candidate.id === attachmentId);
  if (attachment === undefined) throw new Error("The attachment is not present in this vault item.");
  return attachment;
}

async function capture(
  runtime: ExtensionVaultRuntime,
  pageUrl: string,
  username: string | null,
  password: string,
): Promise<void> {
  if (password.length === 0 || password.length > 16_384 || (username?.length ?? 0) > 2_000) {
    throw new Error("Captured credential is outside supported limits.");
  }
  const url = new URL(pageUrl);
  pending = {
    pageUrl,
    name: url.hostname,
    username,
    password,
    capturedAt: Date.now(),
    matches: parse<CredentialSummary[]>(runtime.credentialsForUrl(pageUrl)),
  };
  await setBadge("1");
}

async function savePending(runtime: ExtensionVaultRuntime, existingId: string | null): Promise<VaultItem> {
  const candidate = currentPending();
  if (candidate === null) throw new Error("The captured credential expired.");
  let id: string;
  if (existingId === null) {
    id = runtime.createLogin(JSON.stringify({
      name: candidate.name,
      username: candidate.username,
      password: candidate.password,
      uri: candidate.pageUrl,
      totp: null,
      notes: null,
      favorite: false,
    } satisfies LoginDraft));
  } else {
    if (!candidate.matches.some((match) => match.id === existingId)) {
      throw new Error("The selected item does not match this page.");
    }
    id = existingId;
    runtime.updateCredentialFromPage(id, candidate.pageUrl, candidate.username ?? undefined, candidate.password);
  }
  await upload(runtime, id);
  clearPending();
  return parse<VaultItem>(runtime.getItem(id));
}

async function lock(manual: boolean): Promise<void> {
  const runtime = await runtimePromise;
  runtime.lock();
  cache = null;
  cursor = null;
  clearPending();
  pendingAccountWebauthn = null;
  for (const requestId of [...passkeyPrompts.keys()]) {
    settlePasskeyPrompt(requestId, { decision: "cancel", itemId: null, credentialId: null });
  }
  await browser.alarms.clear(LOCK_ALARM).catch(() => false);
  if (manual) {
    const record = await deviceSecrets.loadSession().catch(() => null);
    if (record !== null) await deviceSecrets.saveSession({ ...record, manualLockSuppressed: true, updatedAt: Date.now() }).catch(() => undefined);
  }
}

async function setAutoLock(minutes: number | null, runtime: ExtensionVaultRuntime): Promise<ExtensionState> {
  const normalized = normalizeAutoLock(minutes);
  const current = await ensureSettings();
  settings = { ...current, autoLockMinutes: normalized };
  await browser.storage.local.set({ [SETTINGS_KEY]: settings });
  if (normalized === null || !runtime.isUnlocked) {
    await browser.alarms.clear(LOCK_ALARM).catch(() => false);
  } else {
    await touch();
  }
  return state(runtime);
}

async function setRememberUnlock(enabled: boolean, runtime: ExtensionVaultRuntime): Promise<ExtensionState> {
  const session = api.session;
  const currentSettings = await ensureSettings();
  const record = await deviceSecrets.loadSession().catch(() => null);
  if (session === null || record === null || session.accountId !== record.accountId || session.deviceId !== record.deviceId) {
    throw new Error("The extension session is unavailable. Sign in again.");
  }
  if (enabled && !runtime.isUnlocked) {
    throw new Error("Unlock the vault before enabling remembered unlock.");
  }
  await persistUnlockAndSession(session, record.serverUrl || currentSettings.serverUrl, record.email, enabled, false, runtime);
  return state(runtime);
}

async function logout(): Promise<void> {
  const runtime = await runtimePromise;
  const record = await deviceSecrets.loadSession().catch(() => null);
  const session = api.session;
  try {
    if (session !== null) await api.logout();
  } finally {
    runtime.lock();
    api.clearSession();
    cache = null;
    cursor = null;
    clearPending();
    unlockContext = null;
    pendingAccountWebauthn = null;
    for (const requestId of [...passkeyPrompts.keys()]) {
      settlePasskeyPrompt(requestId, { decision: "cancel", itemId: null, credentialId: null });
    }
    await browser.alarms.clear(LOCK_ALARM).catch(() => false);
    const serverUrl = record?.serverUrl ?? settings?.serverUrl ?? null;
    const deviceId = record?.deviceId ?? session?.deviceId ?? null;
    const accountId = record?.accountId ?? session?.accountId ?? null;
    if (serverUrl !== null && deviceId !== null) await deviceSecrets.removeRefreshToken(serverUrl, deviceId).catch(() => undefined);
    if (serverUrl !== null && accountId !== null && deviceId !== null) {
      await deviceSecrets.removeUnlock(serverUrl, accountId, deviceId).catch(() => undefined);
    }
    await deviceSecrets.removeSession().catch(() => undefined);
    rememberedUnlockEnabled = false;
  }
}

function state(runtime: ExtensionVaultRuntime): ExtensionState {
  const authenticated = api.session !== null;
  const unlocked = runtime.isUnlocked && authenticated;
  const allItems = unlocked ? parse<ItemSummary[]>(runtime.listItems("", "all")) : [];
  return {
    authenticated,
    unlocked,
    autoLockMinutes: effectiveAutoLock(settings?.autoLockMinutes),
    rememberUnlock: rememberedUnlockEnabled,
    serverUrl: settings?.serverUrl ?? null,
    email: settings?.email ?? null,
    accountId: authenticated ? api.accountId : null,
    itemCount: allItems.length,
    pending: unlocked ? pendingSummary() : null,
  };
}

function requireUnlocked(runtime: ExtensionVaultRuntime): void {
  if (!runtime.isUnlocked || api.session === null) throw new Error("Vault is locked. Open the extension to unlock it.");
}

async function touch(): Promise<void> {
  const minutes = effectiveAutoLock(settings?.autoLockMinutes);
  if (minutes === null) {
    await browser.alarms.clear(LOCK_ALARM).catch(() => false);
    return;
  }
  await browser.alarms.create(LOCK_ALARM, { delayInMinutes: minutes });
}

async function initializeSettings(): Promise<void> {
  if (settings !== null) return;
  const stored = await browser.storage.local.get(SETTINGS_KEY);
  const candidate = stored[SETTINGS_KEY];
  if (isStoredSettings(candidate)) {
    settings = {
      ...candidate,
      autoLockMinutes: persistedAutoLock(candidate.autoLockMinutes),
    };
    api.configure(candidate.serverUrl);
  }
}

async function saveSettings(serverUrl: string, email: string): Promise<void> {
  const current = await ensureSettings();
  settings = {
    serverUrl,
    email,
    deviceIdentifier: current.deviceIdentifier,
    autoLockMinutes: effectiveAutoLock(current.autoLockMinutes),
  };
  api.configure(serverUrl);
  await browser.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function ensureSettings(): Promise<StoredSettings> {
  await initializeSettings();
  if (settings !== null) return settings;
  settings = { serverUrl: "", email: "", deviceIdentifier: crypto.randomUUID() };
  return settings;
}

async function deviceRequest(): Promise<{ identifier: string; name: string; deviceType: "extension" }> {
  const current = await ensureSettings();
  return { identifier: current.deviceIdentifier, name: "Hasilan Browser Extension", deviceType: "extension" };
}

function optional(value: string | null): string | null {
  const normalized = value?.trim() ?? "";
  return normalized === "" ? null : normalized;
}

function pendingSummary(): PendingCredentialSummary | null {
  const candidate = currentPending();
  if (candidate === null) return null;
  return {
    pageUrl: candidate.pageUrl,
    name: candidate.name,
    username: candidate.username,
    capturedAt: candidate.capturedAt,
    matches: candidate.matches,
  };
}

function currentPending(): PendingCredential | null {
  if (pending !== null && Date.now() - pending.capturedAt > PENDING_LIFETIME_MS) clearPending();
  return pending;
}

function clearPending(): void {
  if (pending !== null) pending.password = "";
  pending = null;
  void setBadge("");
}

async function setBadge(text: string): Promise<void> {
  await browser.action.setBadgeBackgroundColor({ color: "#6c6ff6" }).catch(() => undefined);
  await browser.action.setBadgeText({ text }).catch(() => undefined);
}

function assertContentPage(sender: Browser.Runtime.MessageSender, requested: string): void {
  if (sender.tab?.id === undefined || sender.url === undefined) throw new Error("This request is only available to page content scripts.");
  const actual = normalizedPage(sender.url);
  const claimed = normalizedPage(requested);
  if (actual !== claimed) throw new Error("The page URL did not match the requesting frame.");
}

async function createSitePasskey(
  runtime: ExtensionVaultRuntime,
  sender: Browser.Runtime.MessageSender,
  pageUrl: string,
  supplied: PasskeyCreationOptionsJson,
): Promise<PasskeyBridgeResult> {
  let origin: string;
  try {
    origin = passkeyPageOrigin(sender, pageUrl);
    requireUnlocked(runtime);
  } catch {
    return { status: "fallback" };
  }
  const options = { ...supplied, origin };
  let targets: PasskeyTarget[];
  try {
    targets = parse<PasskeyTarget[]>(runtime.passkeyCreationTargets(JSON.stringify(options)));
  } catch (error) {
    const detail = errorMessage(error);
    if (detail.includes("excluded passkey")) {
      return passkeyError("InvalidStateError", "A matching passkey already exists for this account.");
    }
    if (detail.includes("unsupported")) return { status: "fallback" };
    return passkeyError("SecurityError", "The passkey request did not match this page's origin.");
  }

  const rpId = supplied.rp.id?.toLowerCase() ?? new URL(origin).hostname;
  const approval = await requestPasskeyApproval({
    requestId: crypto.randomUUID(),
    kind: "create",
    origin,
    rpId,
    rpName: supplied.rp.name,
    userName: supplied.user.name,
    userDisplayName: supplied.user.displayName,
    targets,
    candidates: [],
  });
  if (approval.decision === "fallback") return { status: "fallback" };
  if (approval.decision !== "approve") {
    return passkeyError("NotAllowedError", "Passkey creation was cancelled.");
  }

  let result: {
    itemId: string;
    credentialId: string;
    clientDataJSON: string;
    attestationObject: string;
    authenticatorData: string;
    publicKey: string;
    publicKeyAlgorithm: number;
    transports: string[];
    extensions: { credProps: { rk: boolean } };
  };
  let changedItemId: string | null = null;
  try {
    result = parse(runtime.createVaultPasskey(JSON.stringify(options), approval.itemId, true));
    changedItemId = result.itemId;
    await upload(runtime, result.itemId);
  } catch {
    if (changedItemId !== null) runtime.discardItemChanges(changedItemId);
    return passkeyError("UnknownError", "The encrypted passkey could not be saved.");
  }
  const { itemId: _itemId, ...publicResult } = result;
  return { status: "created", result: publicResult };
}

async function assertSitePasskey(
  runtime: ExtensionVaultRuntime,
  sender: Browser.Runtime.MessageSender,
  pageUrl: string,
  supplied: PasskeyAssertionOptionsJson,
): Promise<PasskeyBridgeResult> {
  let origin: string;
  try {
    origin = passkeyPageOrigin(sender, pageUrl);
    requireUnlocked(runtime);
  } catch {
    return { status: "fallback" };
  }
  if (supplied.mediation === "conditional") return { status: "fallback" };
  const options = { ...supplied, origin };
  let candidates: PasskeyCandidate[];
  try {
    candidates = parse<PasskeyCandidate[]>(runtime.passkeyAssertionCandidates(JSON.stringify(options)));
  } catch (error) {
    return errorMessage(error).includes("unsupported")
      ? { status: "fallback" }
      : passkeyError("SecurityError", "The passkey request did not match this page's origin.");
  }
  if (candidates.length === 0) return { status: "fallback" };

  const rpId = supplied.rpId?.toLowerCase() ?? new URL(origin).hostname;
  const approval = await requestPasskeyApproval({
    requestId: crypto.randomUUID(),
    kind: "get",
    origin,
    rpId,
    rpName: rpId,
    userName: null,
    userDisplayName: null,
    targets: [],
    candidates,
  });
  if (approval.decision === "fallback") return { status: "fallback" };
  if (approval.decision !== "approve" || approval.itemId === null || approval.credentialId === null) {
    return passkeyError("NotAllowedError", "Passkey authentication was cancelled.");
  }

  let result: {
    itemId: string;
    credentialId: string;
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
    counterChanged: boolean;
  };
  let changedItemId: string | null = null;
  try {
    result = parse(runtime.assertVaultPasskey(
      JSON.stringify(options),
      approval.itemId,
      approval.credentialId,
      true,
    ));
    if (result.counterChanged) changedItemId = result.itemId;
    if (result.counterChanged) await upload(runtime, result.itemId);
  } catch {
    if (changedItemId !== null) runtime.discardItemChanges(changedItemId);
    return passkeyError("UnknownError", "The vault passkey could not complete this assertion.");
  }
  const { itemId: _itemId, counterChanged: _counterChanged, ...publicResult } = result;
  return { status: "asserted", result: publicResult };
}

function passkeyPageOrigin(sender: Browser.Runtime.MessageSender, requested: string): string {
  assertContentPage(sender, requested);
  if (sender.frameId !== 0 || sender.url === undefined) {
    throw new Error("Vault passkeys are limited to the top-level frame.");
  }
  return new URL(sender.url).origin;
}

function passkeyError(name: string, message: string): PasskeyBridgeResult {
  return { status: "error", name, message };
}

async function requestPasskeyApproval(prompt: PasskeyPrompt): Promise<PasskeyApproval> {
  const promise = new Promise<PasskeyApproval>((resolve, reject) => {
    const timeout = setTimeout(() => {
      const pendingPrompt = passkeyPrompts.get(prompt.requestId);
      if (pendingPrompt === undefined) return;
      passkeyPrompts.delete(prompt.requestId);
      reject(new Error("The passkey confirmation timed out."));
      if (pendingPrompt.windowId !== null) void browser.windows.remove(pendingPrompt.windowId).catch(() => undefined);
    }, 180_000);
    passkeyPrompts.set(prompt.requestId, {
      prompt,
      resolve,
      reject,
      timeout,
      windowId: null,
    });
  });
  try {
    const confirmation = await browser.windows.create({
      url: browser.runtime.getURL(`confirm.html#${encodeURIComponent(prompt.requestId)}`),
      type: "popup",
      width: 430,
      height: 620,
      focused: true,
    });
    const state = passkeyPrompts.get(prompt.requestId);
    if (state !== undefined) state.windowId = confirmation.id ?? null;
  } catch (error) {
    const state = passkeyPrompts.get(prompt.requestId);
    if (state !== undefined) {
      clearTimeout(state.timeout);
      passkeyPrompts.delete(prompt.requestId);
      state.reject(error instanceof Error ? error : new Error("Passkey confirmation could not open."));
    }
  }
  return promise.catch(() => ({ decision: "cancel", itemId: null, credentialId: null }));
}

async function respondToPasskeyPrompt(
  runtime: ExtensionVaultRuntime,
  message: Extract<ExtensionRequest, { type: "RESPOND_PASSKEY_PROMPT" }>,
): Promise<void> {
  const state = passkeyPrompts.get(message.requestId);
  if (state === undefined) throw new Error("This passkey request has expired.");
  if (message.decision !== "approve") {
    settlePasskeyPrompt(message.requestId, {
      decision: message.decision,
      itemId: null,
      credentialId: null,
    });
    return;
  }
  const context = unlockContext;
  if (context === null || !runtime.isUnlocked) throw new Error("Unlock the vault again before approving.");
  if (message.masterPassword === "" || !runtime.verifyMasterPassword(
    context.email,
    message.masterPassword,
    JSON.stringify(context.kdf),
    context.protectedUserKey,
  )) {
    throw new Error("The master password did not match this unlocked vault.");
  }
  if (state.prompt.kind === "create") {
    if (message.itemId !== null && !state.prompt.targets.some((target) => target.itemId === message.itemId)) {
      throw new Error("The selected vault item is not eligible for this relying party.");
    }
    settlePasskeyPrompt(message.requestId, {
      decision: "approve",
      itemId: message.itemId,
      credentialId: null,
    });
    return;
  }
  const candidate = state.prompt.candidates.find((value) => (
    value.itemId === message.itemId && value.credentialId === message.credentialId
  ));
  if (candidate === undefined) throw new Error("The selected passkey is not eligible for this request.");
  settlePasskeyPrompt(message.requestId, {
    decision: "approve",
    itemId: candidate.itemId,
    credentialId: candidate.credentialId,
  });
}

function settlePasskeyPrompt(requestId: string, approval: PasskeyApproval): void {
  const state = passkeyPrompts.get(requestId);
  if (state === undefined) return;
  clearTimeout(state.timeout);
  passkeyPrompts.delete(requestId);
  state.resolve(approval);
  if (state.windowId !== null) void browser.windows.remove(state.windowId).catch(() => undefined);
}

function assertExtensionPage(sender: Browser.Runtime.MessageSender): void {
  const expected = browser.runtime.getURL("");
  if (
    sender.url === undefined
    || !sender.url.startsWith(expected)
    || (sender.id !== undefined && sender.id !== browser.runtime.id)
  ) {
    throw new Error("This request is available only to an extension page.");
  }
}

function normalizedPage(value: string): string {
  const url = new URL(value);
  if (!matchesWebPage(url)) throw new Error("Autofill is available only on HTTP(S) pages.");
  url.hash = "";
  return url.href;
}

function matchesWebPage(url: URL): boolean {
  return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "";
}

async function registerSite(matchPattern: string, tabId: number): Promise<void> {
  const pattern = validateMatchPattern(matchPattern);
  const permitted = await browser.permissions.contains({ origins: [pattern] });
  if (!permitted) throw new Error("Site access was not granted by the browser.");
  const baseId = `hasilan-${await shortHash(pattern)}`;
  const isolatedId = `${baseId}-isolated`;
  const pageId = `${baseId}-main`;
  await browser.scripting.unregisterContentScripts({ ids: [isolatedId, pageId] }).catch(() => undefined);
  await browser.scripting.registerContentScripts([
    {
      id: isolatedId,
      js: [CONTENT_SCRIPT],
      matches: [pattern],
      allFrames: true,
      persistAcrossSessions: true,
      runAt: "document_start",
      world: "ISOLATED",
    },
    {
      id: pageId,
      js: [PASSKEY_PAGE_SCRIPT],
      matches: [pattern],
      allFrames: false,
      persistAcrossSessions: true,
      runAt: "document_start",
      world: "MAIN",
    },
  ]);
  await browser.scripting.executeScript({
    target: { tabId, allFrames: true },
    files: [CONTENT_SCRIPT],
    world: "ISOLATED",
  }).catch(() => undefined);
  await browser.scripting.executeScript({
    target: { tabId, allFrames: false },
    files: [PASSKEY_PAGE_SCRIPT],
    world: "MAIN",
  }).catch(() => undefined);
}

async function pruneRegistrations(): Promise<void> {
  const scripts = await browser.scripting.getRegisteredContentScripts();
  for (const script of scripts) {
    const matches = script.matches ?? [];
    if (!script.id.startsWith("hasilan-") || matches.length !== 1) continue;
    const allowed = await browser.permissions.contains({ origins: matches });
    if (!allowed) await browser.scripting.unregisterContentScripts({ ids: [script.id] });
  }
}

async function openMenuInTab(tabId: number): Promise<void> {
  const runtime = await runtimePromise;
  if (!runtime.isUnlocked) return;
  await browser.scripting.executeScript({ target: { tabId, allFrames: false }, files: [CONTENT_SCRIPT] }).catch(() => undefined);
  await browser.tabs.sendMessage(tabId, { channel: "hasilan-pass-content-v1", type: "OPEN_MENU" }).catch(() => undefined);
}

function validateMatchPattern(value: string): string {
  if (!value.endsWith("/*")) throw new Error("Invalid site permission pattern.");
  const origin = new URL(value.slice(0, -2));
  if (!matchesWebPage(origin) || `${origin.origin}/*` !== value) throw new Error("Invalid site permission pattern.");
  return value;
}

async function shortHash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest).slice(0, 12)].map((part) => part.toString(16).padStart(2, "0")).join("");
}

function isStoredSettings(value: unknown): value is StoredSettings {
  return typeof value === "object" && value !== null
    && "serverUrl" in value && typeof value.serverUrl === "string"
    && "email" in value && typeof value.email === "string"
    && "deviceIdentifier" in value && typeof value.deviceIdentifier === "string";
}

function parse<T>(value: string): T {
  return JSON.parse(value) as T;
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message.trim() !== "" ? error.message : "The extension operation failed.";
}
