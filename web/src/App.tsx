import { useCallback, useDeferredValue, useEffect, useRef, useState } from "react";

import { ApiClient, ApiError } from "./api";
import { EncryptedVaultCache } from "./cache";
import { AccountDialog } from "./components/AccountDialog";
import { AuthScreen } from "./components/AuthScreen";
import { GeneratorDialog } from "./components/GeneratorDialog";
import { FoldersDialog } from "./components/FoldersDialog";
import { glyphFor, ItemDetail } from "./components/ItemDetail";
import { ItemEditor } from "./components/ItemEditor";
import { LoginEditor } from "./components/LoginEditor";
import type { LoginDestination } from "./components/LoginEditor";
import { OrganizationsDialog } from "./components/OrganizationsDialog";
import { TransferDialog } from "./components/TransferDialog";
import type { SharedVaultRuntime } from "./runtime";
import { deviceIdentifier, downloadPlaintext, messageFromError } from "./security";
import { DeviceUnlockStore, TrustedDeviceStore, keyVersionFor, type WebSessionRecord } from "./trusted-device";
import { getWebauthnCredential } from "./webauthn";
import type {
  DeviceRequest,
  ImportResult,
  ItemSummary,
  KdfSettings,
  LoginDraft,
  LoginValue,
  RegistrationMaterial,
  SyncResponse,
  TokenResponse,
  TotpCode,
  VaultItem,
  SharingKeyMaterial,
  OrganizationResponse,
  CollectionResponse,
  AttachmentInitiateRequest,
  AttachmentMetadata,
  EditableItemDraft,
  EditableItemKind,
  FolderSummary,
} from "./types";

const ATTACHMENT_CHUNK_SIZE = 1024 * 1024;
const FALLBACK_ATTACHMENT_DOWNLOAD_LIMIT = 128 * 1024 * 1024;

const DEFAULT_KDF: KdfSettings = {
  kdfType: "argon2id",
  iterations: 6,
  memoryMib: 32,
  parallelism: 4,
};

const CATEGORIES = [
  ["all", "All items", "⌘"],
  ["favorites", "Favorites", "★"],
  ["logins", "Logins", "↗"],
  ["passkeys", "Passkeys", "◉"],
  ["cards", "Cards", "◇"],
  ["identities", "Identities", "◎"],
  ["notes", "Secure notes", "≡"],
  ["trash", "Trash", "⌫"],
] as const;

type Category = (typeof CATEGORIES)[number][0] | `folder:${string}`;
type AutoLockMinutes = 5 | 15 | 30 | 60 | 240;
type AutoLockSetting = AutoLockMinutes | null;
const AUTO_LOCK_MINUTES = [5, 15, 30, 60, 240] as const satisfies readonly AutoLockMinutes[];
type AuthState = "unauthenticated" | "locked" | "unlocked";

interface AppProps {
  runtime: SharedVaultRuntime;
}

export function App({ runtime }: AppProps) {
  const [api] = useState(() => new ApiClient());
  const [authState, setAuthState] = useState<AuthState>("unauthenticated");
  const [accountId, setAccountId] = useState<string | null>(null);
  const [accountEmail, setAccountEmail] = useState<string | null>(null);
  const [trustedDevices] = useState(() => new TrustedDeviceStore());
  const [deviceUnlocks] = useState(() => new DeviceUnlockStore());
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [folders, setFolders] = useState<FolderSummary[]>([]);
  const [category, setCategory] = useState<Category>("all");
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [editorItem, setEditorItem] = useState<VaultItem | null | undefined>(undefined);
  const [editorKind, setEditorKind] = useState<EditableItemKind>("login");
  const [newItemKind, setNewItemKind] = useState<EditableItemKind>("login");
  const [generatedForEditor, setGeneratedForEditor] = useState<string | undefined>(undefined);
  const [authBusy, setAuthBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [syncStatus, setSyncStatus] = useState<"idle" | "syncing" | "offline" | "error">("idle");
  const [showGenerator, setShowGenerator] = useState(false);
  const [showTransfer, setShowTransfer] = useState(false);
  const [showAccount, setShowAccount] = useState(false);
  const [showOrganizations, setShowOrganizations] = useState(false);
  const [pendingInvitationToken, setPendingInvitationToken] = useState(readInvitationToken);
  const [showFolders, setShowFolders] = useState(false);
  const [organizations, setOrganizations] = useState<OrganizationResponse[]>([]);
  const [organizationCollections, setOrganizationCollections] = useState<CollectionResponse[]>([]);
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [lockMinutes, setLockMinutes] = useState(readLockMinutes);
  const [rememberUnlock, setRememberUnlock] = useState(false);
  const cacheRef = useRef<EncryptedVaultCache | null>(null);
  const cursorRef = useRef<string | null>(null);
  const activityRef = useRef(Date.now());
  const channelRef = useRef<BroadcastChannel | null>(null);
  const restoreStartedRef = useRef(false);

  const clearStoredSession = useCallback(async (expectedSession?: TokenResponse | null): Promise<boolean> => {
    const record = await deviceUnlocks.loadSession().catch(() => null);
    if (
      expectedSession !== undefined
      && expectedSession !== null
      && record !== null
      && (record.accountId !== expectedSession.accountId || record.deviceId !== expectedSession.deviceId)
    ) {
      // A new account may have been signed in while the old refresh request completed. Never
      // delete the new account's durable resume state in response to the old rejection.
      return false;
    }
    if (record === null) {
      if (expectedSession === undefined) await deviceUnlocks.clearUnlocks().catch(() => undefined);
    } else {
      await deviceUnlocks.removeUnlock(record.accountId, record.deviceId).catch(() => undefined);
    }
    await deviceUnlocks.removeSession().catch(() => undefined);
    return true;
  }, [deviceUnlocks]);

  const clearVaultState = useCallback((reason: string | null) => {
    runtime.lock();
    cacheRef.current = null;
    cursorRef.current = null;
    setItems([]);
    setFolders([]);
    setSelectedItem(null);
    setEditorItem(undefined);
    setEditorKind("login");
    setNewItemKind("login");
    setGeneratedForEditor(undefined);
    setShowGenerator(false);
    setShowTransfer(false);
    setShowAccount(false);
    setShowOrganizations(false);
    setShowFolders(false);
    setOrganizations([]);
    setOrganizationCollections([]);
    setTotp(null);
    setSyncStatus("idle");
    setAuthError(reason);
  }, [runtime]);

  const clearSessionState = useCallback((reason: string | null) => {
    clearVaultState(reason);
    api.clearSession();
    setAccountId(null);
    setAccountEmail(null);
    setRememberUnlock(false);
    setAuthState("unauthenticated");
  }, [api, clearVaultState]);

  const lockVault = useCallback((reason: string | null, manual = false, broadcast = true) => {
    if (api.session === null) {
      clearSessionState(reason);
      return;
    }
    clearVaultState(reason);
    setAuthState("locked");
    if (manual) void deviceUnlocks.setManualLockSuppressed(true).catch(() => undefined);
    if (broadcast) channelRef.current?.postMessage({ type: "lock", manual });
  }, [api, clearSessionState, clearVaultState, deviceUnlocks]);

  const logoutVault = useCallback(async (reason: string | null = null): Promise<void> => {
    const current = api.session;
    try {
      if (current !== null) await api.logout();
    } finally {
      await clearStoredSession();
      clearSessionState(reason);
      channelRef.current?.postMessage({ type: "logout" });
    }
  }, [api, clearSessionState, clearStoredSession]);

  useEffect(() => {
    api.setSessionLostHandler((lostSession) => {
      if (
        lostSession !== null
        && api.session !== null
        && api.session.sessionId !== lostSession.sessionId
      ) return;
      void (async () => {
        if (await clearStoredSession(lostSession)) {
          clearSessionState("Your session expired or was revoked. Sign in again.");
        }
      })();
    });
  }, [api, clearSessionState, clearStoredSession]);

  useEffect(() => {
    const readFragment = () => setPendingInvitationToken(readInvitationToken());
    window.addEventListener("hashchange", readFragment);
    return () => window.removeEventListener("hashchange", readFragment);
  }, []);

  useEffect(() => {
    if (accountId !== null && pendingInvitationToken !== null) setShowOrganizations(true);
  }, [accountId, pendingInvitationToken]);

  useEffect(() => {
    if (typeof BroadcastChannel === "undefined") return undefined;
    const channel = new BroadcastChannel("hasilan-pass-control-v1");
    channelRef.current = channel;
    channel.onmessage = (event: MessageEvent<unknown>) => {
      if (isLockMessage(event.data)) lockVault("The vault was locked from another tab.", event.data.manual === true, false);
      if (isLogoutMessage(event.data)) {
        void (async () => {
          await clearStoredSession();
          clearSessionState("You signed out in another tab.");
        })();
      }
    };
    return () => {
      channel.close();
      channelRef.current = null;
    };
  }, [api, clearSessionState, clearStoredSession, lockVault]);

  useEffect(() => {
    if (restoreStartedRef.current) return undefined;
    restoreStartedRef.current = true;
    let cancelled = false;
    void (async () => {
      const record = await deviceUnlocks.loadSession().catch(() => null);
      if (cancelled || api.session !== null) return;
      if (record === null) {
        await deviceUnlocks.clearUnlocks().catch(() => undefined);
        return;
      }
      try {
        const session = await api.restoreWebSession(record);
        if (cancelled) return;
        if (session.accountId !== record.accountId || session.deviceId !== record.deviceId) {
          throw new Error("The remembered session belongs to another account or device.");
        }
        const sessionKeyVersion = await keyVersionFor(session.protectedUserKey, session.kdf);
        const rememberedKeyCurrent = record.keyVersion === undefined || record.keyVersion === sessionKeyVersion;
        const shouldRememberUnlock = record.rememberUnlock && rememberedKeyCurrent;
        setAccountId(session.accountId);
        setAccountEmail(record.email);
        setRememberUnlock(shouldRememberUnlock);
        if (record.rememberUnlock && !rememberedKeyCurrent) {
          await deviceUnlocks.removeUnlock(record.accountId, record.deviceId).catch(() => undefined);
        }
        if (shouldRememberUnlock && !record.manualLockSuppressed) {
          const key = await deviceUnlocks.loadUnlock(session.accountId, record.deviceId, sessionKeyVersion);
          if (key === null) throw new Error("The remembered device unlock is unavailable.");
          try {
            runtime.unlockWithUserKey(key);
            // Add key-version metadata when migrating an older envelope.
            await deviceUnlocks.saveUnlock(session.accountId, record.deviceId, key, sessionKeyVersion);
          } finally {
            key.fill(0);
          }
          await enterVault(session);
        } else {
          setAuthState("locked");
          setAuthError("Session resumed. Unlock the vault to continue.");
        }
        await persistSessionRecord(record.email, shouldRememberUnlock, record.manualLockSuppressed, sessionKeyVersion);
      } catch (error) {
        const resumeError = `Session resume failed: ${messageFromError(error)}`;
        // A revoked/expired server session must remove every local resume capability. A network
        // or temporary server failure must not turn a reload into an irreversible local logout;
        // keep the encrypted record so a later reload can retry. Local unlock corruption is
        // discarded, but the authenticated session record remains available for retry.
        const serverRejected = (error instanceof ApiError && (error.status === 401 || error.status === 403))
          || (error instanceof Error && error.message.startsWith("The remembered session belongs"));
        if (serverRejected || !(error instanceof ApiError)) {
          await deviceUnlocks.removeUnlock(record.accountId, record.deviceId).catch(() => undefined);
        }
        if (serverRejected) await deviceUnlocks.removeSession().catch(() => undefined);
        else if (!(error instanceof ApiError)) {
          // A local envelope failure is not a server logout, but the unusable remembered-unlock
          // preference should be disabled so the next reload falls back to password unlock.
          await deviceUnlocks.saveSession({
            ...record,
            rememberUnlock: false,
            manualLockSuppressed: false,
            updatedAt: Date.now(),
          }).catch(() => undefined);
        }
        clearSessionState(null);
        setAuthError(resumeError);
      }
    })();
    return () => {
      cancelled = true;
    };
  // Initial session restoration must run once for this runtime instance.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (notice === null) return undefined;
    const timer = window.setTimeout(() => setNotice(null), 6_000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (accountId === null) return undefined;
    if (lockMinutes === null) return undefined;
    const markActivity = () => { activityRef.current = Date.now(); };
    window.addEventListener("pointerdown", markActivity, { passive: true, capture: true });
    window.addEventListener("keydown", markActivity, { capture: true });
    window.addEventListener("touchstart", markActivity, { passive: true, capture: true });
    const timer = window.setInterval(() => {
      if (Date.now() - activityRef.current >= lockMinutes * 60_000) {
        lockVault("Vault locked after inactivity.");
      }
    }, 10_000);
    return () => {
      window.removeEventListener("pointerdown", markActivity, { capture: true });
      window.removeEventListener("keydown", markActivity, { capture: true });
      window.removeEventListener("touchstart", markActivity, { capture: true });
      window.clearInterval(timer);
    };
  }, [accountId, lockMinutes, lockVault]);

  useEffect(() => {
    if (accountId === null) return undefined;
    const refreshEvery = Math.max(60, Math.floor((api.session?.expiresIn ?? 900) * 0.75)) * 1_000;
    const timer = window.setInterval(() => {
      void api.refresh()
        .then(() => persistSessionRecord(accountEmail ?? "", undefined, undefined))
        .catch(() => undefined);
    }, refreshEvery);
    return () => window.clearInterval(timer);
  }, [accountId, api]);

  const refreshItems = useCallback(() => {
    if (!runtime.isUnlocked) {
      setItems([]);
      return;
    }
    const json = runtime.listItems(deferredQuery, category);
    setItems(parseJson<ItemSummary[]>(json));
    setFolders(parseJson<FolderSummary[]>(runtime.listFolders()));
  }, [category, deferredQuery, runtime]);

  useEffect(() => refreshItems(), [refreshItems]);

  useEffect(() => {
    if (selectedItem?.data.kind !== "login") {
      setTotp(null);
      return undefined;
    }
    const login = selectedItem.data.value as LoginValue;
    if (login.totp === null) {
      setTotp(null);
      return undefined;
    }
    const update = () => {
      try {
        setTotp(parseJson<TotpCode>(runtime.totpForItem(selectedItem.id, BigInt(Math.floor(Date.now() / 1_000)))));
      } catch {
        setTotp(null);
      }
    };
    update();
    const timer = window.setInterval(update, 1_000);
    return () => window.clearInterval(timer);
  }, [runtime, selectedItem]);

  async function login(
    email: string,
    password: string,
    secondFactor: string | null,
    rememberDevice: boolean,
    rememberUnlock: boolean,
  ): Promise<void> {
    setAuthBusy(true);
    setAuthError(null);
    try {
      email = email.trim().toLowerCase();
      const kdf = await api.prelogin(email);
      const authProof = runtime.prepareLogin(email, password, JSON.stringify(kdf));
      password = "";
      const device = webDevice();
      const normalizedFactor = optional(secondFactor);
      const totpCode = normalizedFactor !== null && /^[0-9 -]{6,12}$/u.test(normalizedFactor)
        ? normalizedFactor
        : null;
      const recoveryCode = normalizedFactor !== null && totpCode === null ? normalizedFactor : null;
      const trustedDeviceToken = normalizedFactor === null
        ? await trustedDevices.load(email, device.identifier).catch(() => null)
        : null;
      let session: TokenResponse;
      try {
        session = await api.login({
          email,
          authProof,
          device,
          totpCode,
          recoveryCode,
          trustedDeviceToken,
          rememberDevice,
        });
        runtime.finishLogin(session.protectedUserKey);
        await rememberSession(session, email, rememberUnlock);
        if (session.trustedDeviceToken !== null) {
          await trustedDevices.save(email, device.identifier, session.trustedDeviceToken);
        }
      } catch (error) {
        if (error instanceof ApiError && error.code === "mfa_required" && trustedDeviceToken !== null) {
          await trustedDevices.remove(email, device.identifier).catch(() => undefined);
        }
        runtime.lock();
        api.clearSession();
        throw error;
      }
      setAccountEmail(email);
      await enterVault(session);
    } catch (error) {
      setAuthError(messageFromError(error));
    } finally {
      setAuthBusy(false);
    }
  }

  async function webauthnMfaLogin(
    email: string,
    password: string,
    rememberDevice: boolean,
    rememberUnlock: boolean,
  ): Promise<void> {
    setAuthBusy(true);
    setAuthError(null);
    try {
      email = email.trim().toLowerCase();
      const kdf = await api.prelogin(email);
      const authProof = runtime.prepareLogin(email, password, JSON.stringify(kdf));
      password = "";
      const device = webDevice();
      const challenge = await api.startWebauthnMfaLogin({ email, authProof, device });
      const credential = await getWebauthnCredential(challenge.options);
      const session = await api.finishWebauthnLogin({
        ceremonyId: challenge.ceremonyId,
        credential,
        rememberDevice,
      });
      runtime.finishLogin(session.protectedUserKey);
      await rememberSession(session, email, rememberUnlock);
      if (session.trustedDeviceToken !== null) {
        await trustedDevices.save(email, device.identifier, session.trustedDeviceToken);
      }
      setAccountEmail(email);
      await enterVault(session);
    } catch (error) {
      runtime.lock();
      api.clearSession();
      setAuthError(messageFromError(error));
    } finally {
      setAuthBusy(false);
    }
  }

  async function passkeyLogin(
    email: string,
    password: string,
    rememberDevice: boolean,
    rememberUnlock: boolean,
  ): Promise<void> {
    setAuthBusy(true);
    setAuthError(null);
    try {
      email = email.trim().toLowerCase();
      const kdf = await api.prelogin(email);
      runtime.prepareLogin(email, password, JSON.stringify(kdf));
      password = "";
      const device = webDevice();
      const challenge = await api.startPasskeyLogin({ email, device });
      const credential = await getWebauthnCredential(challenge.options);
      const session = await api.finishWebauthnLogin({
        ceremonyId: challenge.ceremonyId,
        credential,
        rememberDevice,
      });
      runtime.finishLogin(session.protectedUserKey);
      await rememberSession(session, email, rememberUnlock);
      if (session.trustedDeviceToken !== null) {
        await trustedDevices.save(email, device.identifier, session.trustedDeviceToken);
      }
      setAccountEmail(email);
      await enterVault(session);
    } catch (error) {
      runtime.lock();
      api.clearSession();
      setAuthError(messageFromError(error));
    } finally {
      setAuthBusy(false);
    }
  }

  async function register(email: string, password: string): Promise<void> {
    setAuthBusy(true);
    setAuthError(null);
    try {
      email = email.trim().toLowerCase();
      const material = parseJson<RegistrationMaterial>(
        runtime.prepareRegistration(email, password, JSON.stringify(DEFAULT_KDF)),
      );
      password = "";
      await api.register({
        email,
        authProof: material.authProof,
        protectedUserKey: material.protectedUserKey,
        kdf: DEFAULT_KDF,
        device: webDevice(),
      });
      const session = await api.login({
        email,
        authProof: material.authProof,
        device: webDevice(),
        totpCode: null,
        recoveryCode: null,
        trustedDeviceToken: null,
        rememberDevice: false,
      });
      await rememberSession(session, email, false);
      setAccountEmail(email.trim().toLowerCase());
      await enterVault(session);
    } catch (error) {
      runtime.lock();
      api.clearSession();
      setAuthError(messageFromError(error));
    } finally {
      setAuthBusy(false);
    }
  }

  async function unlockWithPassword(email: string, password: string, rememberUnlock: boolean): Promise<void> {
    setAuthBusy(true);
    setAuthError(null);
    try {
      const session = api.session;
      if (session === null || accountId === null || accountEmail === null) {
        throw new Error("The account session is unavailable. Sign in again.");
      }
      const normalizedEmail = email.trim().toLowerCase();
      if (normalizedEmail !== accountEmail.toLowerCase()) throw new Error("Use the email address for this account.");
      runtime.prepareLogin(normalizedEmail, password, JSON.stringify(session.kdf));
      password = "";
      runtime.finishLogin(session.protectedUserKey);
      await rememberSession(session, normalizedEmail, rememberUnlock);
      await deviceUnlocks.setManualLockSuppressed(false).catch(() => undefined);
      await enterVault(session);
    } catch (error) {
      runtime.lock();
      setAuthError(messageFromError(error));
    } finally {
      setAuthBusy(false);
    }
  }

  async function rememberSession(session: TokenResponse, email: string, rememberUnlock: boolean): Promise<void> {
    setRememberUnlock(rememberUnlock);
    if (api.csrfToken === null) throw new Error("The browser session did not return a CSRF token.");
    const keyVersion = await keyVersionFor(session.protectedUserKey, session.kdf);
    if (!rememberUnlock) {
      await deviceUnlocks.removeUnlock(session.accountId, session.deviceId);
    } else {
      const key = runtime.exportUserKey();
      try {
        await deviceUnlocks.saveUnlock(session.accountId, session.deviceId, key, keyVersion);
      } finally {
        key.fill(0);
      }
    }
    const record: WebSessionRecord = {
      accountId: session.accountId,
      email: email.trim().toLowerCase(),
      deviceId: session.deviceId,
      csrfToken: api.csrfToken,
      kdf: session.kdf,
      protectedUserKey: session.protectedUserKey,
      keyVersion,
      rememberUnlock,
      manualLockSuppressed: false,
      updatedAt: Date.now(),
    };
    await deviceUnlocks.saveSession(record);
  }

  async function persistSessionRecord(
    emailOverride?: string,
    rememberUnlockOverride?: boolean,
    manualLockSuppressedOverride?: boolean,
    keyVersionOverride?: string,
  ): Promise<void> {
    const session = api.session;
    if (session === null || api.csrfToken === null) return;
    const keyVersion = keyVersionOverride ?? await keyVersionFor(session.protectedUserKey, session.kdf);
    const existing = await deviceUnlocks.loadSession();
    const email = emailOverride?.trim().toLowerCase() || existing?.email || accountEmail?.toLowerCase() || "";
    if (email === "") return;
    await deviceUnlocks.saveSession({
      accountId: session.accountId,
      email,
      deviceId: session.deviceId,
      csrfToken: api.csrfToken,
      kdf: session.kdf,
      protectedUserKey: session.protectedUserKey,
      keyVersion,
      rememberUnlock: rememberUnlockOverride ?? existing?.rememberUnlock ?? false,
      manualLockSuppressed: manualLockSuppressedOverride ?? existing?.manualLockSuppressed ?? false,
      updatedAt: Date.now(),
    });
  }

  async function changeRememberUnlock(enabled: boolean): Promise<void> {
    const session = api.session;
    // Registration enters the vault immediately after persisting the session. React may not
    // have committed `accountEmail` yet when the first sidebar interaction arrives, so use the
    // durable record as the source of truth during that short transition as well.
    const storedSession = accountEmail === null
      ? await deviceUnlocks.loadSession().catch(() => null)
      : null;
    const email = accountEmail ?? storedSession?.email ?? null;
    if (session === null || email === null) return;
    if (enabled && !runtime.isUnlocked) {
      setAuthError("Unlock the vault before enabling remembered unlock.");
      return;
    }
    const previous = rememberUnlock;
    // Reflect the native checkbox immediately. Persistence is asynchronous; if it fails, the
    // caller displays the error and we restore the previous controlled value below.
    setRememberUnlock(enabled);
    try {
      if (enabled) {
        const key = runtime.exportUserKey();
        try {
          await deviceUnlocks.saveUnlock(
            session.accountId,
            session.deviceId,
            key,
            await keyVersionFor(session.protectedUserKey, session.kdf),
          );
        } finally {
          key.fill(0);
        }
      } else {
        await deviceUnlocks.removeUnlock(session.accountId, session.deviceId);
      }
      await persistSessionRecord(email, enabled, false);
      setNotice(enabled ? "This device will remember the encrypted vault unlock." : "Remembered unlock removed from this device.");
    } catch (error) {
      setRememberUnlock(previous);
      throw error;
    }
  }

  async function enterVault(session: TokenResponse): Promise<void> {
    await reloadOrganizations();
    const cache = new EncryptedVaultCache(session.accountId);
    cacheRef.current = cache;
    cursorRef.current = null;
    let cacheValid = true;
    try {
      const snapshot = await cache.load();
      for (const object of snapshot.objects) {
        try {
          runtime.acceptObject(JSON.stringify(object));
        } catch {
          cacheValid = false;
          break;
        }
      }
      if (cacheValid) cursorRef.current = snapshot.cursor;
    } catch {
      cacheValid = false;
    }
    if (!cacheValid) {
      cursorRef.current = null;
      await cache.clear().catch(() => undefined);
      setNotice("The local encrypted cache was invalid and has been discarded. A full sync will repair it.");
    }

    setAccountId(session.accountId);
    setAuthState("unlocked");
    activityRef.current = Date.now();
    try {
      await syncVault(cache);
      setSyncStatus("idle");
    } catch (error) {
      setSyncStatus(navigator.onLine ? "error" : "offline");
      setNotice(`Unlocked, but synchronization failed: ${messageFromError(error)}`);
    }
  }

  async function reloadOrganizations(): Promise<void> {
    let sharingKey;
    try {
      sharingKey = await api.sharingKey();
    } catch (error) {
      if (!(error instanceof ApiError) || error.code !== "sharing_key_not_found") throw error;
      const generated = parseJson<SharingKeyMaterial>(runtime.generateSharingKey());
      try {
        sharingKey = await api.putSharingKey(generated);
      } catch (installError) {
        if (!(installError instanceof ApiError) || installError.code !== "sharing_key_exists") {
          throw installError;
        }
        sharingKey = await api.sharingKey();
      }
    }
    if (sharingKey.protectedPrivateKey === null) {
      throw new Error("The account sharing private key is unavailable.");
    }
    runtime.installSharingKey(sharingKey.publicKey, sharingKey.protectedPrivateKey);
    const nextOrganizations = await api.listOrganizations();
    const activeOrganizationIds = nextOrganizations
      .filter((organization) => ["accepted", "confirmed"].includes(organization.status))
      .map((organization) => organization.id);
    runtime.retainOrganizationAccess(JSON.stringify(activeOrganizationIds));
    runtime.clearOrganizationKeys();
    for (const organization of nextOrganizations) {
      if (
        ["accepted", "confirmed"].includes(organization.status)
        && organization.encryptedOrganizationKey !== null
      ) {
        runtime.openOrganizationKey(organization.id, organization.encryptedOrganizationKey);
      }
    }
    const collectionPages = await Promise.all(
      nextOrganizations
        .filter((organization) => organization.status === "confirmed")
        .map((organization) => api.listCollections(organization.id)),
    );
    setOrganizations(nextOrganizations);
    setOrganizationCollections(collectionPages.flat());
  }

  async function syncVault(cache = cacheRef.current): Promise<void> {
    if (cache === null) return;
    setSyncStatus("syncing");
    let pageCount = 0;
    while (true) {
      const previousCursor = cursorRef.current;
      const page = await api.sync(previousCursor);
      runtime.applySyncPage(JSON.stringify(page));
      await cache.applySyncPage(page);
      cursorRef.current = page.nextCursor;
      pageCount += 1;
      if (!page.hasMore) break;
      if (page.nextCursor === previousCursor || pageCount > 1_000) {
        throw new Error("The sync feed did not make progress.");
      }
    }
    setSyncStatus("idle");
    refreshItems();
    if (selectedItem !== null) selectItem(selectedItem.id);
  }

  async function manualSync(): Promise<void> {
    try {
      await reloadOrganizations();
      await syncVault();
      setNotice("Vault synchronized.");
    } catch (error) {
      setSyncStatus(navigator.onLine ? "error" : "offline");
      setNotice(`Synchronization failed: ${messageFromError(error)}`);
    }
  }

  function selectItem(id: string): void {
    try {
      setSelectedItem(parseJson<VaultItem>(runtime.getItem(id)));
    } catch (error) {
      setNotice(messageFromError(error));
    }
  }

  async function saveLogin(
    draft: LoginDraft,
    existing: VaultItem | null,
    destination: LoginDestination,
    folderId: string | null,
  ): Promise<void> {
    await saveEditedItem("login", draft, existing, destination, folderId);
  }

  async function saveGenericItem(
    draft: EditableItemDraft,
    existing: VaultItem | null,
    destination: LoginDestination,
    folderId: string | null,
  ): Promise<void> {
    await saveEditedItem(draft.data.kind, draft, existing, destination, folderId);
  }

  async function saveEditedItem(
    kind: EditableItemKind,
    draft: LoginDraft | EditableItemDraft,
    existing: VaultItem | null,
    destination: LoginDestination,
    folderId: string | null,
  ): Promise<void> {
    if (accountId === null) return;
    setActionBusy(true);
    let id: string | null = null;
    try {
      const serializedDraft = JSON.stringify(draft);
      if (existing === null) {
        id = kind === "login"
          ? runtime.createLogin(serializedDraft)
          : runtime.createItem(serializedDraft);
      } else {
        id = existing.id;
        if (kind === "login") {
          runtime.updateLogin(id, serializedDraft);
        } else {
          runtime.updateItem(id, serializedDraft);
        }
      }
      runtime.assignItemDestination(
        id,
        destination.organizationId ?? undefined,
        JSON.stringify(destination.collectionIds),
      );
      runtime.assignItemFolder(id, destination.organizationId === null ? folderId : undefined);
      const request = runtime.buildPutRequest(id, accountId);
      const object = await api.putEncryptedObject(id, request);
      runtime.acceptObject(JSON.stringify(object));
      await cacheRef.current?.saveObject(object);
      refreshItems();
      selectItem(id);
      setEditorItem(undefined);
      setGeneratedForEditor(undefined);
      setNotice("Item encrypted and synchronized.");
    } catch (error) {
      if (id !== null) {
        try {
          setEditorItem(parseJson<VaultItem>(runtime.getItem(id)));
          setEditorKind(kind);
        } catch {
          // Preserve the existing editor state when local validation failed.
        }
      }
      if (error instanceof ApiError && error.status === 409) {
        await manualSync();
        setNotice("Another client changed this item. The latest server version is loaded; review and save again.");
      } else {
        setNotice(`Save failed: ${messageFromError(error)}`);
      }
    } finally {
      setActionBusy(false);
    }
  }

  async function synchronizeFolder(id: string): Promise<void> {
    if (accountId === null) throw new Error("Vault is locked.");
    const request = runtime.buildFolderPutRequest(id, accountId);
    const object = await api.putEncryptedObject(id, request);
    runtime.acceptObject(JSON.stringify(object));
    await cacheRef.current?.saveObject(object);
  }

  async function createFolder(name: string): Promise<void> {
    setActionBusy(true);
    let id: string | null = null;
    try {
      id = runtime.createFolder(name);
      await synchronizeFolder(id);
      refreshItems();
      setNotice("Folder name encrypted and synchronized.");
    } catch (error) {
      if (id !== null) {
        try { runtime.discardFolderChanges(id); } catch { /* Retain the original synchronization error. */ }
      }
      refreshItems();
      setNotice(`Folder creation failed: ${messageFromError(error)}`);
    } finally {
      setActionBusy(false);
    }
  }

  async function renameFolder(id: string, name: string): Promise<void> {
    setActionBusy(true);
    try {
      runtime.updateFolder(id, name);
      await synchronizeFolder(id);
      refreshItems();
      setNotice("Folder renamed and synchronized.");
    } catch (error) {
      try { runtime.discardFolderChanges(id); } catch { /* Retain the original synchronization error. */ }
      refreshItems();
      if (error instanceof ApiError && error.status === 409) await manualSync();
      setNotice(`Folder rename failed: ${messageFromError(error)}`);
    } finally {
      setActionBusy(false);
    }
  }

  async function deleteFolder(folder: FolderSummary): Promise<void> {
    if (!window.confirm(`Delete folder “${folder.name}”? Items will remain in the vault without a folder.`)) return;
    setActionBusy(true);
    try {
      const itemIds = parseJson<string[]>(runtime.detachFolder(folder.id));
      for (const itemId of itemIds) {
        if (accountId === null) throw new Error("Vault is locked.");
        const itemRequest = runtime.buildPutRequest(itemId, accountId);
        const itemObject = await api.putEncryptedObject(itemId, itemRequest);
        runtime.acceptObject(JSON.stringify(itemObject));
        await cacheRef.current?.saveObject(itemObject);
      }
      const request = runtime.buildDeleteRequest(folder.id);
      const object = await api.deleteEncryptedObject(folder.id, request);
      runtime.acceptObject(JSON.stringify(object));
      await cacheRef.current?.saveObject(object);
      if (category === `folder:${folder.id}`) setCategory("all");
      refreshItems();
      setNotice("Folder deleted; its items remain in the personal vault.");
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) await manualSync();
      refreshItems();
      setNotice(`Folder deletion stopped safely: ${messageFromError(error)}`);
    } finally {
      setActionBusy(false);
    }
  }

  async function deleteSelected(): Promise<void> {
    if (selectedItem === null) return;
    if (!window.confirm(`Move “${selectedItem.name}” to trash?`)) return;
    setActionBusy(true);
    try {
      const request = runtime.buildDeleteRequest(selectedItem.id);
      const object = await api.deleteEncryptedObject(selectedItem.id, request);
      runtime.acceptObject(JSON.stringify(object));
      await cacheRef.current?.saveObject(object);
      setSelectedItem(parseJson<VaultItem>(runtime.getItem(selectedItem.id)));
      refreshItems();
      setNotice("Item moved to trash.");
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) await manualSync();
      setNotice(`Delete failed: ${messageFromError(error)}`);
    } finally {
      setActionBusy(false);
    }
  }

  async function uploadAttachment(file: File, existing?: AttachmentMetadata): Promise<void> {
    if (selectedItem === null || accountId === null) return;
    if (existing !== undefined && (file.name !== existing.fileName || file.size !== existing.size)) {
      setNotice("Choose the same filename and byte length to resume this encrypted upload.");
      return;
    }
    setActionBusy(true);
    let metadata = existing;
    let generatedLocally = false;
    let metadataSynchronized = existing !== undefined;
    try {
      if (metadata === undefined) {
        metadata = parseJson<AttachmentMetadata>(runtime.createAttachment(
          selectedItem.id,
          file.name,
          file.type || "application/octet-stream",
          BigInt(file.size),
          ATTACHMENT_CHUNK_SIZE,
        ));
        generatedLocally = true;
        const object = await api.putEncryptedObject(
          selectedItem.id,
          runtime.buildPutRequest(selectedItem.id, accountId),
        );
        runtime.acceptObject(JSON.stringify(object));
        await cacheRef.current?.saveObject(object);
        metadataSynchronized = true;
      }

      const initiateRequest = parseJson<AttachmentInitiateRequest>(
        runtime.attachmentInitiateRequest(selectedItem.id, metadata.id),
      );
      let upload;
      if (existing === undefined) {
        upload = await api.initiateAttachment(JSON.stringify(initiateRequest));
      } else {
        try {
          upload = await api.attachmentStatus(metadata.id);
        } catch (error) {
          if (!(error instanceof ApiError) || error.status !== 404) throw error;
          upload = await api.initiateAttachment(JSON.stringify(initiateRequest));
        }
      }
      if (upload.state !== "complete") {
        for (let index = 0; index < metadata.chunkCount; index += 1) {
          const start = index * metadata.chunkSize;
          const end = Math.min(file.size, start + metadata.chunkSize);
          const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
          let ciphertext: Uint8Array;
          try {
            ciphertext = runtime.encryptAttachmentChunk(
              selectedItem.id,
              metadata.id,
              index,
              plaintext,
            );
          } finally {
            plaintext.fill(0);
          }
          try {
            await api.putAttachmentChunk(metadata.id, index, ciphertext);
          } finally {
            ciphertext.fill(0);
          }
          setNotice(`Encrypted attachment upload ${index + 1}/${metadata.chunkCount}…`);
        }
        await api.completeAttachment(metadata.id, initiateRequest.objectRevision);
      }
      refreshItems();
      selectItem(selectedItem.id);
      setNotice(`“${metadata.fileName}” encrypted and uploaded.`);
    } catch (error) {
      if (generatedLocally && !metadataSynchronized) {
        try { runtime.discardItemChanges(selectedItem.id); } catch { /* authoritative state will return on sync */ }
      }
      if (error instanceof ApiError && error.code === "attachment_parent_changed") {
        await manualSync();
        setNotice("The item changed during upload. Select the same file and use Retry.");
      } else {
        selectItem(selectedItem.id);
        setNotice(`Attachment upload paused: ${messageFromError(error)} Select the same file and use Retry.`);
      }
    } finally {
      setActionBusy(false);
    }
  }

  async function downloadAttachment(attachment: AttachmentMetadata): Promise<void> {
    if (selectedItem === null) return;
    setActionBusy(true);
    let writer: AttachmentFileWriter | null = null;
    try {
      const status = await api.attachmentStatus(attachment.id);
      if (status.state !== "complete") throw new Error("The encrypted upload is not complete.");
      const picker = attachmentSavePicker();
      const fallbackParts: ArrayBuffer[] = [];
      if (picker !== null) {
        const handle = await picker({
          suggestedName: attachment.fileName,
        });
        writer = await handle.createWritable();
      } else if (attachment.size > FALLBACK_ATTACHMENT_DOWNLOAD_LIMIT) {
        throw new Error("This browser needs the File System Access API to stream downloads larger than 128 MiB.");
      }
      let downloadedBytes = 0;
      for (let index = 0; index < attachment.chunkCount; index += 1) {
        const ciphertext = await api.attachmentChunk(attachment.id, index);
        const plaintext = runtime.decryptAttachmentChunk(
          selectedItem.id,
          attachment.id,
          index,
          ciphertext,
        );
        downloadedBytes += plaintext.byteLength;
        try {
          if (writer !== null) {
            await writer.write(plaintext);
          } else {
            fallbackParts.push(plaintext.slice().buffer as ArrayBuffer);
          }
        } finally {
          plaintext.fill(0);
        }
        setNotice(`Decrypting attachment ${index + 1}/${attachment.chunkCount}…`);
      }
      if (downloadedBytes !== attachment.size) throw new Error("The attachment length did not authenticate.");
      if (writer !== null) {
        await writer.close();
        writer = null;
      } else {
        downloadBlob(attachment.fileName, attachment.mediaType, fallbackParts);
      }
      setNotice(`“${attachment.fileName}” authenticated and decrypted.`);
    } catch (error) {
      await writer?.abort().catch(() => undefined);
      setNotice(`Attachment download failed: ${messageFromError(error)}`);
    } finally {
      setActionBusy(false);
    }
  }

  async function removeAttachment(attachment: AttachmentMetadata): Promise<void> {
    if (selectedItem === null || accountId === null) return;
    if (!window.confirm(`Remove encrypted attachment “${attachment.fileName}”?`)) return;
    setActionBusy(true);
    let parentSynchronized = false;
    try {
      runtime.removeAttachment(selectedItem.id, attachment.id);
      const object = await api.putEncryptedObject(
        selectedItem.id,
        runtime.buildPutRequest(selectedItem.id, accountId),
      );
      parentSynchronized = true;
      runtime.acceptObject(JSON.stringify(object));
      await cacheRef.current?.saveObject(object);
      let cleanupWarning = "";
      try {
        await api.deleteAttachment(attachment.id);
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 404) {
          cleanupWarning = " The reference is gone, but encrypted server storage cleanup must be retried.";
        }
      }
      refreshItems();
      selectItem(selectedItem.id);
      setNotice(`Encrypted attachment removed.${cleanupWarning}`);
    } catch (error) {
      if (!parentSynchronized) {
        try { runtime.discardItemChanges(selectedItem.id); } catch { /* authoritative state will return on sync */ }
      }
      if (error instanceof ApiError && error.status === 409) await manualSync();
      setNotice(`Attachment removal failed: ${messageFromError(error)}`);
    } finally {
      setActionBusy(false);
    }
  }

  async function importVault(content: string): Promise<void> {
    if (accountId === null) return;
    setActionBusy(true);
    try {
      const result = parseJson<ImportResult>(runtime.importBitwardenJson(content));
      let uploaded = 0;
      let failed = 0;
      for (const id of result.folderIds) {
        try {
          await synchronizeFolder(id);
        } catch {
          failed += 1;
        }
      }
      for (const id of result.itemIds) {
        try {
          const request = runtime.buildPutRequest(id, accountId);
          const object = await api.putEncryptedObject(id, request);
          runtime.acceptObject(JSON.stringify(object));
          await cacheRef.current?.saveObject(object);
          uploaded += 1;
        } catch {
          failed += 1;
        }
      }
      refreshItems();
      setShowTransfer(false);
      setNotice(
        failed === 0
          ? `Imported and encrypted ${uploaded} items, ${result.folderCount} folders, and ${result.collectionCount} collections.`
          : `Imported ${result.itemCount} items and ${result.folderCount} folders locally; ${uploaded} items synchronized and ${failed} encrypted objects require attention. Verify that imported organization and collection IDs exist and are writable.`,
      );
    } finally {
      setActionBusy(false);
    }
  }

  function exportVault(): void {
    const content = runtime.exportBitwardenJson();
    const date = new Date().toISOString().slice(0, 10);
    downloadPlaintext(`hasilan-pass-bitwarden-${date}.json`, content);
    setShowTransfer(false);
    setNotice("Plaintext export downloaded. Store it safely and delete it after use.");
  }

  function changeLockMinutes(value: AutoLockSetting): void {
    setLockMinutes(value);
    activityRef.current = Date.now();
    try {
      localStorage.setItem("hasilan-pass-lock-minutes", value === null ? "never" : String(value));
    } catch { /* preference persistence is optional */ }
  }

  if (authState !== "unlocked") {
    return (
      <AuthScreen
        busy={authBusy}
        error={authError}
        initialEmail={accountEmail}
        locked={authState === "locked"}
        onLogin={login}
        onLogout={() => void logoutVault("You signed out of this browser.")}
        onUnlock={unlockWithPassword}
        onPasskeyLogin={passkeyLogin}
        onRegister={register}
        onWebauthnMfaLogin={webauthnMfaLogin}
      />
    );
  }

  return (
    <div className="vault-app">
      <aside className="vault-sidebar">
        <div className="sidebar-brand">
          <div className="brand-lock small" aria-hidden="true"><img alt="" src="/icons/hasilan-pass-icon.svg" /></div>
          <div><strong>Hasilan</strong><span>Pass</span></div>
        </div>
        <nav aria-label="Vault categories">
          <p className="nav-label">Vault</p>
          {CATEGORIES.map(([value, label, glyph]) => (
            <button className={category === value ? "active" : ""} key={value} onClick={() => { setCategory(value); setSelectedItem(null); }} type="button">
              <span aria-hidden="true">{glyph}</span>{label}
            </button>
          ))}
          <div className="folder-nav-heading"><p className="nav-label">Folders</p><button aria-label="Manage folders" onClick={() => setShowFolders(true)} type="button">＋</button></div>
          {folders.map((folder) => (
            <button className={category === `folder:${folder.id}` ? "active" : ""} key={folder.id} onClick={() => { setCategory(`folder:${folder.id}`); setSelectedItem(null); }} type="button">
              <span aria-hidden="true">▱</span><span className="folder-nav-name">{folder.name}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-security">
          <span className="security-pulse" aria-hidden="true" />
          <div><strong>End-to-end encrypted</strong><span>Keys live in this tab</span></div>
        </div>
        <label className="lock-setting">
          <span><input checked={rememberUnlock} onChange={(event) => void changeRememberUnlock(event.currentTarget.checked).catch((error) => setAuthError(messageFromError(error)))} type="checkbox" /> Remember unlock</span>
          <small className="remember-warning">Device access can unlock the vault; memory-only mode is stronger.</small>
        </label>
        <label className="lock-setting">
          Auto-lock
          <select
            onChange={(event) => changeLockMinutes(parseAutoLockSetting(event.target.value))}
            value={lockMinutes === null ? "never" : String(lockMinutes)}
          >
            <option value="5">5 minutes</option>
            <option value="15">15 minutes</option>
            <option value="30">30 minutes</option>
            <option value="60">1 hour</option>
            <option value="240">4 hours</option>
            <option value="never">Never</option>
          </select>
        </label>
      </aside>

      <main className="vault-main">
        <header className="vault-toolbar">
          <div className="search-box">
            <span aria-hidden="true">⌕</span>
            <input aria-label="Search vault" autoComplete="off" onChange={(event) => setQuery(event.target.value)} placeholder="Search your vault" spellCheck={false} value={query} />
            <kbd>⌘ K</kbd>
          </div>
          <div className="toolbar-actions">
            <span className={`sync-state ${syncStatus}`}><i />{syncLabel(syncStatus)}</span>
            <button className="quiet-button" disabled={syncStatus === "syncing"} onClick={() => void manualSync()} type="button">Sync</button>
            <button className="quiet-button" onClick={() => setShowGenerator(true)} type="button">Generate</button>
            <button className="quiet-button" onClick={() => setShowTransfer(true)} type="button">Transfer</button>
            <button className="quiet-button" onClick={() => setShowOrganizations(true)} type="button">Organizations</button>
            <button aria-label="Sessions and devices" className="avatar-button" onClick={() => setShowAccount(true)} type="button">HP</button>
          </div>
        </header>

        <section className="vault-list-region">
          <header className="list-heading">
            <div>
              <p className="eyebrow">Personal & organization vaults</p>
              <h1>{categoryTitle(category, folders)}</h1>
              <p>{items.length} {items.length === 1 ? "item" : "items"}{deferredQuery === "" ? "" : ` matching “${deferredQuery}”`}</p>
            </div>
            <div className="new-item-actions">
              <label>
                <span className="visually-hidden">New item type</span>
                <select
                  aria-label="New item type"
                  onChange={(event) => setNewItemKind(event.target.value as EditableItemKind)}
                  value={newItemKind}
                >
                  <option value="login">Login</option>
                  <option value="secureNote">Secure note</option>
                  <option value="card">Payment card</option>
                  <option value="identity">Identity</option>
                  <option value="sshKey">SSH key</option>
                </select>
              </label>
              <button aria-label={`New ${itemKindLabel(newItemKind).toLowerCase()}`} className="primary-button" onClick={() => { setGeneratedForEditor(undefined); setEditorKind(newItemKind); setEditorItem(null); }} type="button"><span>＋</span> New item</button>
            </div>
          </header>

          {items.length === 0 ? (
            <div className="empty-vault">
              <div aria-hidden="true">⌁</div>
              <h2>{deferredQuery === "" ? "Nothing here yet" : "No matching items"}</h2>
              <p>{deferredQuery === "" ? "Create a vault item or import a Bitwarden JSON export." : "Try another search phrase or category."}</p>
            </div>
          ) : (
            <div className="item-grid">
              {items.map((item) => (
                <button className={`item-card${selectedItem?.id === item.id ? " selected" : ""}`} key={item.id} onClick={() => selectItem(item.id)} type="button">
                  <span className="item-glyph" aria-hidden="true">{glyphFor(typeKind(item.itemType))}</span>
                  <span className="item-copy">
                    <strong>{item.name}</strong>
                    <span>{item.username ?? item.primaryUri ?? typeLabel(item.itemType)}{item.organizationId === null ? "" : ` · ${organizationName(item.organizationId, organizations)}`}</span>
                  </span>
                  <span className="item-signals">
                    {item.favorite ? <i title="Favorite">★</i> : null}
                    {item.hasTotp ? <i title="Authenticator code">◷</i> : null}
                    {item.passkeyCount > 0 ? <i title={`${item.passkeyCount} passkey(s)`}>◉</i> : null}
                  </span>
                  <span aria-hidden="true" className="item-chevron">›</span>
                </button>
              ))}
            </div>
          )}
        </section>
      </main>

      {selectedItem === null ? null : (
        <ItemDetail
          attachmentBusy={actionBusy}
          item={selectedItem}
          onAttach={(file, existing) => void uploadAttachment(file, existing)}
          onClose={() => setSelectedItem(null)}
          onDelete={() => void deleteSelected()}
          onDownloadAttachment={(attachment) => void downloadAttachment(attachment)}
          onEdit={() => {
            const kind = editableItemKind(selectedItem.data.kind);
            if (kind === null) {
              setNotice("This imported item type is preserved but does not have an editor yet.");
              return;
            }
            setGeneratedForEditor(undefined);
            setEditorKind(kind);
            setEditorItem(selectedItem);
          }}
          onNotice={setNotice}
          onRemoveAttachment={(attachment) => void removeAttachment(attachment)}
          totp={totp}
        />
      )}

      <button className="lock-button" onClick={() => lockVault("Vault locked. Your session remains active.", true)} type="button">⌑ Lock vault</button>
      <button className="logout-button" onClick={() => void logoutVault("You signed out of this browser.")} type="button">↪ Log out</button>
      {notice === null ? null : <div className="toast" role="status">{notice}</div>}

      {editorItem === undefined ? null : editorKind === "login" ? (
        <LoginEditor
          busy={actionBusy}
          destinations={loginDestinations(editorItem, organizations, organizationCollections)}
          folders={folders}
          generatedPassword={generatedForEditor}
          item={editorItem}
          onClose={() => { setEditorItem(undefined); setGeneratedForEditor(undefined); }}
          onSave={saveLogin}
        />
      ) : (
        <ItemEditor
          busy={actionBusy}
          destinations={loginDestinations(editorItem, organizations, organizationCollections)}
          folders={folders}
          item={editorItem}
          kind={editorKind}
          onClose={() => { setEditorItem(undefined); setGeneratedForEditor(undefined); }}
          onSave={saveGenericItem}
        />
      )}
      {showGenerator ? (
        <GeneratorDialog
          onClose={() => setShowGenerator(false)}
          onNotice={setNotice}
          onUse={(password) => { setShowGenerator(false); setGeneratedForEditor(password); setEditorKind("login"); setEditorItem(null); }}
          runtime={runtime}
        />
      ) : null}
      {showTransfer ? <TransferDialog busy={actionBusy} onClose={() => setShowTransfer(false)} onExport={exportVault} onImport={importVault} /> : null}
      {showFolders ? (
        <FoldersDialog
          busy={actionBusy}
          folders={folders}
          onClose={() => setShowFolders(false)}
          onCreate={createFolder}
          onDelete={deleteFolder}
          onRename={renameFolder}
        />
      ) : null}
      {showOrganizations ? (
        <OrganizationsDialog
          api={api}
          initialInvitationToken={pendingInvitationToken}
          onClose={() => setShowOrganizations(false)}
          onInvitationAccepted={() => {
            setPendingInvitationToken(null);
            clearInvitationFragment();
          }}
          onNotice={setNotice}
          onReload={reloadOrganizations}
          organizations={organizations}
          runtime={runtime}
        />
      ) : null}
      {showAccount && accountEmail !== null ? (
        <AccountDialog
          api={api}
          deriveAuthProof={(masterPassword) => {
            const session = api.session;
            if (session === null) throw new Error("The account session is unavailable.");
            return runtime.prepareLogin(accountEmail, masterPassword, JSON.stringify(session.kdf));
          }}
          onClose={() => setShowAccount(false)}
          onCurrentRevoked={() => void logoutVault("The current session was revoked.")}
          onNotice={setNotice}
          onTrustRevoked={(deviceId) => {
            if (api.session?.deviceId === deviceId) {
              void trustedDevices.remove(accountEmail, deviceIdentifier()).catch(() => undefined);
            }
          }}
        />
      ) : null}
    </div>
  );
}

function parseJson<T>(json: string): T {
  return JSON.parse(json) as T;
}

function optional(value: string | null): string | null {
  const normalized = value?.trim() ?? "";
  return normalized === "" ? null : normalized;
}

function webDevice(): DeviceRequest {
  return { identifier: deviceIdentifier(), name: "Hasilan Web Vault", deviceType: "web" };
}

function readLockMinutes(): AutoLockSetting {
  try {
    const stored = localStorage.getItem("hasilan-pass-lock-minutes");
    if (stored === "never") return null;
    const value = Number(stored);
    if (AUTO_LOCK_MINUTES.includes(value as AutoLockMinutes)) return value as AutoLockMinutes;
  } catch {
    // Local preference storage is optional.
  }
  return 15;
}

function parseAutoLockSetting(value: string): AutoLockSetting {
  if (value === "never") return null;
  const minutes = Number(value);
  return AUTO_LOCK_MINUTES.includes(minutes as AutoLockMinutes)
    ? minutes as AutoLockMinutes
    : 15;
}

function readInvitationToken(): string | null {
  const token = new URLSearchParams(window.location.hash.slice(1)).get("invitation");
  return token !== null && /^[A-Za-z0-9_-]{32,256}$/u.test(token) ? token : null;
}

function clearInvitationFragment(): void {
  const url = new URL(window.location.href);
  url.hash = "";
  window.history.replaceState(window.history.state, "", url);
}

function isLockMessage(value: unknown): value is { type: "lock"; manual?: boolean } {
  return typeof value === "object"
    && value !== null
    && "type" in value
    && value.type === "lock"
    && (!("manual" in value) || typeof value.manual === "boolean");
}

function isLogoutMessage(value: unknown): value is { type: "logout" } {
  return typeof value === "object" && value !== null && "type" in value && value.type === "logout";
}

function syncLabel(status: "idle" | "syncing" | "offline" | "error"): string {
  return { idle: "Encrypted & synced", syncing: "Syncing ciphertext", offline: "Offline", error: "Sync attention" }[status];
}

function categoryTitle(category: Category, folders: FolderSummary[]): string {
  if (category.startsWith("folder:")) {
    return folders.find((folder) => `folder:${folder.id}` === category)?.name ?? "Folder";
  }
  return CATEGORIES.find(([value]) => value === category)?.[1] ?? "Vault";
}

function typeKind(itemType: number): string {
  return ({ 1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey" } as Record<number, string>)[itemType] ?? "unsupported";
}

function editableItemKind(kind: string): EditableItemKind | null {
  return (["login", "secureNote", "card", "identity", "sshKey"] as const).find(
    (candidate) => candidate === kind,
  ) ?? null;
}

function itemKindLabel(kind: EditableItemKind): string {
  return ({
    login: "Login",
    secureNote: "Secure note",
    card: "Payment card",
    identity: "Identity",
    sshKey: "SSH key",
  } as const)[kind];
}

function typeLabel(itemType: number): string {
  return ({ 1: "Login", 2: "Secure note", 3: "Payment card", 4: "Identity", 5: "SSH key" } as Record<number, string>)[itemType] ?? `Item type ${itemType}`;
}

function organizationName(id: string, organizations: OrganizationResponse[]): string {
  return organizations.find((organization) => organization.id === id)?.name ?? "Organization";
}

function loginDestinations(
  item: VaultItem | null | undefined,
  organizations: OrganizationResponse[],
  collections: CollectionResponse[],
): LoginDestination[] {
  const destinations: LoginDestination[] = [{
    id: "personal",
    label: "Personal vault",
    organizationId: null,
    collectionIds: [],
    writable: true,
  }];
  for (const collection of collections) {
    destinations.push({
      id: `${collection.organizationId}:${collection.id}`,
      label: `${organizationName(collection.organizationId, organizations)} / ${collection.name}`,
      organizationId: collection.organizationId,
      collectionIds: [collection.id],
      writable: !collection.readOnly,
    });
  }
  if (item?.organizationId !== null && item?.organizationId !== undefined) {
    const exact = destinations.some(
      (destination) =>
        destination.organizationId === item.organizationId
        && destination.collectionIds.length === item.collectionIds.length
        && destination.collectionIds.every((id) => item.collectionIds.includes(id)),
    );
    if (!exact) {
      destinations.push({
        id: `current:${item.id}`,
        label: `${organizationName(item.organizationId, organizations)} / Current collections`,
        organizationId: item.organizationId,
        collectionIds: item.collectionIds,
        writable: true,
      });
    }
  }
  return destinations;
}

interface AttachmentFileWriter {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): Promise<void>;
}

interface AttachmentFileHandle {
  createWritable(): Promise<AttachmentFileWriter>;
}

function attachmentSavePicker(): ((options: Record<string, unknown>) => Promise<AttachmentFileHandle>) | null {
  const candidate = (window as unknown as { showSaveFilePicker?: (options: Record<string, unknown>) => Promise<AttachmentFileHandle> }).showSaveFilePicker;
  return candidate?.bind(window) ?? null;
}

function downloadBlob(fileName: string, mediaType: string, parts: ArrayBuffer[]): void {
  const blob = new Blob(parts, { type: mediaType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.download = fileName;
  link.href = url;
  link.rel = "noopener";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}
