import { useEffect, useRef, useState, type CSSProperties, type FormEvent, type MouseEvent, type ReactNode, type RefObject } from "react";
import { listen } from "@tauri-apps/api/event";

import { AndroidAccountSecurity } from "./AndroidAccountSecurity";

import {
  desktop,
  loginValue,
  type AttachmentMetadata,
  type BiometricStatus,
  type ClipboardPolicy,
  type ConflictSummary,
  type DesktopStatus,
  type FolderDraft,
  type ItemSummary,
  type ItemDraft,
  type LoginDraft,
  type LoginValue,
  type OrganizationCatalog,
  type PassphraseOptions,
  type PasswordOptions,
  type TotpView,
  type VaultItem,
} from "./ipc";

type WorkspaceView = "vault" | "generator" | "settings" | "conflicts";
type AuthMode = "login" | "register";
type EditableItemKind = "login" | "secureNote" | "card" | "identity";
interface LoginDestination {
  id: string;
  label: string;
  organizationId: string | null;
  collectionIds: string[];
  writable: boolean;
}

const categories = [
  ["all", "All items", "⌘"],
  ["logins", "Logins", "↗"],
  ["passkeys", "Passkeys", "◇"],
  ["cards", "Cards", "▰"],
  ["identities", "Identities", "◎"],
  ["notes", "Secure notes", "▤"],
  ["favorites", "Favorites", "★"],
  ["trash", "Trash", "⌫"],
] as const;

const emptyOrganizationCatalog: OrganizationCatalog = { organizations: [], collections: [], folders: [] };

export function DesktopApp() {
  const [status, setStatus] = useState<DesktopStatus | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [organizationCatalog, setOrganizationCatalog] = useState<OrganizationCatalog>(emptyOrganizationCatalog);
  const [selected, setSelected] = useState<VaultItem | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [view, setView] = useState<WorkspaceView>("vault");
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [editor, setEditor] = useState<VaultItem | null | undefined>(undefined);
  const [editorKind, setEditorKind] = useState<EditableItemKind>("login");
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [totp, setTotp] = useState<TotpView | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const editorHistoryEntry = useRef(false);
  const dismissingEditorFromBack = useRef(false);

  useEffect(() => {
    void desktop.status().then(setStatus).catch((caught) => setError(message(caught)));
    const unlisten = listen("vault-locked", () => {
      setStatus((current) => current === null ? null : { ...current, unlocked: false, online: false, itemCount: 0 });
      setItems([]);
      setOrganizationCatalog(emptyOrganizationCatalog);
      setSelected(null);
      setEditor(undefined);
    });
    const unlistenDeepLink = listen<string>("android-deep-link", (event) => {
      if (typeof event?.payload === "string") setNotice(deepLinkNotice(event.payload));
    });
    return () => {
      void unlisten.then((dispose) => dispose());
      void unlistenDeepLink.then((dispose) => dispose());
    };
  }, []);

  useEffect(() => {
    const refreshAfterForeground = () => {
      if (document.visibilityState !== "visible") return;
      // Android clears the native coordinator while backgrounded. Refresh before rendering a
      // previously-visible vault screen so stale decrypted UI state cannot survive a resume.
      void desktop.status().then((next) => {
        setStatus(next);
        if (!next.unlocked) {
          setItems([]);
          setOrganizationCatalog(emptyOrganizationCatalog);
          setSelected(null);
          setEditor(undefined);
        }
      }).catch(() => undefined);
    };
    document.addEventListener("visibilitychange", refreshAfterForeground);
    return () => document.removeEventListener("visibilitychange", refreshAfterForeground);
  }, []);

  useEffect(() => {
    if (status?.unlocked !== true) return;
    const timer = window.setTimeout(() => void refreshItems(query, category), 70);
    return () => window.clearTimeout(timer);
  }, [query, category, status?.unlocked]);

  useEffect(() => {
    if (status?.unlocked !== true) return;
    void refreshOrganizationCatalog();
  }, [status?.unlocked]);

  // Android's predictive Back is routed through the WebView history by MainActivity. Keep one
  // history entry solely while an editor is open so Back closes the sensitive editor first,
  // without treating vault data as a URL or leaking it to browser history.
  useEffect(() => {
    if (editor !== undefined && !editorHistoryEntry.current) {
      window.history.pushState({ hasilanEditor: true }, "");
      editorHistoryEntry.current = true;
      return;
    }
    if (editor === undefined && editorHistoryEntry.current) {
      const fromBack = dismissingEditorFromBack.current;
      dismissingEditorFromBack.current = false;
      editorHistoryEntry.current = false;
      if (!fromBack) window.history.back();
    }
  }, [editor]);

  useEffect(() => {
    const closeEditorForBack = () => {
      if (editor === undefined || !editorHistoryEntry.current) return;
      dismissingEditorFromBack.current = true;
      setEditor(undefined);
      setGeneratedPassword("");
    };
    window.addEventListener("popstate", closeEditorForBack);
    return () => window.removeEventListener("popstate", closeEditorForBack);
  }, [editor]);

  useEffect(() => {
    if (status?.unlocked !== true) return undefined;
    let lastTouch = 0;
    const touch = () => {
      const now = Date.now();
      if (now - lastTouch > 15_000) {
        lastTouch = now;
        void desktop.touch();
      }
    };
    window.addEventListener("pointerdown", touch, { passive: true });
    window.addEventListener("keydown", touch);
    return () => {
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("keydown", touch);
    };
  }, [status?.unlocked]);

  useEffect(() => {
    const login = loginValue(selected);
    if (selected === null || login?.totp === null || selected.deletedDate !== null) {
      setTotp(null);
      return undefined;
    }
    const update = () => {
      void desktop.totp(selected.id, Math.floor(Date.now() / 1_000)).then(setTotp).catch(() => setTotp(null));
    };
    update();
    const timer = window.setInterval(update, 1_000);
    return () => window.clearInterval(timer);
  }, [selected]);

  useEffect(() => {
    const shortcuts = (event: KeyboardEvent) => {
      const target = event.target;
      const typing = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
      if (event.key === "/" && !typing && status?.unlocked === true) {
        event.preventDefault();
        setView("vault");
        window.setTimeout(() => searchRef.current?.focus(), 0);
      } else if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "n" && status?.unlocked === true) {
        event.preventDefault();
        setGeneratedPassword("");
        setEditorKind("login");
        setEditor(null);
      } else if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "l" && status?.unlocked === true) {
        event.preventDefault();
        void lockVault();
      } else if (event.key === "Escape" && editor !== undefined) {
        setEditor(undefined);
      }
    };
    window.addEventListener("keydown", shortcuts);
    return () => window.removeEventListener("keydown", shortcuts);
  }, [status?.unlocked, editor]);

  async function refreshItems(search: string, selectedCategory: string): Promise<void> {
    try {
      const next = await desktop.listItems(search, selectedCategory);
      setItems(next);
      if (selected !== null) {
        const stillVisible = next.some((item) => item.id === selected.id);
        if (!stillVisible && search !== "") setSelected(null);
      }
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function refreshOrganizationCatalog(): Promise<void> {
    try {
      setOrganizationCatalog(await desktop.organizationCatalog());
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function authenticate(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const serverUrl = field(data, "serverUrl").trim();
    const email = field(data, "email").trim();
    let masterPassword = field(data, "masterPassword");
    setBusy(true);
    setError(null);
    try {
      const next = authMode === "register"
        ? await desktop.register(serverUrl, email, masterPassword)
        : await desktop.login(
          serverUrl,
          email,
          masterPassword,
          optional(field(data, "totpCode")),
          optional(field(data, "recoveryCode")),
        );
      masterPassword = "";
      setStatus(next);
      setQuery("");
      setCategory("all");
      setView("vault");
      await refreshItems("", "all");
      setNotice(next.online ? "Vault unlocked and synchronized." : "Vault unlocked from the encrypted offline cache.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      masterPassword = "";
      const password = form.elements.namedItem("masterPassword");
      if (password instanceof HTMLInputElement) password.value = "";
      setBusy(false);
    }
  }

  async function authenticateWithAccountPasskey(form: HTMLFormElement): Promise<void> {
    const data = new FormData(form);
    const serverUrl = field(data, "serverUrl").trim();
    const email = field(data, "email").trim();
    let masterPassword = field(data, "masterPassword");
    setBusy(true);
    setError(null);
    try {
      const next = await desktop.loginWithAccountPasskey(serverUrl, email, masterPassword);
      masterPassword = "";
      setStatus(next);
      setQuery("");
      setCategory("all");
      setView("vault");
      await refreshItems("", "all");
      setNotice("Account passkey verified; vault unlocked and synchronized.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      masterPassword = "";
      const password = form.elements.namedItem("masterPassword");
      if (password instanceof HTMLInputElement) password.value = "";
      setBusy(false);
    }
  }

  async function openItem(id: string): Promise<void> {
    try {
      setSelected(await desktop.getItem(id));
      setView("vault");
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function syncVault(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const next = await desktop.sync();
      setStatus(next);
      await refreshItems(query, category);
      await refreshOrganizationCatalog();
      setNotice(next.online ? "Encrypted changes synchronized." : "Offline. Local encrypted changes remain queued.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function lockVault(): Promise<void> {
    const next = await desktop.lock().catch(() => null);
    setStatus(next ?? (status === null ? null : { ...status, unlocked: false, online: false, itemCount: 0 }));
    setItems([]);
    setOrganizationCatalog(emptyOrganizationCatalog);
    setSelected(null);
    setEditor(undefined);
  }

  async function saveLogin(draft: LoginDraft): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const item = await desktop.saveLogin(draft);
      setSelected(item);
      setEditor(undefined);
      const next = await desktop.status();
      setStatus(next);
      await refreshItems(query, category);
      setNotice(next.online ? "Credential encrypted and synchronized." : "Credential encrypted and queued offline.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function saveItem(draft: ItemDraft): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const item = await desktop.saveItem(draft);
      setSelected(item);
      setEditor(undefined);
      const next = await desktop.status();
      setStatus(next);
      await refreshItems(query, category);
      setNotice(next.online ? "Vault item encrypted and synchronized." : "Vault item encrypted and queued offline.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  function beginNew(kind: EditableItemKind): void {
    setGeneratedPassword("");
    setEditorKind(kind);
    setEditor(null);
  }

  function beginEdit(item: VaultItem): void {
    const kind = editableKind(item);
    if (kind === null) {
      setError("This imported item type is read-only in the current editor.");
      return;
    }
    setEditorKind(kind);
    setEditor(item);
  }

  async function removeItem(): Promise<void> {
    if (selected === null || !window.confirm(`Move “${selected.name}” to trash?`)) return;
    setBusy(true);
    try {
      setStatus(await desktop.deleteItem(selected.id));
      setSelected(null);
      await refreshItems(query, category);
      setNotice("Encrypted deletion queued or synchronized.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function uploadAttachment(existing?: AttachmentMetadata): Promise<void> {
    if (selected === null) return;
    const itemId = selected.id;
    setBusy(true);
    setError(null);
    try {
      const item = await desktop.uploadAttachment(itemId, existing?.id ?? null);
      if (item === null) return;
      setSelected(item);
      setStatus(await desktop.status());
      await refreshItems(query, category);
      setNotice(`“${existing?.fileName ?? item.attachments.at(-1)?.fileName ?? "File"}” encrypted and uploaded from the native process.`);
    } catch (caught) {
      try {
        setSelected(await desktop.getItem(itemId));
        setStatus(await desktop.status());
      } catch { /* the vault may have auto-locked */ }
      setError(`Attachment upload paused: ${message(caught)} Reselect the same file and use Retry.`);
    } finally {
      setBusy(false);
    }
  }

  async function downloadAttachment(attachment: AttachmentMetadata): Promise<void> {
    if (selected === null) return;
    setBusy(true);
    setError(null);
    try {
      const path = await desktop.downloadAttachment(selected.id, attachment.id);
      if (path !== null) setNotice(`Authenticated attachment written atomically to ${path}`);
    } catch (caught) {
      setError(`Attachment download failed: ${message(caught)}`);
    } finally {
      setBusy(false);
    }
  }

  async function removeAttachment(attachment: AttachmentMetadata): Promise<void> {
    if (selected === null || !window.confirm(`Remove encrypted attachment “${attachment.fileName}”?`)) return;
    setBusy(true);
    setError(null);
    try {
      const result = await desktop.removeAttachment(selected.id, attachment.id);
      setSelected(result.item);
      setStatus(await desktop.status());
      setNotice(result.cleanupPending
        ? "Attachment reference removed; opaque server cleanup is durably queued."
        : "Encrypted attachment removed and server storage cleaned up.");
    } catch (caught) {
      try { setSelected(await desktop.getItem(selected.id)); } catch { /* the vault may have auto-locked */ }
      setError(`Attachment removal failed: ${message(caught)}`);
    } finally {
      setBusy(false);
    }
  }

  async function copy(value: string): Promise<void> {
    try {
      await desktop.copySecret(value);
      setNotice("Copied. Clipboard clearing follows this device's policy.");
    } catch (caught) {
      setError(message(caught));
    }
  }

  if (status === null) {
    return <div className="boot"><BrandMark /><p>Opening encrypted desktop cache…</p></div>;
  }

  if (!status.unlocked) {
    return (
      <AuthScreen
        busy={busy}
        error={error}
        mode={authMode}
        onAuthenticate={authenticate}
        onAccountPasskey={authenticateWithAccountPasskey}
        onMode={setAuthMode}
        onSelectProfile={async (scope) => {
          try { setStatus(await desktop.selectProfile(scope)); } catch (caught) { setError(message(caught)); }
        }}
        status={status}
      />
    );
  }

  return (
    <div className="desktop-shell">
      <Sidebar
        category={category}
        folders={organizationCatalog.folders}
        onCategory={(next) => { setCategory(next); setView("vault"); setSelected(null); }}
        onLock={() => void lockVault()}
        onView={(next) => { setView(next); setSelected(null); }}
        status={status}
        view={view}
      />
      <main className="workspace">
        <Topbar
          busy={busy}
          onNew={beginNew}
          onSync={() => void syncVault()}
          online={status.online}
          pending={status.pendingCount}
          query={query}
          searchRef={searchRef}
          setQuery={setQuery}
          showSearch={view === "vault"}
        />
        {error === null ? null : <button className="banner error" onClick={() => setError(null)} type="button">{error}<span>Dismiss</span></button>}
        {notice === null ? null : <button className="banner notice" onClick={() => setNotice(null)} type="button">{notice}<span>Dismiss</span></button>}
        {view === "vault" ? (
          <VaultWorkspace
            busy={busy}
            category={category}
            items={items}
            organizationCatalog={organizationCatalog}
            onCopy={(value) => void copy(value)}
            onDelete={() => void removeItem()}
            onDownloadAttachment={(attachment) => void downloadAttachment(attachment)}
            onError={(caught) => setError(message(caught))}
            onEdit={() => selected !== null && beginEdit(selected)}
            onOpen={(id) => void openItem(id)}
            onPasskeyRemoved={(item) => setSelected(item)}
            onRemoveAttachment={(attachment) => void removeAttachment(attachment)}
            onUploadAttachment={(attachment) => void uploadAttachment(attachment)}
            selected={selected}
            totp={totp}
          />
        ) : null}
        {view === "generator" ? <Generator onCopy={(value) => void copy(value)} onUse={(value) => { setGeneratedPassword(value); setEditorKind("login"); setEditor(null); }} /> : null}
        {view === "settings" ? <Settings catalog={organizationCatalog} onRefresh={() => { void refreshOrganizationCatalog(); void refreshItems(query, category); }} status={status} setError={setError} setNotice={setNotice} setStatus={setStatus} /> : null}
        {view === "conflicts" ? <Conflicts onRefresh={() => void refreshItems(query, category)} setError={setError} setStatus={setStatus} /> : null}
      </main>
      <BottomNav
        conflictCount={status.conflictCount}
        onView={(next) => { setView(next); setSelected(null); }}
        onVault={() => { setCategory("all"); setView("vault"); setSelected(null); }}
        view={view}
      />
      {editor === undefined ? null : editorKind === "login"
        ? <LoginEditor busy={busy} destinations={loginDestinations(editor, organizationCatalog)} folders={organizationCatalog.folders} generatedPassword={generatedPassword} item={editor} onCancel={() => { setEditor(undefined); setGeneratedPassword(""); }} onSave={(draft) => void saveLogin(draft)} />
        : <TypedItemEditor busy={busy} destinations={loginDestinations(editor, organizationCatalog)} folders={organizationCatalog.folders} item={editor} key={editor?.id ?? `new-${editorKind}`} kind={editorKind} onCancel={() => setEditor(undefined)} onSave={(draft) => void saveItem(draft)} />}
    </div>
  );
}

function AuthScreen({ status, mode, busy, error, onMode, onAuthenticate, onAccountPasskey, onSelectProfile }: {
  status: DesktopStatus;
  mode: AuthMode;
  busy: boolean;
  error: string | null;
  onMode: (mode: AuthMode) => void;
  onAuthenticate: (event: FormEvent<HTMLFormElement>) => void;
  onAccountPasskey: (form: HTMLFormElement) => void;
  onSelectProfile: (scope: string) => void;
}) {
  const isAndroid = /Android/i.test(navigator.userAgent);
  return (
    <main className="auth-screen">
      <section className="auth-story">
        <div className="brand"><BrandMark /><span>HASILAN PASS</span></div>
        <div className="story-copy"><span className="eyebrow">NATIVE ZERO-KNOWLEDGE VAULT</span><h1>Your passwords stay legible only here.</h1><p>Sync encrypted objects to any server you control. Search and work offline from this device without turning the server into a trusted party.</p></div>
        <div className="trust-grid"><TrustStat value="Rust" label="crypto + sync core" /><TrustStat value="Local" label="decryption boundary" /><TrustStat value="30s" label="clipboard timeout" /></div>
      </section>
      <section className="auth-panel">
        <div className="auth-card">
          <span className="section-kicker">DESKTOP CLIENT</span>
          <h2>{mode === "register" ? "Create encrypted vault" : status.email === null ? "Unlock your vault" : "Welcome back"}</h2>
          <p>{status.email === null ? "Connect directly to your Hasilan Pass server." : `Cached ciphertext is ready for ${status.email}.`}</p>
          <div className="segmented" role="tablist">
            <button aria-selected={mode === "login"} className={mode === "login" ? "active" : ""} onClick={() => onMode("login")} role="tab" type="button">Unlock</button>
            <button aria-selected={mode === "register"} className={mode === "register" ? "active" : ""} onClick={() => onMode("register")} role="tab" type="button">Create</button>
          </div>
          <form className="stack-form" onSubmit={onAuthenticate}>
            <label>Server URL<input defaultValue={status.serverUrl ?? "http://127.0.0.1:8080"} name="serverUrl" required spellCheck={false} type="url" /></label>
            <label>Email<input autoComplete="username" defaultValue={status.email ?? ""} name="email" required type="email" /></label>
            <label>Master password<input autoComplete={mode === "register" ? "new-password" : "current-password"} minLength={mode === "register" ? 12 : undefined} name="masterPassword" required type="password" /></label>
            {mode === "login" ? <><label>Two-step code <span>if enabled</span><input autoComplete="one-time-code" inputMode="numeric" name="totpCode" /></label><label>Recovery code <span>use instead of the two-step code</span><input autoComplete="one-time-code" name="recoveryCode" /></label></> : null}
            {error === null ? null : <p className="form-error" role="alert">{error}</p>}
            <button className="primary large" disabled={busy} type="submit">{busy ? "Deriving keys locally…" : mode === "register" ? "Create vault" : "Unlock vault"}</button>
            {!isAndroid || mode !== "login" ? null : <button disabled={busy} onClick={(event) => onAccountPasskey(event.currentTarget.form!)} type="button">Use account passkey</button>}
          </form>
          <div className="auth-foot"><span className="shield">◆</span><p>The master password is consumed by the native Rust process. It is never transmitted or stored.</p></div>
          {status.profiles.length > 1 ? <div className="profiles"><span>Other cached accounts</span>{status.profiles.filter((profile) => !profile.active).map((profile) => <button key={profile.scope} onClick={() => onSelectProfile(profile.scope)} type="button"><strong>{profile.email}</strong><small>{profile.serverUrl}</small></button>)}</div> : null}
        </div>
      </section>
    </main>
  );
}

function Sidebar({ status, category, folders, view, onCategory, onView, onLock }: {
  status: DesktopStatus;
  category: string;
  folders: OrganizationCatalog["folders"];
  view: WorkspaceView;
  onCategory: (category: string) => void;
  onView: (view: WorkspaceView) => void;
  onLock: () => void;
}) {
  return (
    <aside className="sidebar">
      <div className="brand compact"><BrandMark /><span>HASILAN</span></div>
      <nav aria-label="Vault categories">
        <span className="nav-label">VAULT</span>
        {categories.map(([id, label, glyph]) => <button className={view === "vault" && category === id ? "active" : ""} key={id} onClick={() => onCategory(id)} type="button"><i>{glyph}</i><span>{label}</span></button>)}
        {folders.length === 0 ? null : <><span className="nav-label lower">FOLDERS</span>{folders.map((folder) => <button className={view === "vault" && category === `folder:${folder.id}` ? "active" : ""} key={folder.id} onClick={() => onCategory(`folder:${folder.id}`)} type="button"><i>□</i><span>{folder.name}</span></button>)}</>}
        <span className="nav-label lower">TOOLS</span>
        <button className={view === "generator" ? "active" : ""} onClick={() => onView("generator")} type="button"><i>✦</i><span>Generator</span></button>
        <button className={view === "conflicts" ? "active" : ""} onClick={() => onView("conflicts")} type="button"><i>⇄</i><span>Conflicts</span>{status.conflictCount === 0 ? null : <b>{status.conflictCount}</b>}</button>
        <button className={view === "settings" ? "active" : ""} onClick={() => onView("settings")} type="button"><i>⚙</i><span>Settings</span></button>
      </nav>
      <div className="sidebar-account"><span className={status.online ? "status-dot online" : "status-dot"} /><div><strong>{status.email}</strong><small>{status.online ? "Encrypted sync online" : "Offline cache"}</small></div><button aria-label="Lock vault" onClick={onLock} title="Lock vault (Ctrl+L)" type="button">⌁</button></div>
    </aside>
  );
}

/** Four primary touch destinations for portrait Android; desktop keeps the full sidebar. */
function BottomNav({ view, conflictCount, onVault, onView }: {
  view: WorkspaceView;
  conflictCount: number;
  onVault: () => void;
  onView: (view: WorkspaceView) => void;
}) {
  return <nav aria-label="Primary navigation" className="bottom-nav">
    <button aria-current={view === "vault" ? "page" : undefined} className={view === "vault" ? "active" : ""} onClick={onVault} type="button"><i>⌘</i><span>Vault</span></button>
    <button aria-current={view === "generator" ? "page" : undefined} className={view === "generator" ? "active" : ""} onClick={() => onView("generator")} type="button"><i>✦</i><span>Generate</span></button>
    <button aria-current={view === "conflicts" ? "page" : undefined} className={view === "conflicts" ? "active" : ""} onClick={() => onView("conflicts")} type="button"><i>⇄</i><span>Conflicts{conflictCount === 0 ? "" : ` (${conflictCount})`}</span></button>
    <button aria-current={view === "settings" ? "page" : undefined} className={view === "settings" ? "active" : ""} onClick={() => onView("settings")} type="button"><i>⚙</i><span>Settings</span></button>
  </nav>;
}

function Topbar({ query, setQuery, searchRef, showSearch, online, pending, busy, onSync, onNew }: {
  query: string;
  setQuery: (query: string) => void;
  searchRef: RefObject<HTMLInputElement | null>;
  showSearch: boolean;
  online: boolean;
  pending: number;
  busy: boolean;
  onSync: () => void;
  onNew: (kind: EditableItemKind) => void;
}) {
  return (
    <header className="topbar">
      {showSearch ? <div className="search"><span>⌕</span><input aria-label="Search vault" onChange={(event) => setQuery(event.target.value)} placeholder="Search name, username, URL, notes…" ref={searchRef} value={query} /><kbd>/</kbd></div> : <div><span className="eyebrow">HASILAN DESKTOP</span><strong>Private workspace</strong></div>}
      <div className="top-actions"><span className={online ? "sync-state online" : "sync-state"}>{online ? "ONLINE" : "OFFLINE"}{pending > 0 ? ` · ${pending} QUEUED` : ""}</span><button aria-label="Synchronize vault" className="icon-button" disabled={busy} onClick={onSync} title="Synchronize" type="button">↻</button><button className="primary" onClick={() => onNew("login")} type="button"><span>＋</span> New login</button><select aria-label="Create vault item type" defaultValue="" onChange={(event) => { const kind = event.currentTarget.value; if (kind === "secureNote" || kind === "card" || kind === "identity") { onNew(kind); event.currentTarget.value = ""; } }}><option disabled value="">More…</option><option value="secureNote">Secure note</option><option value="card">Card</option><option value="identity">Identity</option></select></div>
    </header>
  );
}

function VaultWorkspace({ busy, items, selected, category, totp, organizationCatalog, onOpen, onCopy, onEdit, onDelete, onError, onPasskeyRemoved, onUploadAttachment, onDownloadAttachment, onRemoveAttachment }: {
  busy: boolean;
  items: ItemSummary[];
  selected: VaultItem | null;
  category: string;
  totp: TotpView | null;
  organizationCatalog: OrganizationCatalog;
  onOpen: (id: string) => void;
  onCopy: (value: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onUploadAttachment: (attachment?: AttachmentMetadata) => void;
  onDownloadAttachment: (attachment: AttachmentMetadata) => void;
  onRemoveAttachment: (attachment: AttachmentMetadata) => void;
  onError: (error: unknown) => void;
  onPasskeyRemoved: (item: VaultItem) => void;
}) {
  const title = category.startsWith("folder:")
    ? organizationCatalog.folders.find((folder) => folder.id === category.slice("folder:".length))?.name ?? "Folder"
    : categories.find(([id]) => id === category)?.[1] ?? "Vault";
  return (
    <div className="vault-workspace">
      <section className="item-column">
        <div className="column-heading"><div><span className="eyebrow">PRIVATE INDEX</span><h1>{title}</h1></div><span>{items.length} result{items.length === 1 ? "" : "s"}</span></div>
        <div className="item-list" role="list">
          {items.length === 0 ? <div className="empty-state"><div>⌁</div><h2>No matching items</h2><p>Create a login, choose another category, or clear the search.</p></div> : null}
          {items.map((item) => <button className={`item-row ${selected?.id === item.id ? "selected" : ""}`} key={item.id} onClick={() => onOpen(item.id)} role="listitem" type="button"><ItemGlyph type={item.itemType} /><span className="item-copy"><strong>{item.name}</strong><small>{item.username ?? item.primaryUri ?? typeName(item.itemType)}{item.organizationId === null ? "" : ` · ${organizationName(item.organizationId, organizationCatalog)}`}</small></span><span className="row-signals">{item.organizationId === null ? null : <i title="Shared organization item">⌂</i>}{item.favorite ? <i>★</i> : null}{item.hasTotp ? <i>◷</i> : null}{item.passkeyCount > 0 ? <i>◇{item.passkeyCount}</i> : null}{item.pending ? <i title="Queued local change">↑</i> : null}{item.conflicted ? <i className="danger-text" title="Conflict">!</i> : null}</span></button>)}
        </div>
      </section>
      <section className="detail-column">
        {selected === null ? <div className="detail-empty"><BrandMark /><h2>Select a vault item</h2><p>Decrypted detail appears only after an explicit selection.</p><div><kbd>⌘ N</kbd> New login <kbd>/</kbd> Search</div></div> : <ItemDetail busy={busy} item={selected} onCopy={onCopy} onDelete={onDelete} onDownloadAttachment={onDownloadAttachment} onEdit={onEdit} onError={onError} onPasskeyRemoved={onPasskeyRemoved} onRemoveAttachment={onRemoveAttachment} onUploadAttachment={onUploadAttachment} organizationCatalog={organizationCatalog} totp={totp} />}
      </section>
    </div>
  );
}

function ItemDetail({ busy, item, totp, organizationCatalog, onCopy, onEdit, onDelete, onError, onPasskeyRemoved, onUploadAttachment, onDownloadAttachment, onRemoveAttachment }: {
  busy: boolean;
  item: VaultItem;
  totp: TotpView | null;
  organizationCatalog: OrganizationCatalog;
  onCopy: (value: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onUploadAttachment: (attachment?: AttachmentMetadata) => void;
  onDownloadAttachment: (attachment: AttachmentMetadata) => void;
  onRemoveAttachment: (attachment: AttachmentMetadata) => void;
  onError: (error: unknown) => void;
  onPasskeyRemoved: (item: VaultItem) => void;
}) {
  const login = loginValue(item);
  const [revealed, setRevealed] = useState(false);
  const policy = organizationItemPolicy(item, organizationCatalog);
  const editable = editableKind(item);
  return (
    <article className="item-detail">
      <header><ItemGlyph large type={item.data.kind === "login" ? 1 : typeFromKind(item.data.kind)} /><div><span>{typeName(item.data.kind === "login" ? 1 : typeFromKind(item.data.kind))}{item.organizationId === null ? "" : ` · ${organizationName(item.organizationId, organizationCatalog)}`}</span><h2>{item.name}</h2><small>Updated {formatDate(item.revisionDate)}</small></div>{item.favorite ? <i className="favorite">★</i> : null}</header>
      {item.deletedDate === null ? null : <div className="deleted-warning">This item is in trash since {formatDate(item.deletedDate)}.</div>}
      {login === null ? <GenericDetail item={item} onCopy={onCopy} /> : (
        <>
          <SecretRow label="Username" onCopy={onCopy} value={login.username} />
          {policy.hidePasswords ? <div className="policy-warning">Password display and copying are hidden by this collection's official-client policy.</div> : <SecretRow label="Password" masked={!revealed} onCopy={onCopy} onReveal={() => setRevealed((value) => !value)} value={login.password} />}
          {login.uris.map((uri, index) => <SecretRow key={`${uri.uri}-${index}`} label={index === 0 ? "Website" : `Website ${index + 1}`} onCopy={onCopy} value={uri.uri} />)}
          {totp === null ? null : <button className="totp-card" onClick={() => onCopy(totp.code)} type="button"><span>AUTHENTICATOR CODE</span><strong>{totp.code.slice(0, 3)} {totp.code.slice(3)}</strong><i style={{ "--progress": `${(totp.remainingSeconds / 30) * 100}%` } as CSSProperties}>{totp.remainingSeconds}s</i></button>}
          {login.fido2Credentials.length === 0 ? null : <Passkeys credentials={login.fido2Credentials} itemId={item.id} onError={onError} onRemoved={onPasskeyRemoved} />}
        </>
      )}
      {item.notes === null ? null : <section className="notes"><span>NOTES</span><p>{item.notes}</p></section>}
      {item.fields.length === 0 ? null : <section className="custom-fields"><span>CUSTOM FIELDS</span>{item.fields.map((field, index) => <SecretRow key={`${field.name}-${index}`} label={field.name ?? `Field ${index + 1}`} onCopy={onCopy} value={field.value} />)}</section>}
      <section className="desktop-attachments"><header><div><span>ATTACHMENTS</span><small>Native streaming · client-side encryption</small></div>{item.deletedDate !== null || !policy.writable ? null : <button disabled={busy} onClick={() => onUploadAttachment()} type="button">Attach file</button>}</header>{item.attachments.length === 0 ? <p>No encrypted attachments.</p> : item.attachments.map((attachment) => <article key={attachment.id}><div><strong title={attachment.fileName}>{attachment.fileName}</strong><small>{formatFileSize(attachment.size)} · {attachment.mediaType}</small></div><div><button disabled={busy || item.deletedDate !== null} onClick={() => onDownloadAttachment(attachment)} type="button">Download</button>{item.deletedDate !== null || !policy.writable ? null : <><button disabled={busy} onClick={() => onUploadAttachment(attachment)} type="button">Retry</button><button className="danger-text" disabled={busy} onClick={() => onRemoveAttachment(attachment)} type="button">Remove</button></>}</div></article>)}</section>
      <footer>{editable === null || item.deletedDate !== null || !policy.writable || (login !== null && policy.hidePasswords) ? null : <button className="primary" onClick={onEdit} type="button">{editable === "login" ? "Edit login" : `Edit ${typeName(typeFromKind(item.data.kind))}`}</button>}<button className="danger" disabled={item.deletedDate !== null || !policy.writable} onClick={onDelete} type="button">Move to trash</button></footer>
    </article>
  );
}

function SecretRow({ label, value, masked = false, onCopy, onReveal }: { label: string; value: string | null; masked?: boolean; onCopy: (value: string) => void; onReveal?: () => void }) {
  return <div className="secret-row"><span>{label.toUpperCase()}</span><div><strong>{value === null ? "—" : masked ? "••••••••••••" : value}</strong>{onReveal === undefined || value === null ? null : <button onClick={onReveal} type="button">{masked ? "Reveal" : "Hide"}</button>}{value === null ? null : <button onClick={() => onCopy(value)} type="button">Copy</button>}</div></div>;
}

function GenericDetail({ item, onCopy }: { item: VaultItem; onCopy: (value: string) => void }) {
  const values = Object.entries(item.data.value).filter(([, value]) => typeof value === "string" && value !== "");
  return <section className="generic-detail">{values.length === 0 ? <p>No editable fields are present for this item.</p> : values.map(([key, value]) => <SecretRow key={key} label={humanize(key)} onCopy={onCopy} value={value as string} />)}</section>;
}

function Passkeys({ credentials, itemId, onRemoved, onError }: { credentials: LoginValue["fido2Credentials"]; itemId: string; onRemoved: (item: VaultItem) => void; onError: (error: unknown) => void }) {
  return <section className="passkeys"><span>PASSKEYS</span>{credentials.map((credential) => <div className="passkey" key={credential.credentialId}><i>◇</i><div><strong>{credential.rpName ?? credential.rpId}</strong><small>{credential.userDisplayName ?? credential.userName ?? "Unnamed account"}</small><small>Created {formatDate(credential.creationDate)} · {credential.discoverable ? "Discoverable" : "Non-discoverable"}</small></div><button onClick={async () => { if (!window.confirm("Remove this encrypted passkey from the item?")) return; try { onRemoved(await desktop.removePasskey(itemId, credential.credentialId)); } catch (caught) { onError(caught); } }} type="button">Remove</button></div>)}</section>;
}

function LoginEditor({ item, generatedPassword, busy, destinations, folders, onSave, onCancel }: { item: VaultItem | null; generatedPassword: string; busy: boolean; destinations: LoginDestination[]; folders: OrganizationCatalog["folders"]; onSave: (draft: LoginDraft) => void; onCancel: () => void }) {
  const login = loginValue(item);
  const currentDestination = destinationForItem(item, destinations);
  const [fields, setFields] = useState(item?.fields ?? []);
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const destination = destinations.find((candidate) => candidate.id === field(data, "destination"));
    if (destination === undefined || (item === null && !destination.writable)) return;
    onSave({ id: item?.id ?? null, name: field(data, "name").trim(), username: optional(field(data, "username")), password: optionalVerbatim(field(data, "password")), uri: optional(field(data, "uri")), totp: optional(field(data, "totp")), notes: optionalVerbatim(field(data, "notes")), favorite: data.get("favorite") === "on", folderId: destination.organizationId === null ? optional(field(data, "folder")) : null, fields, organizationId: destination.organizationId, collectionIds: destination.collectionIds });
  }
  const isAndroid = /Android/i.test(navigator.userAgent);
  const scanTotp = async (event: MouseEvent<HTMLButtonElement>) => {
    try {
      const value = await desktop.scanTotp();
      const input = event.currentTarget.form?.elements.namedItem("totp");
      if (input instanceof HTMLInputElement) input.value = value;
    } catch { /* Cancelling the native scanner leaves the field unchanged. */ }
  };
  return <div className="modal-backdrop" role="presentation"><section aria-labelledby="editor-title" aria-modal="true" className="modal editor-modal" role="dialog"><header><div><span className="eyebrow">LOCAL ENCRYPTION</span><h2 id="editor-title">{item === null ? "New login" : "Edit login"}</h2></div><button aria-label="Close editor" onClick={onCancel} type="button">×</button></header><form className="stack-form two-column" key={item?.id ?? "new"} onSubmit={submit}><label className="span-two">Vault destination<select defaultValue={currentDestination?.id ?? "personal"} disabled={item !== null} name={item === null ? "destination" : undefined} required>{destinations.map((destination) => <option disabled={item === null && !destination.writable} key={destination.id} value={destination.id}>{destination.label}{destination.writable ? "" : " (read-only)"}</option>)}</select>{item === null ? null : <input name="destination" type="hidden" value={currentDestination?.id ?? "personal"} />}{item === null ? null : <span>Ownership is immutable after the first encrypted upload.</span>}</label><label className="span-two">Folder<select defaultValue={item?.folderId ?? ""} name="folder"><option value="">No folder</option>{folders.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}</select><span>Personal folders only.</span></label><label className="span-two">Name<input autoFocus defaultValue={item?.name ?? ""} name="name" required /></label><label>Username<input autoComplete="off" defaultValue={login?.username ?? ""} name="username" /></label><label>Password<input autoComplete="new-password" defaultValue={generatedPassword || login?.password || ""} name="password" type="password" /></label><label className="span-two">Website URL<input defaultValue={login?.uris[0]?.uri ?? ""} name="uri" type="url" /></label><label className="span-two">Authenticator key or otpauth URI<input autoComplete="off" defaultValue={login?.totp ?? ""} name="totp" />{!isAndroid ? null : <button onClick={(event) => void scanTotp(event)} type="button">Scan QR</button>}</label><label className="span-two">Notes<textarea defaultValue={item?.notes ?? ""} name="notes" rows={4} /></label><CustomFieldsEditor fields={fields} onChange={setFields} /><label className="check span-two"><input defaultChecked={item?.favorite ?? false} name="favorite" type="checkbox" /><span>Mark as favorite</span></label><footer className="span-two"><button onClick={onCancel} type="button">Cancel</button><button className="primary" disabled={busy} type="submit">{busy ? "Encrypting…" : "Encrypt and save"}</button></footer></form></section></div>;
}

function CustomFieldsEditor({ fields, onChange }: { fields: VaultItem["fields"]; onChange: (fields: VaultItem["fields"]) => void }) {
  const update = (index: number, patch: Partial<VaultItem["fields"][number]>) => onChange(fields.map((field, position) => position === index ? { ...field, ...patch } : field));
  return <section className="custom-fields span-two"><span>CUSTOM FIELDS</span>{fields.map((custom, index) => <div className="custom-field-editor" key={`${custom.name ?? "field"}-${index}`}><input aria-label={`Custom field ${index + 1} name`} onChange={(event) => update(index, { name: optionalVerbatim(event.currentTarget.value) })} placeholder="Field name" value={custom.name ?? ""} /><input aria-label={`Custom field ${index + 1} value`} onChange={(event) => update(index, { value: optionalVerbatim(event.currentTarget.value) })} placeholder="Value" type={custom.fieldType === 1 ? "password" : "text"} value={custom.value ?? ""} /><select aria-label={`Custom field ${index + 1} type`} onChange={(event) => update(index, { fieldType: Number(event.currentTarget.value) })} value={custom.fieldType}><option value={0}>Text</option><option value={1}>Hidden</option></select><button aria-label={`Remove custom field ${index + 1}`} onClick={() => onChange(fields.filter((_, position) => position !== index))} type="button">Remove</button></div>)}<button onClick={() => onChange([...fields, { name: null, value: null, fieldType: 0, linkedId: null }])} type="button">Add custom field</button></section>;
}

function TypedItemEditor({ kind, item, busy, destinations, folders, onSave, onCancel }: { kind: Exclude<EditableItemKind, "login">; item: VaultItem | null; busy: boolean; destinations: LoginDestination[]; folders: OrganizationCatalog["folders"]; onSave: (draft: ItemDraft) => void; onCancel: () => void }) {
  const currentDestination = destinationForItem(item, destinations);
  const [fields, setFields] = useState(item?.fields ?? []);
  const data = item?.data.kind === kind ? item.data.value : {};
  const value = (key: string): string => typeof data[key] === "string" ? data[key] as string : "";
  const updateField = (index: number, key: "name" | "value", value: string) => setFields((current) => current.map((field, position) => position === index ? { ...field, [key]: optionalVerbatim(value) } : field));
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const destination = destinations.find((candidate) => candidate.id === field(form, "destination"));
    if (destination === undefined || (item === null && !destination.writable)) return;
    const draftData = kind === "secureNote"
      ? { kind: "secureNote", value: { noteType: 0 } }
      : kind === "card"
        ? { kind: "card", value: { cardholderName: optional(field(form, "cardholderName")), number: optionalVerbatim(field(form, "number")), code: optionalVerbatim(field(form, "code")), brand: optional(field(form, "brand")), expMonth: optional(field(form, "expMonth")), expYear: optional(field(form, "expYear")) } }
        : { kind: "identity", value: Object.fromEntries(identityFields.map(([key]) => [key, optionalVerbatim(field(form, key))])) };
    onSave({ id: item?.id ?? null, name: field(form, "name").trim(), notes: optionalVerbatim(field(form, "notes")), favorite: form.get("favorite") === "on", folderId: destination.organizationId === null ? optional(field(form, "folder")) : null, fields, data: draftData, organizationId: destination.organizationId, collectionIds: destination.collectionIds });
  }
  const typeNameForEditor = kind === "secureNote" ? "Secure note" : kind === "card" ? "Card" : "Identity";
  return <div className="modal-backdrop" role="presentation"><section aria-labelledby="typed-editor-title" aria-modal="true" className="modal editor-modal" role="dialog"><header><div><span className="eyebrow">LOCAL ENCRYPTION</span><h2 id="typed-editor-title">{item === null ? `New ${typeNameForEditor.toLowerCase()}` : `Edit ${typeNameForEditor.toLowerCase()}`}</h2></div><button aria-label="Close editor" onClick={onCancel} type="button">×</button></header><form className="stack-form two-column" onSubmit={submit}><label className="span-two">Vault destination<select defaultValue={currentDestination?.id ?? "personal"} disabled={item !== null} name={item === null ? "destination" : undefined} required>{destinations.map((destination) => <option disabled={item === null && !destination.writable} key={destination.id} value={destination.id}>{destination.label}{destination.writable ? "" : " (read-only)"}</option>)}</select>{item === null ? null : <input name="destination" type="hidden" value={currentDestination?.id ?? "personal"} />}{item === null ? null : <span>Ownership is immutable after the first encrypted upload.</span>}</label><label className="span-two">Folder<select defaultValue={item?.folderId ?? ""} name="folder"><option value="">No folder</option>{folders.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}</select><span>Personal folders only.</span></label><label className="span-two">Name<input autoFocus defaultValue={item?.name ?? ""} name="name" required /></label>{kind === "card" ? <><label>Cardholder<input defaultValue={value("cardholderName")} name="cardholderName" /></label><label>Brand<input defaultValue={value("brand")} name="brand" /></label><label className="span-two">Card number<input autoComplete="cc-number" defaultValue={value("number")} name="number" type="password" /></label><label>Expiry month<input autoComplete="cc-exp-month" defaultValue={value("expMonth")} inputMode="numeric" name="expMonth" /></label><label>Expiry year<input autoComplete="cc-exp-year" defaultValue={value("expYear")} inputMode="numeric" name="expYear" /></label><label>Security code<input autoComplete="cc-csc" defaultValue={value("code")} name="code" type="password" /></label></> : null}{kind === "identity" ? identityFields.map(([key, label, inputType]) => <label key={key}><span>{label}</span><input autoComplete="off" defaultValue={value(key)} name={key} type={inputType} /></label>) : null}<label className="span-two">Notes<textarea defaultValue={item?.notes ?? ""} name="notes" rows={4} /></label><CustomFieldsEditor fields={fields} onChange={setFields} /><label className="check span-two"><input defaultChecked={item?.favorite ?? false} name="favorite" type="checkbox" /><span>Mark as favorite</span></label><footer className="span-two"><button onClick={onCancel} type="button">Cancel</button><button className="primary" disabled={busy} type="submit">{busy ? "Encrypting…" : "Encrypt and save"}</button></footer></form></section></div>;
}

function Generator({ onCopy, onUse }: { onCopy: (value: string) => void; onUse: (value: string) => void }) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [generated, setGenerated] = useState("");
  const [password, setPassword] = useState<PasswordOptions>({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, minimumNumbers: 1, minimumSymbols: 1, excludeAmbiguous: true });
  const [passphrase, setPassphrase] = useState<PassphraseOptions>({ wordCount: 6, separator: "-", capitalize: false, includeNumber: false });
  const [error, setError] = useState<string | null>(null);
  async function generate(): Promise<void> {
    try { setGenerated(mode === "password" ? await desktop.generatePassword(password) : await desktop.generatePassphrase(passphrase)); setError(null); } catch (caught) { setError(message(caught)); }
  }
  useEffect(() => { void generate(); }, [mode]);
  return <section className="tool-page"><header><span className="eyebrow">CSPRNG · SHARED RUST CORE</span><h1>Password generator</h1><p>Generate locally. Nothing leaves this process until you choose to save it.</p></header><div className="generator-grid"><section className="generator-output"><span>GENERATED SECRET</span><code>{generated || "Generating…"}</code><div><button onClick={() => generated !== "" && onCopy(generated)} type="button">Copy</button><button className="primary" onClick={() => generated !== "" && onUse(generated)} type="button">Use in new login</button></div></section><section className="generator-controls"><div className="segmented"><button className={mode === "password" ? "active" : ""} onClick={() => setMode("password")} type="button">Password</button><button className={mode === "passphrase" ? "active" : ""} onClick={() => setMode("passphrase")} type="button">Passphrase</button></div>{mode === "password" ? <><Range label="Length" max={128} min={8} onChange={(length) => setPassword({ ...password, length })} value={password.length} /><Toggle checked={password.uppercase} label="Uppercase letters" onChange={(uppercase) => setPassword({ ...password, uppercase })} /><Toggle checked={password.lowercase} label="Lowercase letters" onChange={(lowercase) => setPassword({ ...password, lowercase })} /><Toggle checked={password.numbers} label="Numbers" onChange={(numbers) => setPassword({ ...password, numbers, minimumNumbers: numbers ? Math.max(1, password.minimumNumbers) : 0 })} /><Toggle checked={password.symbols} label="Symbols" onChange={(symbols) => setPassword({ ...password, symbols, minimumSymbols: symbols ? Math.max(1, password.minimumSymbols) : 0 })} /><Toggle checked={password.excludeAmbiguous} label="Exclude ambiguous characters" onChange={(excludeAmbiguous) => setPassword({ ...password, excludeAmbiguous })} /></> : <><Range label="Word count" max={12} min={3} onChange={(wordCount) => setPassphrase({ ...passphrase, wordCount })} value={passphrase.wordCount} /><label className="control-field">Separator<input maxLength={8} onChange={(event) => setPassphrase({ ...passphrase, separator: event.target.value })} value={passphrase.separator} /></label><Toggle checked={passphrase.capitalize} label="Capitalize words" onChange={(capitalize) => setPassphrase({ ...passphrase, capitalize })} /><Toggle checked={passphrase.includeNumber} label="Insert a number" onChange={(includeNumber) => setPassphrase({ ...passphrase, includeNumber })} /></>} {error === null ? null : <p className="form-error">{error}</p>}<button className="primary full" onClick={() => void generate()} type="button">Generate securely</button></section></div></section>;
}

function Settings({ catalog, onRefresh, status, setStatus, setNotice, setError }: { catalog: OrganizationCatalog; onRefresh: () => void; status: DesktopStatus; setStatus: (status: DesktopStatus) => void; setNotice: (message: string | null) => void; setError: (message: string | null) => void }) {
  const [minutes, setMinutes] = useState(status.autoLockMinutes);
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [clipboard, setClipboard] = useState<ClipboardPolicy | null>(null);
  const isAndroid = /Android/i.test(navigator.userAgent);
  useEffect(() => {
    if (!isAndroid) return;
    void desktop.biometricStatus().then(setBiometric).catch(() => setBiometric(null));
    void desktop.clipboardPolicy().then(setClipboard).catch(() => setClipboard(null));
  }, [isAndroid]);
  const updateBiometric = async (enabled: boolean) => {
    try {
      const next = enabled ? await desktop.enableBiometricUnlock() : await desktop.disableBiometricUnlock();
      setBiometric(next);
      setNotice(next.enabled ? "Biometric unlock is ready for Autofill and passkeys." : "Biometric unlock was removed from this device.");
    } catch (caught) { setError(message(caught)); }
  };
  const updateClipboard = async (clearAfterSeconds: number) => {
    try {
      setClipboard(await desktop.setClipboardPolicy(clearAfterSeconds));
      setNotice(clearAfterSeconds === 0 ? "Clipboard auto-clear is disabled on this device." : "Clipboard clearing policy updated.");
    } catch (caught) { setError(message(caught)); }
  };
  const hardware = biometric?.storageStrongBoxBacked || biometric?.biometricStrongBoxBacked
    ? "StrongBox-backed key available."
    : biometric?.strongBoxAvailable
      ? "StrongBox is available; Hasilan Pass prefers it when the key is created."
    : biometric?.storageHardwareBacked || biometric?.biometricHardwareBacked
      ? "Hardware-backed Keystore key available."
      : "Keystore hardware protection is unavailable or has not been created yet.";
  return <section className="tool-page settings-page"><header><span className="eyebrow">DEVICE + ACCOUNT</span><h1>Settings</h1><p>Controls here affect this device and its encrypted ciphertext cache.</p></header><div className="settings-grid"><SettingsCard title="Security"><div className="setting-line"><div><strong>Automatic lock</strong><small>Clear keys and decrypted items after inactivity</small></div><select aria-label="Automatic lock delay" onChange={(event) => setMinutes(Number(event.target.value))} value={minutes}><option value="1">1 minute</option><option value="5">5 minutes</option><option value="15">15 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option><option value="240">4 hours</option></select></div><button onClick={async () => { try { setStatus(await desktop.setAutoLock(minutes)); setNotice("Automatic lock updated."); } catch (caught) { setError(message(caught)); } }} type="button">Save lock policy</button>{!isAndroid ? null : <><div className="setting-line"><div><strong>Biometric unlock</strong><small>{biometric?.available ? "Required before Android Autofill or passkeys can read the offline vault." : "A Class 3 biometric must be enrolled on this device."}</small></div><button disabled={!biometric?.available} onClick={() => void updateBiometric(!biometric?.enabled)} type="button">{biometric?.enabled ? "Disable" : "Enable"}</button></div><p className="muted">{hardware}</p><div className="setting-line"><div><strong>Clipboard clearing</strong><small>Clear Hasilan Pass copies when they are still unchanged.</small></div><select aria-label="Clipboard clear delay" onChange={(event) => void updateClipboard(Number(event.target.value))} value={clipboard?.clearAfterSeconds ?? 30}><option value="15">15 seconds</option><option value="30">30 seconds</option><option value="60">1 minute</option><option value="120">2 minutes</option><option value="0">Never clear automatically</option></select></div></>}<div className="security-note"><i>◆</i><p>Refresh and device secrets use the OS credential store. Vault keys remain memory-only; the disk cache contains ciphertext.</p></div></SettingsCard><FolderManager catalog={catalog} onError={setError} onNotice={setNotice} onRefresh={onRefresh} onStatus={setStatus} />{!isAndroid ? <SettingsCard title="Import and export"><p className="muted">Bitwarden plaintext JSON is processed locally by the shared Rust compatibility crate.</p><div className="button-row"><button onClick={async () => { if (!window.confirm("The selected Bitwarden JSON may contain plaintext secrets. Continue with local import?")) return; try { const result = await desktop.importBitwarden(); if (result !== null) { onRefresh(); setNotice(`Imported ${result.itemCount} items. Encrypted uploads are queued.`); } } catch (caught) { setError(message(caught)); } }} type="button">Import JSON</button><button className="danger" onClick={async () => { if (!window.confirm("This creates a PLAINTEXT export containing every decrypted vault secret. Store it securely and delete it when finished. Continue?")) return; try { const path = await desktop.exportBitwarden(); if (path !== null) setNotice(`Plaintext export written to ${path}`); } catch (caught) { setError(message(caught)); } }} type="button">Export plaintext JSON</button></div></SettingsCard> : <SettingsCard title="Android services"><p className="muted">Enable both services in Android settings. Each fill, save, and passkey action requires a fresh biometric verification.</p><div className="button-row"><button onClick={() => void desktop.openAutofillSettings().catch((caught) => setError(message(caught)))} type="button">Open Autofill settings</button><button disabled={biometric?.enabled !== true} onClick={() => void desktop.openCredentialProviderSettings().catch((caught) => setError(message(caught)))} type="button">Open passkey settings</button></div></SettingsCard>}<SettingsCard title="Account"><div className="account-card"><span className={status.online ? "status-dot online" : "status-dot"} /><div><strong>{status.email}</strong><small>{status.serverUrl}</small></div></div><p className="muted">Last encrypted sync: {status.lastSyncAt === null ? "Not yet" : formatDate(status.lastSyncAt)}</p><button className="danger" onClick={async () => { if (!window.confirm("Revoke this device session and lock the vault?")) return; try { setStatus(await desktop.logout()); } catch (caught) { setError(message(caught)); } }} type="button">Revoke session and lock</button></SettingsCard>{status.profiles.length > 1 ? <SettingsCard title="Cached accounts">{status.profiles.map((profile) => <button className="profile-row" disabled={profile.active} key={profile.scope} onClick={async () => { try { setStatus(await desktop.selectProfile(profile.scope)); } catch (caught) { setError(message(caught)); } }} type="button"><div><strong>{profile.email}</strong><small>{profile.serverUrl}</small></div><span>{profile.active ? "Current" : "Switch"}</span></button>)}</SettingsCard> : null}{!isAndroid ? null : <AndroidAccountSecurity onError={(next) => setError(next)} onNotice={(next) => setNotice(next)} onStatus={setStatus} />}</div></section>;
}

function FolderManager({ catalog, onRefresh, onStatus, onNotice, onError }: { catalog: OrganizationCatalog; onRefresh: () => void; onStatus: (status: DesktopStatus) => void; onNotice: (message: string | null) => void; onError: (message: string | null) => void }) {
  const [newName, setNewName] = useState("");
  const [renaming, setRenaming] = useState<string | null>(null);
  const [name, setName] = useState("");
  async function save(draft: FolderDraft): Promise<void> {
    try {
      const folder = await desktop.saveFolder(draft);
      setNewName("");
      setRenaming(null);
      onRefresh();
      onNotice(`Encrypted folder ${draft.id === null ? "created" : "renamed"}: ${folder.name}.`);
    } catch (caught) {
      onError(message(caught));
    }
  }
  async function remove(id: string, folderName: string): Promise<void> {
    if (!window.confirm(`Delete “${folderName}”? Its items will remain in your personal vault without a folder.`)) return;
    try {
      onStatus(await desktop.deleteFolder(id));
      onRefresh();
      onNotice("Encrypted folder deleted; affected items were kept.");
    } catch (caught) {
      onError(message(caught));
    }
  }
  return <SettingsCard title="Folders"><p className="muted">Folder names and membership synchronize as encrypted personal-vault objects.</p><form className="folder-create" onSubmit={(event) => { event.preventDefault(); if (newName.trim() !== "") void save({ id: null, name: newName }); }}><input aria-label="New folder name" onChange={(event) => setNewName(event.currentTarget.value)} placeholder="New folder" value={newName} /><button type="submit">Create folder</button></form><div className="folder-list">{catalog.folders.length === 0 ? <p className="muted">No personal folders yet.</p> : catalog.folders.map((folder) => renaming === folder.id ? <form className="folder-row" key={folder.id} onSubmit={(event) => { event.preventDefault(); if (name.trim() !== "") void save({ id: folder.id, name }); }}><input aria-label={`Rename ${folder.name}`} autoFocus onChange={(event) => setName(event.currentTarget.value)} value={name} /><button type="submit">Save</button><button onClick={() => setRenaming(null)} type="button">Cancel</button></form> : <div className="folder-row" key={folder.id}><strong>{folder.name}</strong><button onClick={() => { setRenaming(folder.id); setName(folder.name); }} type="button">Rename</button><button className="danger" onClick={() => void remove(folder.id, folder.name)} type="button">Delete</button></div>)}</div></SettingsCard>;
}

function Conflicts({ setStatus, setError, onRefresh }: { setStatus: (status: DesktopStatus) => void; setError: (message: string | null) => void; onRefresh: () => void }) {
  const [conflicts, setConflicts] = useState<ConflictSummary[] | null>(null);
  useEffect(() => { void desktop.conflicts().then(setConflicts).catch((caught) => setError(message(caught))); }, []);
  async function resolve(id: string, keepLocal: boolean): Promise<void> {
    try { setStatus(await desktop.resolveConflict(id, keepLocal)); setConflicts(await desktop.conflicts()); onRefresh(); } catch (caught) { setError(message(caught)); }
  }
  return <section className="tool-page"><header><span className="eyebrow">NO SILENT DATA LOSS</span><h1>Concurrent edits</h1><p>Both encrypted versions are retained until you choose which one to keep.</p></header><div className="conflicts">{conflicts === null ? <p>Decrypting conflict metadata…</p> : conflicts.length === 0 ? <div className="empty-state"><div>✓</div><h2>No unresolved conflicts</h2><p>Local and server revisions are aligned.</p></div> : conflicts.map((conflict) => <article key={conflict.id}><span>CONCURRENT EDIT</span><div><div><small>THIS DEVICE</small><strong>{conflict.localName}</strong></div><i>⇄</i><div><small>SERVER VERSION</small><strong>{conflict.serverName}</strong></div></div><footer><button className="primary" onClick={() => void resolve(conflict.id, true)} type="button">Keep this device</button><button onClick={() => void resolve(conflict.id, false)} type="button">Keep server</button></footer></article>)}</div></section>;
}

function BrandMark() { return <img alt="" aria-hidden="true" className="brand-mark" src="/hasilan-pass-icon.svg" />; }
function TrustStat({ value, label }: { value: string; label: string }) { return <div><strong>{value}</strong><span>{label}</span></div>; }
function ItemGlyph({ type, large = false }: { type: number; large?: boolean }) {
  const className = `item-glyph ${large ? "large" : ""}`;
  return type === 1
    ? <img alt="" aria-hidden="true" className={className} src="/hasilan-pass-icon.svg" />
    : <span className={className}>{type === 2 ? "N" : type === 3 ? "C" : type === 4 ? "I" : "◆"}</span>;
}
function SettingsCard({ title, children }: { title: string; children: ReactNode }) { return <section className="settings-card"><h2>{title}</h2>{children}</section>; }
function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) { return <label className="toggle"><span>{label}</span><input checked={checked} onChange={(event) => onChange(event.target.checked)} type="checkbox" /><i /></label>; }
function Range({ label, min, max, value, onChange }: { label: string; min: number; max: number; value: number; onChange: (value: number) => void }) { return <label className="range"><span>{label}<strong>{value}</strong></span><input max={max} min={min} onChange={(event) => onChange(event.target.valueAsNumber)} type="range" value={value} /></label>; }

function typeName(type: number): string { return type === 1 ? "Login" : type === 2 ? "Secure note" : type === 3 ? "Card" : type === 4 ? "Identity" : type === 5 ? "SSH key" : "Vault item"; }
function typeFromKind(kind: string): number { return kind === "secureNote" ? 2 : kind === "card" ? 3 : kind === "identity" ? 4 : kind === "sshKey" ? 5 : 0; }
function editableKind(item: VaultItem): EditableItemKind | null { return item.data.kind === "login" || item.data.kind === "secureNote" || item.data.kind === "card" || item.data.kind === "identity" ? item.data.kind : null; }
const identityFields = [
  ["title", "Title", "text"], ["firstName", "First name", "text"], ["middleName", "Middle name", "text"], ["lastName", "Last name", "text"], ["email", "Email", "email"], ["phone", "Phone", "tel"], ["company", "Company", "text"], ["address1", "Address", "text"], ["address2", "Address line 2", "text"], ["address3", "Address line 3", "text"], ["city", "City", "text"], ["state", "State", "text"], ["postalCode", "Postal code", "text"], ["country", "Country", "text"], ["username", "Username", "text"], ["ssn", "National ID", "password"], ["passportNumber", "Passport number", "password"], ["licenseNumber", "License number", "password"],
] as const;
function formatDate(value: string): string { const date = new Date(value); return Number.isNaN(date.valueOf()) ? "unknown" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date); }
function formatFileSize(bytes: number): string { return bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KiB` : bytes < 1024 * 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MiB` : `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`; }
function humanize(value: string): string { return value.replace(/([A-Z])/gu, " $1").replace(/^./u, (letter) => letter.toUpperCase()); }
function organizationName(id: string, catalog: OrganizationCatalog): string { return catalog.organizations.find((organization) => organization.id === id)?.name ?? "Organization"; }
function organizationItemPolicy(item: VaultItem, catalog: OrganizationCatalog): { writable: boolean; hidePasswords: boolean } {
  if (item.organizationId === null) return { writable: true, hidePasswords: false };
  const organization = catalog.organizations.find((candidate) => candidate.id === item.organizationId);
  if (organization === undefined) return { writable: false, hidePasswords: true };
  const elevated = organization.role === "owner" || organization.role === "admin";
  const matching = item.collectionIds.map((id) => catalog.collections.find((collection) => collection.id === id && collection.organizationId === item.organizationId)).filter((collection) => collection !== undefined);
  return {
    writable: elevated || (item.collectionIds.length > 0 && matching.length === item.collectionIds.length && matching.every((collection) => !collection.readOnly)),
    hidePasswords: !elevated && (matching.length === 0 || matching.every((collection) => collection.hidePasswords)),
  };
}
function loginDestinations(item: VaultItem | null | undefined, catalog: OrganizationCatalog): LoginDestination[] {
  const destinations: LoginDestination[] = [{ id: "personal", label: "Personal vault", organizationId: null, collectionIds: [], writable: true }];
  for (const collection of catalog.collections) {
    destinations.push({
      id: `${collection.organizationId}:${collection.id}`,
      label: `${organizationName(collection.organizationId, catalog)} / ${collection.name}`,
      organizationId: collection.organizationId,
      collectionIds: [collection.id],
      writable: !collection.readOnly,
    });
  }
  if (item?.organizationId !== null && item?.organizationId !== undefined && destinationForItem(item, destinations) === undefined) {
    destinations.push({
      id: `current:${item.id}`,
      label: `${organizationName(item.organizationId, catalog)} / Current collections`,
      organizationId: item.organizationId,
      collectionIds: item.collectionIds,
      writable: organizationItemPolicy(item, catalog).writable,
    });
  }
  return destinations;
}
function destinationForItem(item: VaultItem | null, destinations: LoginDestination[]): LoginDestination | undefined {
  if (item === null || item.organizationId === null) return destinations.find((destination) => destination.organizationId === null);
  return destinations.find((destination) => destination.organizationId === item.organizationId && destination.collectionIds.length === item.collectionIds.length && destination.collectionIds.every((id) => item.collectionIds.includes(id)));
}
function field(data: FormData, name: string): string { const value = data.get(name); return typeof value === "string" ? value : ""; }
function optional(value: string): string | null { const trimmed = value.trim(); return trimmed === "" ? null : trimmed; }
function optionalVerbatim(value: string): string | null { return value.trim() === "" ? null : value; }
function deepLinkNotice(action: string): string {
  if (action === "verify-email") return "Return to your server to complete email verification.";
  if (action === "invitation") return "Open the encrypted vault to review the shared-vault invitation.";
  if (action === "passkey") return "Open Settings to manage account passkeys.";
  return "Hasilan Pass opened securely.";
}
function message(error: unknown): string { return typeof error === "string" && error.trim() !== "" ? error : error instanceof Error && error.message.trim() !== "" ? error.message : "The desktop operation failed."; }
