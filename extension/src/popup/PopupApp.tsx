import { useEffect, useState, type FormEvent, type MouseEvent } from "react";
import browser from "webextension-polyfill";

import { getAccountWebauthnCredential } from "../account-webauthn";
import {
  FALLBACK_ATTACHMENT_DOWNLOAD_LIMIT,
  decodeBase64Url,
  encodeBase64Url,
  formatFileSize,
} from "../attachment-transfer";
import { MESSAGE_CHANNEL, type ExtensionResponse } from "../messages";
import type {
  AttachmentMetadata,
  AttachmentResponse,
  ExtensionState,
  ItemSummary,
  LoginDraft,
  LoginValue,
  PendingCredentialSummary,
  VaultItem,
} from "../types";

type View = "vault" | "item" | "editor" | "generator" | "settings";
type GeneratedValue = { kind: "password" | "username"; value: string };

export function PopupApp() {
  const [state, setState] = useState<ExtensionState | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [selected, setSelected] = useState<VaultItem | null>(null);
  const [view, setView] = useState<View>("vault");
  const [editing, setEditing] = useState<VaultItem | null>(null);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [generated, setGenerated] = useState<GeneratedValue | null>(null);
  const [totp, setTotp] = useState<{ code: string; remainingSeconds: number } | null>(null);

  useEffect(() => {
    void refreshState();
  }, []);

  useEffect(() => {
    if (state?.unlocked !== true) return;
    const timer = window.setTimeout(() => void listItems(query), 80);
    return () => window.clearTimeout(timer);
  }, [query, state?.unlocked]);

  useEffect(() => {
    if (selected?.data.kind !== "login") {
      setTotp(null);
      return undefined;
    }
    const login = selected.data.value as LoginValue;
    if (login.totp === null) {
      setTotp(null);
      return undefined;
    }
    const update = () => {
      void send<{ code: string; remainingSeconds: number }>({
        type: "TOTP",
        id: selected.id,
        unixSeconds: Math.floor(Date.now() / 1_000),
      }).then(setTotp).catch(() => setTotp(null));
    };
    update();
    const timer = window.setInterval(update, 1_000);
    return () => window.clearInterval(timer);
  }, [selected]);

  async function refreshState(): Promise<void> {
    try {
      const next = await send<ExtensionState>({ type: "GET_STATE" });
      setState(next);
      if (next.unlocked) await listItems(query);
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function listItems(search: string): Promise<void> {
    try {
      const next = await send<ItemSummary[]>({ type: "LIST_ITEMS", query: search, category: "all" });
      setItems(next);
      if (search === "") {
        setState((current) => current === null ? null : { ...current, itemCount: next.length });
      }
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
    let password = field(data, "password");
    setBusy(true);
    setError(null);
    try {
      const pattern = serverPattern(serverUrl);
      if (!(await browser.permissions.request({ origins: [pattern] }))) {
        throw new Error("Server access permission is required to sign in.");
      }
      const operation = mode === "login"
        ? state?.authenticated === true
          ? send<ExtensionState>({ type: "UNLOCK", email, password, rememberUnlock: data.get("rememberUnlock") === "on" })
          : send<ExtensionState>({
              type: "LOGIN",
              serverUrl,
              email,
              password,
              secondFactor: optional(field(data, "factor")),
              rememberDevice: data.get("rememberDevice") === "on",
              rememberUnlock: data.get("rememberUnlock") === "on",
            })
        : send<ExtensionState>({ type: "REGISTER", serverUrl, email, password });
      password = "";
      const next = await operation;
      setState(next);
      form.reset();
      await listItems("");
    } catch (caught) {
      setError(message(caught));
    } finally {
      const passwordInput = form.elements.namedItem("password");
      if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
      setBusy(false);
    }
  }

  async function authenticateWithWebauthn(
    event: MouseEvent<HTMLButtonElement>,
    webauthnMode: "passkey" | "mfa",
  ): Promise<void> {
    const form = event.currentTarget.form;
    if (form === null || !form.reportValidity()) return;
    const data = new FormData(form);
    const serverUrl = field(data, "serverUrl").trim();
    const email = field(data, "email").trim();
    let password = field(data, "password");
    setBusy(true);
    setError(null);
    try {
      const serverAccess = serverPattern(serverUrl);
      if (!(await browser.permissions.request({ origins: [serverAccess] }))) {
        throw new Error("Server access permission is required to sign in.");
      }
      const challenge = await send<{ ceremonyId: string; options: Record<string, unknown> }>({
        type: "START_ACCOUNT_WEBAUTHN",
        mode: webauthnMode,
        serverUrl,
        email,
        password,
      });
      password = "";
      const rpId = accountRpId(challenge.options);
      const server = new URL(serverUrl);
      const rpPattern = `${server.protocol}//${rpId}/*`;
      if (!(await browser.permissions.contains({ origins: [rpPattern] }))) {
        if (!(await browser.permissions.request({ origins: [rpPattern] }))) {
          throw new Error(`Host permission for the account WebAuthn RP (${rpId}) is required.`);
        }
      }
      const credential = await getAccountWebauthnCredential(challenge.options);
      const next = await send<ExtensionState>({
        type: "FINISH_ACCOUNT_WEBAUTHN",
        ceremonyId: challenge.ceremonyId,
        credential,
        rememberDevice: data.get("rememberDevice") === "on",
        rememberUnlock: data.get("rememberUnlock") === "on",
      });
      setState(next);
      form.reset();
      await listItems("");
    } catch (caught) {
      setError(message(caught));
    } finally {
      password = "";
      const passwordInput = form.elements.namedItem("password");
      if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
      setBusy(false);
    }
  }

  async function sync(): Promise<void> {
    setBusy(true);
    try {
      setState(await send<ExtensionState>({ type: "SYNC" }));
      await listItems(query);
      setNotice("Encrypted vault synchronized.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function lock(): Promise<void> {
    await send({ type: "LOCK" }).catch(() => undefined);
    setState((current) => current === null ? null : { ...current, unlocked: false, itemCount: 0, pending: null });
    setItems([]);
    setSelected(null);
    setView("vault");
  }

  async function logout(): Promise<void> {
    await send({ type: "LOGOUT" }).catch((caught) => setError(message(caught)));
    await refreshState();
    setItems([]);
    setSelected(null);
    setView("vault");
  }

  async function openItem(id: string): Promise<void> {
    try {
      setSelected(await send<VaultItem>({ type: "GET_ITEM", id }));
      setView("item");
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function saveLogin(draft: LoginDraft): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const item = editing === null
        ? await send<VaultItem>({ type: "CREATE_LOGIN", draft })
        : await send<VaultItem>({ type: "UPDATE_LOGIN", id: editing.id, draft });
      setSelected(item);
      setEditing(null);
      setGenerated(null);
      setView("item");
      await listItems(query);
      setNotice("Credential encrypted and saved.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function removeItem(): Promise<void> {
    if (selected === null || !window.confirm(`Move “${selected.name}” to trash?`)) return;
    setBusy(true);
    try {
      await send({ type: "DELETE_ITEM", id: selected.id });
      setSelected(null);
      setView("vault");
      await listItems(query);
      setNotice("Credential moved to trash.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function uploadAttachment(file: File, existing?: AttachmentMetadata): Promise<void> {
    if (selected === null) return;
    const itemId = selected.id;
    setBusy(true);
    setError(null);
    try {
      const transfer = await send<AttachmentBeginResult>({
        type: "ATTACHMENT_BEGIN",
        itemId,
        attachmentId: existing?.id ?? null,
        fileName: file.name,
        mediaType: file.type || "application/octet-stream",
        size: file.size,
      });
      setSelected(transfer.item);
      if (transfer.status.state !== "complete") {
        for (let index = 0; index < transfer.metadata.chunkCount; index += 1) {
          const start = index * transfer.metadata.chunkSize;
          const end = Math.min(file.size, start + transfer.metadata.chunkSize);
          const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
          let encoded = "";
          try {
            encoded = encodeBase64Url(plaintext);
          } finally {
            plaintext.fill(0);
          }
          try {
            await send({
              type: "ATTACHMENT_UPLOAD_CHUNK",
              itemId,
              attachmentId: transfer.metadata.id,
              index,
              plaintext: encoded,
            });
          } finally {
            encoded = "";
          }
          setNotice(`Encrypted attachment upload ${index + 1}/${transfer.metadata.chunkCount}…`);
        }
        await send({
          type: "ATTACHMENT_COMPLETE",
          itemId,
          attachmentId: transfer.metadata.id,
        });
      }
      setSelected(await send<VaultItem>({ type: "GET_ITEM", id: itemId }));
      setNotice(`“${transfer.metadata.fileName}” encrypted and uploaded.`);
    } catch (caught) {
      try { setSelected(await send<VaultItem>({ type: "GET_ITEM", id: itemId })); } catch { /* vault may have locked */ }
      setError(`Attachment upload paused: ${message(caught)} Select the same file and use Retry.`);
    } finally {
      setBusy(false);
    }
  }

  async function downloadAttachment(attachment: AttachmentMetadata): Promise<void> {
    if (selected === null) return;
    const itemId = selected.id;
    setBusy(true);
    setError(null);
    let writer: AttachmentFileWriter | null = null;
    try {
      const picker = attachmentSavePicker();
      const fallbackParts: ArrayBuffer[] = [];
      if (picker !== null) {
        const handle = await picker({ suggestedName: attachment.fileName });
        writer = await handle.createWritable();
      } else if (attachment.size > FALLBACK_ATTACHMENT_DOWNLOAD_LIMIT) {
        throw new Error("This browser needs a streaming save picker for downloads larger than 128 MiB.");
      }
      let downloadedBytes = 0;
      for (let index = 0; index < attachment.chunkCount; index += 1) {
        let encoded = await send<string>({
          type: "ATTACHMENT_DOWNLOAD_CHUNK",
          itemId,
          attachmentId: attachment.id,
          index,
        });
        let plaintext: Uint8Array;
        try {
          plaintext = decodeBase64Url(encoded);
        } finally {
          encoded = "";
        }
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
        setNotice(`Authenticating attachment ${index + 1}/${attachment.chunkCount}…`);
      }
      if (downloadedBytes !== attachment.size) throw new Error("The attachment length did not authenticate.");
      if (writer !== null) {
        await writer.close();
        writer = null;
      } else {
        downloadBlob(attachment.fileName, attachment.mediaType, fallbackParts);
      }
      setNotice(`“${attachment.fileName}” authenticated and decrypted.`);
    } catch (caught) {
      await writer?.abort().catch(() => undefined);
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
      const result = await send<{ item: VaultItem; cleanupWarning: boolean }>({
        type: "ATTACHMENT_REMOVE",
        itemId: selected.id,
        attachmentId: attachment.id,
      });
      setSelected(result.item);
      setNotice(result.cleanupWarning
        ? "Attachment reference removed; encrypted server storage cleanup must be retried."
        : "Encrypted attachment removed.");
    } catch (caught) {
      setError(`Attachment removal failed: ${message(caught)}`);
    } finally {
      setBusy(false);
    }
  }

  async function enableCurrentSite(): Promise<void> {
    try {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (tab?.id === undefined || tab.url === undefined) throw new Error("Open an HTTP(S) page first.");
      const url = new URL(tab.url);
      if (!matchesPage(url)) throw new Error("Autofill cannot run on this browser page.");
      const matchPattern = `${url.origin}/*`;
      if (!(await browser.permissions.request({ origins: [matchPattern] }))) {
        throw new Error("Site access was not granted.");
      }
      await send({ type: "REGISTER_SITE", matchPattern, tabId: tab.id });
      setNotice(`Autofill enabled for ${url.hostname}.`);
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function savePending(existingId: string | null): Promise<void> {
    setBusy(true);
    try {
      await send({ type: "SAVE_PENDING", existingId });
      setState((current) => current === null ? null : { ...current, pending: null });
      await listItems(query);
      setNotice(existingId === null ? "New credential saved." : "Saved password updated.");
    } catch (caught) {
      setError(message(caught));
    } finally {
      setBusy(false);
    }
  }

  async function dismissPending(): Promise<void> {
    await send({ type: "DISMISS_PENDING" });
    setState((current) => current === null ? null : { ...current, pending: null });
  }

  async function generate(kind: GeneratedValue["kind"], length: number): Promise<void> {
    try {
      const value = kind === "password"
        ? await send<string>({
            type: "GENERATE_PASSWORD",
            options: {
              length,
              uppercase: true,
              lowercase: true,
              numbers: true,
              symbols: true,
              minimumNumbers: 1,
              minimumSymbols: 1,
              excludeAmbiguous: true,
            },
          })
        : await send<string>({
            type: "GENERATE_USERNAME",
            options: { length, minimumNumbers: 2 },
          });
      setGenerated({ kind, value });
    } catch (caught) {
      setError(message(caught));
    }
  }

  async function copy(value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      setNotice("Copied. Clipboard clearing is scheduled in 30 seconds.");
      window.setTimeout(() => void navigator.clipboard.writeText("").catch(() => undefined), 30_000);
    } catch (caught) {
      setError(message(caught));
    }
  }

  if (state === null) return <div className="popup-loading"><img alt="" className="logo" src="/icons/icon.svg" /><p>Loading vault core…</p></div>;
  if (!state.unlocked) {
    return (
      <main className="popup auth-popup">
        <Header subtitle="Standalone browser vault" />
        <div className="auth-tabs">
          <button className={mode === "login" ? "active" : ""} onClick={() => setMode("login")} type="button">Unlock</button>
          <button className={mode === "register" ? "active" : ""} onClick={() => setMode("register")} type="button">Create</button>
        </div>
        <form className="popup-form" onSubmit={(event) => void authenticate(event)}>
          <label>Server URL<input defaultValue={state.serverUrl ?? "http://127.0.0.1:8080"} name="serverUrl" required type="url" /></label>
          <label>Email<input autoComplete="username" defaultValue={state.email ?? ""} name="email" required type="email" /></label>
          <label>Master password<input autoComplete={mode === "login" ? "current-password" : "new-password"} minLength={mode === "register" ? 12 : undefined} name="password" required type="password" /></label>
          {mode === "login" ? (
            <>
              {state.authenticated ? null : <label>Authenticator or recovery code <span>if enabled</span><input autoComplete="one-time-code" name="factor" /></label>}
              {state.authenticated ? null : <label className="popup-checkbox"><input name="rememberDevice" type="checkbox" />Trust this browser for 30 days</label>}
              <label className="popup-checkbox"><input name="rememberUnlock" type="checkbox" /><span>Remember unlock on this device (encrypted, optional)<small className="remember-warning">Anyone using this device may unlock the vault; memory-only mode is stronger.</small></span></label>
            </>
          ) : null}
          {error === null ? null : <p className="error" role="alert">{error}</p>}
          <button className="primary" disabled={busy} type="submit">{busy ? "Deriving keys…" : mode === "login" ? "Unlock vault" : "Create vault"}</button>
          {mode === "login" && !state.authenticated ? (
            <div className="auth-alternatives">
              <button disabled={busy} onClick={(event) => void authenticateWithWebauthn(event, "passkey")} type="button">Sign in with account passkey</button>
              <button disabled={busy} onClick={(event) => void authenticateWithWebauthn(event, "mfa")} type="button">Use security key as 2FA</button>
            </div>
          ) : null}
        </form>
        <p className="trust-note">The master password is processed by the packaged Rust/WASM core and is never sent to the server.</p>
      </main>
    );
  }

  return (
    <main className="popup">
      <Header
        onBack={view === "vault" ? undefined : () => { setView("vault"); setSelected(null); setEditing(null); }}
        subtitle={`${state.itemCount} encrypted item${state.itemCount === 1 ? "" : "s"}`}
      />
      {notice === null ? null : <button className="notice" onClick={() => setNotice(null)} type="button">{notice}</button>}
      {error === null ? null : <button className="error dismissible" onClick={() => setError(null)} type="button">{error}</button>}

      {state.pending === null ? null : (
        <PendingCard busy={busy} pending={state.pending} onDismiss={() => void dismissPending()} onSave={(id) => void savePending(id)} />
      )}

      {view === "vault" ? (
        <>
          <div className="search-row">
            <input aria-label="Search vault" autoFocus onChange={(event) => setQuery(event.target.value)} placeholder="Search vault" value={query} />
            <button aria-label="Sync vault" disabled={busy} onClick={() => void sync()} type="button">↻</button>
          </div>
          <div className="quick-actions">
            <button onClick={() => { setEditing(null); setGenerated(null); setView("editor"); }} type="button"><span>＋</span>New</button>
            <button onClick={() => setView("generator")} type="button"><span>✦</span>Generate</button>
            <button onClick={() => void enableCurrentSite()} type="button"><span>↗</span>Enable site</button>
          </div>
          <section className="vault-items" aria-label="Vault items">
            {items.length === 0 ? <div className="empty"><strong>No matching items</strong><p>Create a login or synchronize this account.</p></div> : null}
            {items.map((item) => (
              <button className="vault-row" key={item.id} onClick={() => void openItem(item.id)} type="button">
                <img alt="" className="row-icon" src="/icons/icon.svg" />
                <span><strong>{item.name}</strong><small>{item.username ?? item.primaryUri ?? "Login"}</small></span>
                <i>{item.hasTotp ? "◷" : "›"}</i>
              </button>
            ))}
          </section>
          <footer className="popup-footer">
            <button onClick={() => setView("settings")} type="button">Settings</button>
            <button onClick={() => void lock()} type="button">Lock</button>
          </footer>
        </>
      ) : null}

      {view === "item" && selected !== null ? (
        <ItemView
          busy={busy}
          item={selected}
          onAttach={(file, existing) => void uploadAttachment(file, existing)}
          onCopy={(value) => void copy(value)}
          onDelete={() => void removeItem()}
          onDownloadAttachment={(attachment) => void downloadAttachment(attachment)}
          onEdit={() => { setEditing(selected); setView("editor"); }}
          onRemoveAttachment={(attachment) => void removeAttachment(attachment)}
          totp={totp}
        />
      ) : null}
      {view === "editor" ? <LoginEditor busy={busy} generated={generated} item={editing} onSave={(draft) => void saveLogin(draft)} /> : null}
      {view === "generator" ? <Generator generated={generated} onCopy={(value) => void copy(value)} onGenerate={(kind, length) => void generate(kind, length)} onUse={() => { setEditing(null); setView("editor"); }} /> : null}
      {view === "settings" ? <Settings onAutoLock={(minutes) => void send<ExtensionState>({ type: "SET_AUTO_LOCK", minutes }).then(setState).catch((caught) => setError(message(caught)))} onRememberUnlock={(enabled) => void send<ExtensionState>({ type: "SET_REMEMBER_UNLOCK", enabled }).then(setState).catch((caught) => setError(message(caught)))} state={state} onEnable={() => void enableCurrentSite()} onLock={() => void lock()} onLogout={() => void logout()} /> : null}
    </main>
  );
}

function Header({ subtitle, onBack }: { subtitle: string; onBack?: (() => void) | undefined }) {
  return (
    <header className="popup-header">
      {onBack === undefined ? <img alt="" className="logo" src="/icons/icon.svg" /> : <button aria-label="Back" className="back" onClick={onBack} type="button">‹</button>}
      <div><strong>Hasilan Pass</strong><small>{subtitle}</small></div>
      <span className="secure-dot" title="Local vault core active" />
    </header>
  );
}

function PendingCard({ pending, busy, onSave, onDismiss }: { pending: PendingCredentialSummary; busy: boolean; onSave: (id: string | null) => void; onDismiss: () => void }) {
  return (
    <section className="pending-card">
      <div><span>Save detected login</span><strong>{pending.name}</strong><small>{pending.username ?? "No username"}</small></div>
      <div className="pending-actions">
        <button disabled={busy} onClick={() => onSave(null)} type="button">Save new</button>
        {pending.matches.slice(0, 2).map((match) => <button disabled={busy} key={match.id} onClick={() => onSave(match.id)} type="button">Update {match.name}</button>)}
        <button className="dismiss" onClick={onDismiss} type="button">Dismiss</button>
      </div>
    </section>
  );
}

function ItemView({
  busy,
  item,
  totp,
  onAttach,
  onCopy,
  onEdit,
  onDelete,
  onDownloadAttachment,
  onRemoveAttachment,
}: {
  busy: boolean;
  item: VaultItem;
  totp: { code: string; remainingSeconds: number } | null;
  onAttach: (file: File, existing?: AttachmentMetadata) => void;
  onCopy: (value: string) => void;
  onEdit: () => void;
  onDelete: () => void;
  onDownloadAttachment: (attachment: AttachmentMetadata) => void;
  onRemoveAttachment: (attachment: AttachmentMetadata) => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const login = item.data.kind === "login" ? item.data.value as LoginValue : null;
  if (login === null) return <section className="item-view"><h2>{item.name}</h2><p>This item type is available in the Web Vault editor.</p></section>;
  return (
    <section className="item-view">
      <div className="item-title"><img alt="" className="row-icon big" src="/icons/icon.svg" /><div><small>Login</small><h2>{item.name}</h2></div></div>
      <SecretField label="Username" value={login.username} onCopy={onCopy} />
      <SecretField label="Password" masked={!revealed} value={login.password} onCopy={onCopy} onReveal={() => setRevealed((value) => !value)} />
      {login.uris[0]?.uri === undefined ? null : <SecretField label="Website" value={login.uris[0].uri} onCopy={onCopy} />}
      {totp === null ? null : <button className="totp" onClick={() => onCopy(totp.code)} type="button"><strong>{totp.code}</strong><span>{totp.remainingSeconds}s</span></button>}
      <section className="attachment-section">
        <div className="attachment-heading">
          <div><strong>Attachments</strong><small>Encrypted before upload</small></div>
          <label className={busy ? "attachment-picker disabled" : "attachment-picker"}>
            Attach
            <input
              disabled={busy}
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                event.currentTarget.value = "";
                if (file !== undefined) onAttach(file);
              }}
              type="file"
            />
          </label>
        </div>
        {item.attachments.length === 0 ? <p className="attachment-empty">No encrypted attachments.</p> : null}
        {item.attachments.map((attachment) => (
          <div className="attachment-row" key={attachment.id}>
            <div><strong title={attachment.fileName}>{attachment.fileName}</strong><small>{formatFileSize(attachment.size)} · {attachment.mediaType}</small></div>
            <div>
              <button disabled={busy} onClick={() => onDownloadAttachment(attachment)} type="button">Download</button>
              <label className={busy ? "attachment-action disabled" : "attachment-action"}>
                Retry
                <input
                  disabled={busy}
                  onChange={(event) => {
                    const file = event.currentTarget.files?.[0];
                    event.currentTarget.value = "";
                    if (file !== undefined) onAttach(file, attachment);
                  }}
                  type="file"
                />
              </label>
              <button className="remove" disabled={busy} onClick={() => onRemoveAttachment(attachment)} type="button">Remove</button>
            </div>
          </div>
        ))}
      </section>
      <div className="item-buttons"><button className="primary" onClick={onEdit} type="button">Edit</button><button className="danger" onClick={onDelete} type="button">Trash</button></div>
    </section>
  );
}

function SecretField({ label, value, masked = false, onCopy, onReveal }: { label: string; value: string | null; masked?: boolean; onCopy: (value: string) => void; onReveal?: () => void }) {
  return (
    <div className="secret-field"><span>{label}</span><div><strong>{value === null ? "—" : masked ? "••••••••••" : value}</strong>{onReveal === undefined || value === null ? null : <button onClick={onReveal} type="button">{masked ? "Show" : "Hide"}</button>}{value === null ? null : <button onClick={() => onCopy(value)} type="button">Copy</button>}</div></div>
  );
}

function LoginEditor({ item, generated, busy, onSave }: { item: VaultItem | null; generated: GeneratedValue | null; busy: boolean; onSave: (draft: LoginDraft) => void }) {
  const login = item?.data.kind === "login" ? item.data.value as LoginValue : null;
  function submit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    onSave({
      name: field(data, "name").trim(),
      username: optional(field(data, "username")),
      password: optionalVerbatim(field(data, "password")),
      uri: optional(field(data, "uri")),
      totp: optional(field(data, "totp")),
      notes: optionalVerbatim(field(data, "notes")),
      favorite: data.get("favorite") === "on",
    });
  }
  return (
    <form className="editor popup-form" onSubmit={submit}>
      <h2>{item === null ? "New login" : "Edit login"}</h2>
      <label>Name<input defaultValue={item?.name ?? ""} name="name" required /></label>
      <label>Username<input defaultValue={generated?.kind === "username" ? generated.value : login?.username ?? ""} name="username" /></label>
      <label>Password<input defaultValue={generated?.kind === "password" ? generated.value : login?.password ?? ""} name="password" type="password" /></label>
      <label>Website URL<input defaultValue={login?.uris[0]?.uri ?? ""} name="uri" type="url" /></label>
      <label>Authenticator key<input defaultValue={login?.totp ?? ""} name="totp" /></label>
      <label>Notes<textarea defaultValue={item?.notes ?? ""} name="notes" rows={3} /></label>
      <label className="check"><input defaultChecked={item?.favorite ?? false} name="favorite" type="checkbox" />Favorite</label>
      <button className="primary" disabled={busy} type="submit">{busy ? "Encrypting…" : "Encrypt and save"}</button>
    </form>
  );
}

function Generator({ generated, onGenerate, onCopy, onUse }: { generated: GeneratedValue | null; onGenerate: (kind: GeneratedValue["kind"], length: number) => void; onCopy: (value: string) => void; onUse: () => void }) {
  const [kind, setKind] = useState<GeneratedValue["kind"]>("password");
  const [length, setLength] = useState(24);
  return (
    <section className="generator">
      <h2>Credential generator</h2>
      <div className="generator-tabs">
        <button className={kind === "password" ? "active" : ""} onClick={() => setKind("password")} type="button">Password</button>
        <button className={kind === "username" ? "active" : ""} onClick={() => setKind("username")} type="button">Username</button>
      </div>
      <label>Length <strong>{length}</strong><input max="128" min="8" onChange={(event) => setLength(event.target.valueAsNumber)} type="range" value={length} /></label>
      <button className="primary" onClick={() => onGenerate(kind, length)} type="button">Generate securely</button>
      {generated === null ? null : <div className="generated"><small>{generated.kind === "password" ? "PASSWORD" : "USERNAME"}</small><code>{generated.value}</code><div><button onClick={() => onCopy(generated.value)} type="button">Copy</button><button onClick={onUse} type="button">Use in new login</button></div></div>}
    </section>
  );
}

function Settings({ state, onEnable, onLock, onLogout, onAutoLock, onRememberUnlock }: { state: ExtensionState; onEnable: () => void; onLock: () => void; onLogout: () => void; onAutoLock: (minutes: number | null) => void; onRememberUnlock: (enabled: boolean) => void }) {
  return (
    <section className="settings">
      <h2>Extension settings</h2>
      <div className="setting-row"><span>Account</span><strong>{state.email}</strong></div>
      <div className="setting-row"><span>Server</span><strong>{state.serverUrl}</strong></div>
      <label className="setting-row">Automatic lock<select aria-label="Automatic lock delay" onChange={(event) => onAutoLock(event.target.value === "never" ? null : Number(event.target.value))} value={state.autoLockMinutes === null ? "never" : String(state.autoLockMinutes)}><option value="1">1 minute</option><option value="5">5 minutes</option><option value="15">15 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option><option value="240">4 hours</option><option value="never">Never</option></select></label>
      <label className="setting-row"><span>Remember unlock on this device</span><input aria-label="Remember unlock on this device" checked={state.rememberUnlock} onChange={(event) => onRememberUnlock(event.currentTarget.checked)} type="checkbox" /></label>
      <p className="remember-warning">Encrypted device storage is convenient, but memory-only mode is stronger against anyone who can use this device.</p>
      <div className="security-box"><strong>Secure runtime</strong><p>Keys and access tokens are memory-only. Browser storage contains ciphertext and non-secret preferences.</p></div>
      <button className="primary" onClick={onEnable} type="button">Enable autofill on current site</button>
      <button className="primary full" onClick={onLock} type="button">Lock vault (keep session)</button>
      <button className="danger full" onClick={onLogout} type="button">Log out and revoke session</button>
    </section>
  );
}

interface AttachmentBeginResult {
  metadata: AttachmentMetadata;
  status: AttachmentResponse;
  item: VaultItem;
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
  const candidate = (window as unknown as {
    showSaveFilePicker?: (options: Record<string, unknown>) => Promise<AttachmentFileHandle>;
  }).showSaveFilePicker;
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

async function send<T = unknown>(body: Record<string, unknown>): Promise<T> {
  const response = await browser.runtime.sendMessage({ channel: MESSAGE_CHANNEL, ...body }) as ExtensionResponse<T>;
  if (!response.ok) throw new Error(response.error);
  return response.data;
}

function serverPattern(value: string): string {
  const url = new URL(value.trim());
  return `${url.origin}/*`;
}

function accountRpId(options: Record<string, unknown>): string {
  const publicKey = options.publicKey;
  if (
    typeof publicKey !== "object"
    || publicKey === null
    || !("rpId" in publicKey)
    || typeof publicKey.rpId !== "string"
  ) {
    throw new Error("The server did not return a valid WebAuthn RP ID.");
  }
  return publicKey.rpId;
}

function matchesPage(url: URL): boolean {
  return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "";
}

function field(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

function optional(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

function optionalVerbatim(value: string): string | null {
  return value.trim() === "" ? null : value;
}

function message(error: unknown): string {
  return error instanceof Error && error.message !== "" ? error.message : "The operation failed.";
}
