import { useState } from "react";

import { copySecret } from "../security";
import type { AttachmentMetadata, LoginValue, TotpCode, VaultItem } from "../types";

interface ItemDetailProps {
  item: VaultItem;
  totp: TotpCode | null;
  onClose: () => void;
  onDelete: () => void;
  onEdit: () => void;
  onNotice: (message: string) => void;
  attachmentBusy: boolean;
  onAttach: (file: File, existing?: AttachmentMetadata) => void;
  onDownloadAttachment: (attachment: AttachmentMetadata) => void;
  onRemoveAttachment: (attachment: AttachmentMetadata) => void;
}

export function ItemDetail({ item, totp, onClose, onDelete, onEdit, onNotice, attachmentBusy, onAttach, onDownloadAttachment, onRemoveAttachment }: ItemDetailProps) {
  const [revealPassword, setRevealPassword] = useState(false);
  const [revealPrivate, setRevealPrivate] = useState(false);
  const login = item.data.kind === "login" ? (item.data.value as LoginValue) : null;

  async function copy(value: string, label: string): Promise<void> {
    try {
      await copySecret(value);
      onNotice(`${label} copied. Clipboard clearing is scheduled in 30 seconds.`);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "Clipboard access failed.");
    }
  }

  return (
    <aside className="detail-panel" aria-label={`${item.name} details`}>
      <header className="detail-header">
        <div className="item-glyph large" aria-hidden="true">{glyphFor(item.data.kind)}</div>
        <div className="detail-title">
          <p className="eyebrow">{labelFor(item.data.kind)}</p>
          <h2>{item.name}</h2>
        </div>
        <button aria-label="Close item" className="icon-button" onClick={onClose} type="button">×</button>
      </header>

      {login === null ? (
        <GenericDetails item={item} reveal={revealPrivate} onReveal={() => setRevealPrivate((value) => !value)} onCopy={copy} />
      ) : (
        <div className="detail-content">
          <DetailSection title="Credentials">
            <ValueRow label="Username" value={login.username} onCopy={copy} />
            <SecretRow
              label="Password"
              revealed={revealPassword}
              value={login.password}
              onCopy={copy}
              onReveal={() => setRevealPassword((value) => !value)}
            />
            {login.uris.map((uri, index) => (
              <ValueRow key={`${uri.uri}-${index}`} label={index === 0 ? "Website" : `Website ${index + 1}`} value={uri.uri} link onCopy={copy} />
            ))}
          </DetailSection>

          {totp === null ? null : (
            <DetailSection title="Authenticator">
              <button className="totp-card" onClick={() => void copy(totp.code, "Verification code")} type="button">
                <span className="totp-code">{totp.code}</span>
                <span className="totp-time">{totp.remainingSeconds}s</span>
                <span className="totp-progress" style={{ "--remaining": `${Math.min(100, (totp.remainingSeconds / totp.period) * 100)}%` } as React.CSSProperties} />
              </button>
              <p className="totp-metadata">
                <span>{totp.issuer ?? "Authenticator"}</span>
                {totp.accountName === null ? null : <span>{totp.accountName}</span>}
                <span>{totp.algorithm} · {totp.digits} digits · {totp.period}s</span>
              </p>
            </DetailSection>
          )}

          {login.fido2Credentials.length === 0 ? null : (
            <DetailSection title="Passkeys">
              {login.fido2Credentials.map((credential, index) => (
                <div className="passkey-card" key={String(credential.credentialId ?? index)}>
                  <span className="status-dot" />
                  <div>
                    <strong>{String(credential.rpName ?? credential.rpId ?? "Passkey")}</strong>
                    <p>{String(credential.userDisplayName ?? credential.userName ?? "Discoverable credential")}</p>
                  </div>
                </div>
              ))}
            </DetailSection>
          )}

          {item.notes === null ? null : (
            <DetailSection title="Notes"><p className="notes-block">{item.notes}</p></DetailSection>
          )}
        </div>
      )}

      {item.deletedDate === null ? (
        <div className="detail-content attachment-content">
          <DetailSection title="Attachments">
            {item.attachments.length === 0 ? <p className="muted">No encrypted attachments.</p> : null}
            {item.attachments.map((attachment) => (
              <div className="attachment-row" key={attachment.id}>
                <span aria-hidden="true">⇩</span>
                <div><strong>{attachment.fileName}</strong><small>{formatBytes(attachment.size)} · {attachment.mediaType}</small></div>
                <button disabled={attachmentBusy} onClick={() => onDownloadAttachment(attachment)} type="button">Download</button>
                <label className={attachmentBusy ? "disabled" : ""}>Retry<input disabled={attachmentBusy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; if (file !== undefined) onAttach(file, attachment); }} type="file" /></label>
                <button className="danger-text" disabled={attachmentBusy} onClick={() => onRemoveAttachment(attachment)} type="button">Remove</button>
              </div>
            ))}
            <label className={`attachment-picker${attachmentBusy ? " disabled" : ""}`}>
              {attachmentBusy ? "Encrypting attachment…" : "＋ Attach encrypted file"}
              <input disabled={attachmentBusy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; if (file !== undefined) onAttach(file); }} type="file" />
            </label>
            <p className="attachment-note">Files are split into 1 MiB frames and encrypted locally before upload.</p>
          </DetailSection>
        </div>
      ) : null}

      <footer className="detail-actions">
        {isEditableKind(item.data.kind) && item.deletedDate === null ? (
          <button className="primary-button" onClick={onEdit} type="button">Edit item</button>
        ) : null}
        {item.deletedDate === null ? (
          <button className="danger-button" onClick={onDelete} type="button">Move to trash</button>
        ) : (
          <span className="trash-note">Deleted {formatDate(item.deletedDate)}</span>
        )}
      </footer>
    </aside>
  );
}

interface GenericDetailsProps {
  item: VaultItem;
  reveal: boolean;
  onReveal: () => void;
  onCopy: (value: string, label: string) => Promise<void>;
}

function GenericDetails({ item, reveal, onReveal, onCopy }: GenericDetailsProps) {
  const entries = Object.entries(item.data.value).filter(([, value]) => value !== null && value !== "");
  return (
    <div className="detail-content">
      <DetailSection title={labelFor(item.data.kind)}>
        {entries.length === 0 ? <p className="muted">No structured fields.</p> : null}
        {entries.map(([key, value]) => {
          const rendered = printable(value);
          return (
            <div className="value-row" key={key}>
              <span>{humanize(key)}</span>
              <div>
                <strong>{reveal ? rendered : privateMask(rendered)}</strong>
                {rendered === "" ? null : <button onClick={() => void onCopy(rendered, humanize(key))} type="button">Copy</button>}
              </div>
            </div>
          );
        })}
        <button className="quiet-button reveal-all" onClick={onReveal} type="button">
          {reveal ? "Hide private fields" : "Reveal private fields"}
        </button>
      </DetailSection>
      {item.notes === null ? null : <DetailSection title="Notes"><p className="notes-block">{item.notes}</p></DetailSection>}
    </div>
  );
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="detail-section"><h3>{title}</h3>{children}</section>;
}

function ValueRow({ label, value, link = false, onCopy }: { label: string; value: string | null; link?: boolean; onCopy: (value: string, label: string) => Promise<void> }) {
  return (
    <div className="value-row">
      <span>{label}</span>
      <div>
        {link && value !== null && safeHttpUrl(value) ? <a href={value} rel="noreferrer" target="_blank">{value}</a> : <strong>{value ?? "—"}</strong>}
        {value === null ? null : <button onClick={() => void onCopy(value, label)} type="button">Copy</button>}
      </div>
    </div>
  );
}

function SecretRow({ label, value, revealed, onReveal, onCopy }: { label: string; value: string | null; revealed: boolean; onReveal: () => void; onCopy: (value: string, label: string) => Promise<void> }) {
  return (
    <div className="value-row">
      <span>{label}</span>
      <div>
        <strong className="secret-value">{value === null ? "—" : revealed ? value : "••••••••••••"}</strong>
        {value === null ? null : <button onClick={onReveal} type="button">{revealed ? "Hide" : "Reveal"}</button>}
        {value === null ? null : <button onClick={() => void onCopy(value, label)} type="button">Copy</button>}
      </div>
    </div>
  );
}

function printable(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

function privateMask(value: string): string {
  return value === "" ? "—" : "••••••••••••";
}

function humanize(value: string): string {
  const spaced = value.replaceAll(/([a-z])([A-Z])/gu, "$1 $2");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function glyphFor(kind: string): string {
  return ({ login: "↗", secureNote: "≡", card: "◇", identity: "◎", sshKey: "⌁" } as Record<string, string>)[kind] ?? "□";
}

export function labelFor(kind: string): string {
  return ({ login: "Login", secureNote: "Secure note", card: "Payment card", identity: "Identity", sshKey: "SSH key" } as Record<string, string>)[kind] ?? "Vault item";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(value));
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = -1;
  do { size /= 1024; unit += 1; } while (size >= 1024 && unit < units.length - 1);
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unit]}`;
}

function safeHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

function isEditableKind(kind: string): boolean {
  return ["login", "secureNote", "card", "identity", "sshKey"].includes(kind);
}
