import { useRef, useState, type ChangeEvent, type FormEvent } from "react";

import { decodeTotpQrFile } from "../totp-qr";
import type { FolderSummary, LoginDraft, LoginValue, VaultItem } from "../types";
import { Dialog } from "./Dialog";

interface LoginEditorProps {
  item: VaultItem | null;
  generatedPassword: string | undefined;
  busy: boolean;
  onClose: () => void;
  destinations: LoginDestination[];
  folders: FolderSummary[];
  onSave: (
    draft: LoginDraft,
    item: VaultItem | null,
    destination: LoginDestination,
    folderId: string | null,
  ) => Promise<void>;
}

export interface LoginDestination {
  id: string;
  label: string;
  organizationId: string | null;
  collectionIds: string[];
  writable: boolean;
}

export function LoginEditor({
  item,
  generatedPassword,
  busy,
  destinations,
  folders,
  onClose,
  onSave,
}: LoginEditorProps) {
  const login = item?.data.kind === "login" ? (item.data.value as LoginValue) : null;
  const [showPassword, setShowPassword] = useState(false);
  const [qrStatus, setQrStatus] = useState<{ error: boolean; message: string } | null>(null);
  const totpInput = useRef<HTMLInputElement>(null);
  const currentDestination = destinationForItem(item, destinations);

  async function importTotpQr(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (file === undefined) return;
    setQrStatus({ error: false, message: "Reading QR image locally…" });
    try {
      const payload = await decodeTotpQrFile(file);
      if (totpInput.current === null) throw new Error("The authenticator field is unavailable.");
      totpInput.current.value = payload;
      setQrStatus({ error: false, message: "TOTP configuration imported from the QR image." });
    } catch (error) {
      setQrStatus({
        error: true,
        message: error instanceof Error ? error.message : "The QR image could not be read.",
      });
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const destinationId = requiredText(data, "destination");
    const destination = destinations.find((candidate) => candidate.id === destinationId);
    if (destination === undefined) throw new Error("The selected vault destination is unavailable.");
    await onSave(
      {
        name: requiredText(data, "name"),
        username: optionalText(data, "username"),
        password: optionalVerbatimText(data, "password"),
        uri: optionalText(data, "uri"),
        totp: optionalText(data, "totp"),
        notes: optionalVerbatimText(data, "notes"),
        favorite: data.get("favorite") === "on",
      },
      item,
      destination,
      optionalText(data, "folder"),
    );
  }

  return (
    <Dialog
      description="The complete item is encrypted in Rust before it leaves this device."
      onClose={onClose}
      title={item === null ? "New login" : "Edit login"}
      wide
    >
      <form className="editor-form" onSubmit={(event) => void submit(event)}>
        <div className="field-grid two-columns">
          <label className="span-two">
            Vault destination
            <select
              defaultValue={currentDestination?.id ?? "personal"}
              disabled={item !== null}
              name={item === null ? "destination" : undefined}
              required
            >
              {destinations.map((destination) => (
                <option
                  disabled={item === null && !destination.writable}
                  key={destination.id}
                  value={destination.id}
                >{destination.label}{destination.writable ? "" : " (read-only)"}</option>
              ))}
            </select>
            {item === null ? null : (
              <input name="destination" type="hidden" value={currentDestination?.id ?? "personal"} />
            )}
            {item === null ? null : <small>Ownership is immutable after the first encrypted upload.</small>}
          </label>
          <label className="span-two">
            Personal folder
            <select defaultValue={item?.folderId ?? ""} name="folder">
              <option value="">No folder</option>
              {folders.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}
            </select>
            <small>Organization items use collections; a folder selection is ignored for them.</small>
          </label>
          <label className="span-two">
            Name
            <input defaultValue={item?.name ?? ""} maxLength={2000} name="name" required />
          </label>
          <label>
            Username
            <input autoComplete="off" defaultValue={login?.username ?? ""} name="username" />
          </label>
          <label>
            Password
            <span className="input-action">
              <input
                autoComplete="new-password"
                defaultValue={generatedPassword ?? login?.password ?? ""}
                name="password"
                type={showPassword ? "text" : "password"}
              />
              <button onClick={() => setShowPassword((shown) => !shown)} type="button">
                {showPassword ? "Hide" : "Show"}
              </button>
            </span>
          </label>
          <label className="span-two">
            Website URL
            <input defaultValue={login?.uris[0]?.uri ?? ""} name="uri" placeholder="https://example.com/login" type="url" />
          </label>
          <div className="span-two totp-editor-field">
            <label htmlFor="login-totp">Authenticator key or otpauth URI</label>
            <input autoComplete="off" defaultValue={login?.totp ?? ""} id="login-totp" name="totp" ref={totpInput} spellCheck={false} />
            <div className="totp-qr-row">
              <label className="quiet-button totp-qr-picker">
                Import QR image
                <input accept="image/png,image/jpeg,image/webp" onChange={(event) => void importTotpQr(event)} type="file" />
              </label>
              <small className={qrStatus?.error === true ? "error" : ""} role="status">
                {qrStatus?.message ?? "The image is decoded in this browser and is never uploaded."}
              </small>
            </div>
          </div>
          <label className="span-two">
            Notes
            <textarea defaultValue={item?.notes ?? ""} name="notes" rows={5} />
          </label>
        </div>
        <label className="checkbox-row">
          <input defaultChecked={item?.favorite ?? false} name="favorite" type="checkbox" />
          Add to favorites
        </label>
        <footer className="dialog-actions">
          <button className="quiet-button" onClick={onClose} type="button">Cancel</button>
          <button className="primary-button" disabled={busy} type="submit">
            {busy ? "Encrypting…" : "Encrypt and save"}
          </button>
        </footer>
      </form>
    </Dialog>
  );
}

function destinationForItem(
  item: VaultItem | null,
  destinations: LoginDestination[],
): LoginDestination | undefined {
  if (item?.organizationId === null || item === null) {
    return destinations.find((destination) => destination.organizationId === null);
  }
  return destinations.find(
    (destination) =>
      destination.organizationId === item.organizationId
      && destination.collectionIds.length === item.collectionIds.length
      && destination.collectionIds.every((id) => item.collectionIds.includes(id)),
  );
}

function requiredText(data: FormData, name: string): string {
  const value = optionalText(data, name);
  if (value === null) throw new Error(`${name} is required.`);
  return value;
}

function optionalText(data: FormData, name: string): string | null {
  const value = data.get(name);
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

function optionalVerbatimText(data: FormData, name: string): string | null {
  const value = data.get(name);
  if (typeof value !== "string" || value.trim() === "") return null;
  return value;
}
