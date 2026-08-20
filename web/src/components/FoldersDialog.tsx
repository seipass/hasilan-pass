import { useState, type FormEvent } from "react";

import type { FolderSummary } from "../types";
import { Dialog } from "./Dialog";

interface FoldersDialogProps {
  folders: FolderSummary[];
  busy: boolean;
  onClose: () => void;
  onCreate: (name: string) => Promise<void>;
  onRename: (id: string, name: string) => Promise<void>;
  onDelete: (folder: FolderSummary) => Promise<void>;
}

export function FoldersDialog({ folders, busy, onClose, onCreate, onRename, onDelete }: FoldersDialogProps) {
  const [editing, setEditing] = useState<FolderSummary | null>(null);

  async function submitCreate(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const name = requiredName(new FormData(form));
    await onCreate(name);
    form.reset();
  }

  async function submitRename(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (editing === null) return;
    await onRename(editing.id, requiredName(new FormData(event.currentTarget)));
    setEditing(null);
  }

  return (
    <Dialog
      description="Folder names are encrypted like vault items. Personal folders do not replace organization collections."
      onClose={onClose}
      title="Folders"
    >
      <form className="folder-create" onSubmit={(event) => void submitCreate(event)}>
        <label>New folder name<input autoFocus maxLength={1000} name="name" required /></label>
        <button className="primary-button" disabled={busy} type="submit">Create encrypted folder</button>
      </form>
      <section className="folder-list" aria-label="Personal folders">
        {folders.length === 0 ? <p className="muted">No personal folders yet.</p> : null}
        {folders.map((folder) => editing?.id === folder.id ? (
          <form className="folder-row editing" key={folder.id} onSubmit={(event) => void submitRename(event)}>
            <input defaultValue={folder.name} maxLength={1000} name="name" required />
            <button disabled={busy} type="submit">Save</button>
            <button disabled={busy} onClick={() => setEditing(null)} type="button">Cancel</button>
          </form>
        ) : (
          <div className="folder-row" key={folder.id}>
            <span aria-hidden="true">▱</span><strong>{folder.name}</strong>
            <button disabled={busy} onClick={() => setEditing(folder)} type="button">Rename</button>
            <button className="danger-text" disabled={busy} onClick={() => void onDelete(folder)} type="button">Delete</button>
          </div>
        ))}
      </section>
    </Dialog>
  );
}

function requiredName(data: FormData): string {
  const value = data.get("name");
  if (typeof value !== "string" || value.trim() === "") throw new Error("Folder name is required.");
  return value.trim();
}
