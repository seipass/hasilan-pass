import { useState, type ChangeEvent } from "react";

import { messageFromError, readImportFile } from "../security";
import { Dialog } from "./Dialog";

interface TransferDialogProps {
  busy: boolean;
  onClose: () => void;
  onExport: () => void;
  onImport: (content: string) => Promise<void>;
}

export function TransferDialog({ busy, onClose, onExport, onImport }: TransferDialogProps) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function importFile(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (file === undefined) return;
    try {
      const content = await readImportFile(file);
      await onImport(content);
      input.value = "";
    } catch (caught) {
      setError(messageFromError(caught));
    }
  }

  return (
    <Dialog description="Move data with the standard unencrypted Bitwarden JSON format." onClose={onClose} title="Import and export">
      <div className="warning-box">
        <strong>Plaintext leaves the encrypted vault boundary</strong>
        <p>Import files and downloaded exports contain readable passwords. Delete them securely after use and never place them in a shared or synchronized folder.</p>
      </div>
      <label className="checkbox-row transfer-acknowledgement">
        <input checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} type="checkbox" />
        I understand that these files are plaintext.
      </label>
      <div className="transfer-actions">
        <label className={`file-button${!acknowledged || busy ? " disabled" : ""}`}>
          Import Bitwarden JSON
          <input accept="application/json,.json" disabled={!acknowledged || busy} onChange={(event) => void importFile(event)} type="file" />
        </label>
        <button className="quiet-button" disabled={!acknowledged || busy} onClick={onExport} type="button">
          Export plaintext JSON
        </button>
      </div>
      {busy ? <p className="loading-line">Encrypting and uploading imported items…</p> : null}
      {error === null ? null : <p className="form-error" role="alert">{error}</p>}
    </Dialog>
  );
}

