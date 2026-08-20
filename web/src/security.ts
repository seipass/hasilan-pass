const SECRET_CLIPBOARD_LIFETIME_MS = 30_000;
const MAX_IMPORT_BYTES = 50 * 1024 * 1024;

export async function copySecret(value: string): Promise<void> {
  if (!window.isSecureContext || navigator.clipboard === undefined) {
    throw new Error("Clipboard access requires a secure browser context.");
  }
  await navigator.clipboard.writeText(value);
  window.setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => undefined);
  }, SECRET_CLIPBOARD_LIFETIME_MS);
}

export async function readImportFile(file: File): Promise<string> {
  if (file.size > MAX_IMPORT_BYTES) {
    throw new Error("Import files are limited to 50 MiB.");
  }
  return file.text();
}

export function downloadPlaintext(filename: string, content: string): void {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function messageFromError(error: unknown): string {
  if (error instanceof Error && error.message.trim() !== "") {
    return error.message;
  }
  return "The operation could not be completed.";
}

export function deviceIdentifier(): string {
  const key = "hasilan-pass-device-identifier";
  try {
    const existing = localStorage.getItem(key);
    if (existing !== null && /^[0-9a-f-]{36}$/iu.test(existing)) {
      return existing;
    }
    const created = crypto.randomUUID();
    localStorage.setItem(key, created);
    return created;
  } catch {
    return crypto.randomUUID();
  }
}

