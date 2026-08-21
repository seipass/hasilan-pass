import { useEffect, useState, type FormEvent, type MouseEvent } from "react";

import { messageFromError } from "../security";

interface AuthScreenProps {
  busy: boolean;
  error: string | null;
  locked?: boolean;
  initialEmail?: string | null;
  onLogin: (email: string, password: string, secondFactor: string | null, rememberDevice: boolean, rememberUnlock: boolean) => Promise<void>;
  onUnlock?: (email: string, password: string, rememberUnlock: boolean) => Promise<void>;
  onLogout?: () => void;
  onPasskeyLogin: (email: string, password: string, rememberDevice: boolean, rememberUnlock: boolean) => Promise<void>;
  onRegister: (email: string, password: string) => Promise<void>;
  onWebauthnMfaLogin: (email: string, password: string, rememberDevice: boolean, rememberUnlock: boolean) => Promise<void>;
}

type AuthMode = "login" | "register";

export function AuthScreen({
  busy,
  error,
  locked = false,
  initialEmail = null,
  onLogin,
  onUnlock,
  onLogout,
  onPasskeyLogin,
  onRegister,
  onWebauthnMfaLogin,
}: AuthScreenProps) {
  const [mode, setMode] = useState<AuthMode>("login");
  const [validationError, setValidationError] = useState<string | null>(null);
  const displayedError = validationError ?? error;

  useEffect(() => {
    if (locked) setMode("login");
  }, [locked]);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const email = text(data, "email").trim();
    let password = text(data, "password");
    setValidationError(null);
    try {
      if (mode === "register") {
        if (password.length < 12) throw new Error("Use at least 12 characters for the master password.");
        if (password !== text(data, "confirmation")) throw new Error("The master passwords do not match.");
        const operation = onRegister(email, password);
        password = "";
        await operation;
      } else {
        const rememberUnlock = data.get("rememberUnlock") === "on";
        const operation = locked && onUnlock !== undefined
          ? onUnlock(email, password, rememberUnlock)
          : onLogin(
              email,
              password,
              text(data, "factor").trim() === "" ? null : text(data, "factor").trim(),
              data.get("rememberDevice") === "on",
              rememberUnlock,
            );
        password = "";
        await operation;
      }
    } catch (caught) {
      setValidationError(messageFromError(caught));
    } finally {
      const passwordInput = form.elements.namedItem("password");
      const confirmationInput = form.elements.namedItem("confirmation");
      if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
      if (confirmationInput instanceof HTMLInputElement) confirmationInput.value = "";
    }
  }

  async function submitWebauthn(
    event: MouseEvent<HTMLButtonElement>,
    kind: "mfa" | "passkey",
  ): Promise<void> {
    const form = event.currentTarget.form;
    if (form === null || !form.reportValidity()) return;
    const data = new FormData(form);
    const email = text(data, "email").trim();
    let password = text(data, "password");
    setValidationError(null);
    try {
      const remember = data.get("rememberDevice") === "on";
      const rememberUnlock = data.get("rememberUnlock") === "on";
      const operation = kind === "passkey"
        ? onPasskeyLogin(email, password, remember, rememberUnlock)
        : onWebauthnMfaLogin(email, password, remember, rememberUnlock);
      password = "";
      await operation;
    } catch (caught) {
      setValidationError(messageFromError(caught));
    } finally {
      const passwordInput = form.elements.namedItem("password");
      if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-story" aria-label="Product introduction">
        <div className="brand-lock" aria-hidden="true">
          <img alt="" src="/icons/hasilan-pass-icon.svg" />
        </div>
        <p className="eyebrow">Self-hosted · Zero knowledge</p>
        <h1>Your vault.<br />Your keys.<br />Your server.</h1>
        <p className="auth-lede">
          Encryption happens in this browser. The server synchronizes authenticated ciphertext and never receives your master password or unwrapped vault key.
        </p>
        <ul className="trust-list">
          <li><span>01</span>Argon2id account protection</li>
          <li><span>02</span>Per-item authenticated encryption</li>
          <li><span>03</span>Bitwarden JSON portability</li>
        </ul>
      </section>

      <section className="auth-panel">
        <div className="auth-card">
          <div className="auth-tabs" role="tablist" aria-label="Account action">
            <button
              hidden={locked}
              aria-selected={mode === "login"}
              className={mode === "login" ? "active" : ""}
              onClick={() => { setMode("login"); setValidationError(null); }}
              role="tab"
              type="button"
            >
              Unlock
            </button>
            <button
              aria-selected={mode === "register"}
              className={mode === "register" ? "active" : ""}
              onClick={() => { setMode("register"); setValidationError(null); }}
              role="tab"
              type="button"
            >
              Create vault
            </button>
          </div>

          <div className="auth-heading">
            <p className="eyebrow">Web Vault</p>
            <h2>{mode === "login" ? "Welcome back" : "Start with a private vault"}</h2>
            <p>
              {mode === "login"
                ? "Derive your key locally and synchronize encrypted records."
                : "There is no password reset backdoor. Keep your master password safe."}
            </p>
          </div>

          <form onSubmit={(event) => void submit(event)}>
            <label>
              Email address
              <input autoComplete="username" defaultValue={initialEmail ?? ""} name="email" required type="email" />
            </label>
            <label>
              Master password
              <input
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                minLength={mode === "register" ? 12 : undefined}
                name="password"
                required
                type="password"
              />
            </label>
            {mode === "register" ? (
              <label>
                Confirm master password
                <input autoComplete="new-password" minLength={12} name="confirmation" required type="password" />
              </label>
            ) : locked ? null : (
              <label>
                Authenticator or recovery code <span className="label-note">if enabled</span>
                <input autoComplete="one-time-code" name="factor" />
              </label>
            )}
            {mode === "login" && !locked ? (
              <label className="checkbox-row">
                <input name="rememberDevice" type="checkbox" />
                Trust this browser for 30 days after full verification
              </label>
            ) : null}
            {mode === "login" ? (
              <label className="checkbox-row">
                <input name="rememberUnlock" type="checkbox" />
                <span>
                  Remember unlock on this device (encrypted, optional)
                  <small className="remember-warning">Anyone who can use this device may unlock the vault; memory-only mode is stronger.</small>
                </span>
              </label>
            ) : null}
            {displayedError === null ? null : <p className="form-error" role="alert">{displayedError}</p>}
            <button className="primary-button full-button" disabled={busy} type="submit">
              {busy ? "Deriving keys…" : mode === "login" ? "Unlock vault" : "Create encrypted vault"}
            </button>
            {mode === "login" && !locked ? (
              <div className="auth-alternatives">
                <button disabled={busy} onClick={(event) => void submitWebauthn(event, "passkey")} type="button">
                  Sign in with passkey
                </button>
                <button disabled={busy} onClick={(event) => void submitWebauthn(event, "mfa")} type="button">
                  Use security key as 2FA
                </button>
              </div>
            ) : null}
          </form>

          <p className="auth-footnote">
            {locked
              ? `The session for ${initialEmail ?? "this account"} is still active. Unlocking clears the device lock without signing out.`
              : "Master-password derivation runs inside the shared Rust WebAssembly core. Passkey sign-in authenticates the account; the master password remains local and unlocks its encrypted key."}
          </p>
          {locked && onLogout !== undefined ? <button className="danger-button full-button" onClick={onLogout} type="button">Log out and revoke session</button> : null}
        </div>
      </section>
    </main>
  );
}

function text(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}
