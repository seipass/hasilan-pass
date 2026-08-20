import { useCallback, useEffect, useState } from "react";

import {
  desktop,
  type AccountSecuritySnapshot,
  type AccountTotpSetup,
  type DesktopStatus,
} from "./ipc";

interface Props {
  onError: (message: string) => void;
  onNotice: (message: string) => void;
  onStatus: (status: DesktopStatus) => void;
}

/** Android-native account MFA, passkey, session, and trusted-device controls. */
export function AndroidAccountSecurity({ onError, onNotice, onStatus }: Props) {
  const [snapshot, setSnapshot] = useState<AccountSecuritySnapshot | null>(null);
  const [setup, setSetup] = useState<AccountTotpSetup | null>(null);
  const [masterPassword, setMasterPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [passkeyName, setPasskeyName] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    setSnapshot(await desktop.accountSecurity());
  }, []);

  useEffect(() => {
    void reload().catch((error: unknown) => onError(message(error)));
  }, [onError, reload]);

  async function perform(operation: () => Promise<void>): Promise<void> {
    setBusy(true);
    try {
      await operation();
    } catch (error) {
      onError(message(error));
    } finally {
      setBusy(false);
    }
  }

  function requireMasterPassword(): string | null {
    if (masterPassword === "") {
      onError("Enter the master password for this account-security change.");
      return null;
    }
    return masterPassword;
  }

  return (
    <section className="settings-card account-security-card">
      <h2>Account security</h2>
      <p className="muted">Manage server-backed second factors, passkeys, sessions, and trusted devices from this Android client.</p>
      {snapshot === null ? <p className="muted">Loading account security…</p> : <>
        <label className="account-security-password">
          Master password for the next account-security change
          <input
            autoComplete="current-password"
            onChange={(event) => setMasterPassword(event.currentTarget.value)}
            type="password"
            value={masterPassword}
          />
        </label>

        <section className="account-security-section">
          <div className="security-card-heading"><div><span>Authenticator app</span><h3>TOTP two-step login</h3></div><span className={snapshot.mfa.totpEnabled ? "status-dot online" : "status-dot"} /></div>
          {setup === null ? <button disabled={busy} onClick={() => void perform(async () => {
            const password = requireMasterPassword();
            if (password === null) return;
            setSetup(await desktop.startAccountTotpSetup(password));
            setMasterPassword("");
            setRecoveryCodes([]);
          })} type="button">{snapshot.mfa.totpEnabled ? "Replace authenticator" : "Set up authenticator"}</button> : <div className="account-totp-setup">
            <p>Save this seed in an authenticator app, then enter its current six-digit code.</p>
            <code>{setup.secret}</code>
            <div className="button-row"><button onClick={() => void desktop.copySecret(setup.otpauthUri).then(() => onNotice("TOTP setup URI copied."), (error: unknown) => onError(message(error)))} type="button">Copy setup URI</button></div>
            <label>Authenticator code<input autoComplete="one-time-code" inputMode="numeric" onChange={(event) => setTotpCode(event.currentTarget.value)} value={totpCode} /></label>
            <button className="primary" disabled={busy || totpCode.trim() === ""} onClick={() => void perform(async () => {
              const result = await desktop.finishAccountTotpSetup(setup.setupId, totpCode.trim());
              setSetup(null);
              setTotpCode("");
              setRecoveryCodes(result.recoveryCodes);
              await reload();
              onNotice("Authenticator app enabled.");
            })} type="button">Verify and enable</button>
          </div>}
          {snapshot.mfa.totpEnabled ? <button className="danger" disabled={busy} onClick={() => void perform(async () => {
            const password = requireMasterPassword();
            if (password === null) return;
            await desktop.disableAccountTotp(password);
            setMasterPassword("");
            setSetup(null);
            await reload();
            onNotice("Authenticator app disabled.");
          })} type="button">Disable TOTP</button> : null}
        </section>

        <section className="account-security-section">
          <div className="security-card-heading"><div><span>Credential Manager</span><h3>Account passkeys</h3></div><span>{snapshot.mfa.webauthnCredentials.length}</span></div>
          <p className="muted">Uses Android Credential Manager and this APK’s signing-certificate-bound WebAuthn origin.</p>
          {snapshot.mfa.webauthnCredentials.map((credential) => <article className="account-security-row" key={credential.id}><div><strong>{credential.name}</strong><small>Last used {credential.lastUsedAt === null ? "never" : formatDate(credential.lastUsedAt)}</small></div><button className="danger" disabled={busy} onClick={() => void perform(async () => {
            await desktop.removeAccountPasskey(credential.id);
            await reload();
            onNotice("Account passkey removed.");
          })} type="button">Remove</button></article>)}
          <label>Passkey name<input maxLength={128} onChange={(event) => setPasskeyName(event.currentTarget.value)} placeholder="This Android device" value={passkeyName} /></label>
          <button disabled={busy || passkeyName.trim() === ""} onClick={() => void perform(async () => {
            const password = requireMasterPassword();
            if (password === null) return;
            const result = await desktop.registerAccountPasskey(password, passkeyName.trim());
            setMasterPassword("");
            setPasskeyName("");
            if (result.recoveryCodes.length > 0) setRecoveryCodes(result.recoveryCodes);
            await reload();
            onNotice("Account passkey registered.");
          })} type="button">Register account passkey</button>
        </section>

        <section className="account-security-section">
          <div className="security-card-heading"><div><span>Emergency access</span><h3>Recovery codes</h3></div><span>{snapshot.mfa.recoveryCodesRemaining} left</span></div>
          <button disabled={busy || (!snapshot.mfa.totpEnabled && snapshot.mfa.webauthnCredentials.length === 0)} onClick={() => void perform(async () => {
            const password = requireMasterPassword();
            if (password === null) return;
            const result = await desktop.rotateAccountRecoveryCodes(password);
            setMasterPassword("");
            setRecoveryCodes(result.codes);
            await reload();
            onNotice("Recovery codes replaced.");
          })} type="button">Rotate recovery codes</button>
        </section>

        {recoveryCodes.length === 0 ? null : <section className="recovery-panel"><div><h3>Save these recovery codes now</h3><p>They are shown once and each code works once.</p></div><div className="recovery-grid">{recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div><button onClick={() => void desktop.copySecret(recoveryCodes.join("\n")).then(() => onNotice("Recovery codes copied."), (error: unknown) => onError(message(error)))} type="button">Copy all codes</button></section>}

        <section className="account-security-section">
          <h3>Sessions</h3>
          {snapshot.sessions.map((session) => <article className="account-security-row" key={session.id}><div><strong>{session.current ? "This session" : `Session ${session.id.slice(0, 8)}`}</strong><small>Last active {formatDate(session.lastSeenAt)}</small></div>{session.revokedAt === null ? <button className="danger" disabled={busy} onClick={() => void perform(async () => {
            const next = await desktop.revokeAccountSession(session.id);
            onStatus(next);
            if (!next.unlocked) return;
            await reload();
            onNotice("Session revoked.");
          })} type="button">Revoke</button> : <small>Revoked</small>}</article>)}
        </section>

        <section className="account-security-section">
          <h3>Devices</h3>
          {snapshot.devices.map((device) => <article className="account-security-row" key={device.id}><div><strong>{device.name}</strong><small>{device.deviceType} · Last active {formatDate(device.lastSeenAt)} · {device.trusted ? "trusted" : "standard"}</small></div>{device.trusted ? <button className="danger" disabled={busy} onClick={() => void perform(async () => {
            await desktop.revokeAccountDeviceTrust(device.id);
            await reload();
            onNotice("Trusted-device access revoked.");
          })} type="button">Forget</button> : null}</article>)}
        </section>
      </>}
    </section>
  );
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "unknown" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function message(error: unknown): string {
  return typeof error === "string" && error.trim() !== ""
    ? error
    : error instanceof Error && error.message.trim() !== ""
      ? error.message
      : "The account-security operation failed.";
}
