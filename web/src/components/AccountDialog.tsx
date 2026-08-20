import { useCallback, useEffect, useState } from "react";

import type { ApiClient } from "../api";
import { copySecret, messageFromError } from "../security";
import type {
  DeviceResponse,
  MfaStatusResponse,
  SessionResponse,
  TotpSetupStartResponse,
} from "../types";
import { createWebauthnCredential } from "../webauthn";
import { Dialog } from "./Dialog";

interface AccountDialogProps {
  api: ApiClient;
  deriveAuthProof: (masterPassword: string) => string;
  onClose: () => void;
  onCurrentRevoked: () => void;
  onNotice: (message: string) => void;
  onTrustRevoked: (deviceId: string) => void;
}

const EMPTY_SECURITY: MfaStatusResponse = {
  totpEnabled: false,
  recoveryCodesRemaining: 0,
  webauthnCredentials: [],
};

export function AccountDialog({
  api,
  deriveAuthProof,
  onClose,
  onCurrentRevoked,
  onNotice,
  onTrustRevoked,
}: AccountDialogProps) {
  const [sessions, setSessions] = useState<SessionResponse[]>([]);
  const [devices, setDevices] = useState<DeviceResponse[]>([]);
  const [security, setSecurity] = useState<MfaStatusResponse>(EMPTY_SECURITY);
  const [setup, setSetup] = useState<TotpSetupStartResponse | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [masterPassword, setMasterPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [credentialName, setCredentialName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    const [nextSessions, nextDevices, nextSecurity] = await Promise.all([
      api.listSessions(),
      api.listDevices(),
      api.accountSecurity(),
    ]);
    setSessions(nextSessions);
    setDevices(nextDevices);
    setSecurity(nextSecurity);
  }, [api]);

  useEffect(() => {
    let cancelled = false;
    void reload()
      .catch((caught: unknown) => {
        if (!cancelled) setError(messageFromError(caught));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reload]);

  function reauthenticate(): string {
    if (masterPassword === "") throw new Error("Enter your master password to change account security.");
    const proof = deriveAuthProof(masterPassword);
    setMasterPassword("");
    return proof;
  }

  async function perform(operation: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (caught) {
      setError(messageFromError(caught));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(session: SessionResponse): Promise<void> {
    await perform(async () => {
      await api.revokeSession(session.id);
      if (session.current) {
        api.clearSession();
        onCurrentRevoked();
        return;
      }
      setSessions((current) => current.map((value) => value.id === session.id
        ? { ...value, revokedAt: new Date().toISOString() }
        : value));
      onNotice("Session revoked.");
    });
  }

  async function revokeTrust(device: DeviceResponse): Promise<void> {
    await perform(async () => {
      await api.revokeDeviceTrust(device.id);
      setDevices((current) => current.map((value) => value.id === device.id
        ? { ...value, trusted: false, trustedUntil: null }
        : value));
      onTrustRevoked(device.id);
      onNotice("Device trust revoked.");
    });
  }

  async function startTotp(): Promise<void> {
    await perform(async () => {
      const next = await api.startTotpSetup(reauthenticate());
      setSetup(next);
      setTotpCode("");
      setRecoveryCodes([]);
    });
  }

  async function finishTotp(): Promise<void> {
    if (setup === null) return;
    await perform(async () => {
      const result = await api.finishTotpSetup(setup.setupId, totpCode.trim());
      setSetup(null);
      setTotpCode("");
      setRecoveryCodes(result.recoveryCodes);
      await reload();
      onNotice("Authenticator-app verification enabled.");
    });
  }

  async function disableTotp(): Promise<void> {
    await perform(async () => {
      await api.disableTotp(reauthenticate());
      setSetup(null);
      setRecoveryCodes([]);
      await reload();
      onNotice("Authenticator-app verification disabled.");
    });
  }

  async function rotateRecoveryCodes(): Promise<void> {
    await perform(async () => {
      const result = await api.rotateRecoveryCodes(reauthenticate());
      setRecoveryCodes(result.codes);
      await reload();
    });
  }

  async function registerPasskey(): Promise<void> {
    await perform(async () => {
      const name = credentialName.trim();
      if (name === "") throw new Error("Give the passkey or security key a recognizable name.");
      const challenge = await api.startWebauthnRegistration(reauthenticate(), name);
      const credential = await createWebauthnCredential(challenge.options);
      const result = await api.finishWebauthnRegistration(challenge.ceremonyId, credential);
      setCredentialName("");
      if (result.recoveryCodes.length > 0) setRecoveryCodes(result.recoveryCodes);
      await reload();
      onNotice("Passkey registered.");
    });
  }

  async function removePasskey(id: string): Promise<void> {
    await perform(async () => {
      await api.deleteWebauthnCredential(id);
      await reload();
      onNotice("Passkey removed.");
    });
  }

  return (
    <Dialog
      description="Configure phishing-resistant account authentication, recovery, remembered browsers, and revocable sessions. Vault-item TOTP secrets remain separate and end-to-end encrypted."
      onClose={onClose}
      title="Account security"
      wide
    >
      {loading ? <p className="loading-line">Loading account security…</p> : null}
      {error === null ? null : <p className="form-error" role="alert">{error}</p>}

      <section className="security-reauth">
        <label>
          Master password for the next security change
          <input
            autoComplete="current-password"
            onChange={(event) => setMasterPassword(event.currentTarget.value)}
            type="password"
            value={masterPassword}
          />
        </label>
        <p>It is derived locally into an authorization proof and is never sent to the server.</p>
      </section>

      <div className="security-grid">
        <section className="security-card">
          <div className="security-card-heading">
            <div><span>Authenticator app</span><h3>TOTP two-step login</h3></div>
            <span className={security.totpEnabled ? "status active" : "status neutral"}>
              {security.totpEnabled ? "Enabled" : "Off"}
            </span>
          </div>
          {setup === null ? (
            <button className="quiet-button" disabled={busy} onClick={() => void startTotp()} type="button">
              {security.totpEnabled ? "Replace authenticator" : "Set up authenticator"}
            </button>
          ) : (
            <div className="totp-setup">
              <p>Enter this seed or URI in your authenticator, then confirm its current six-digit code.</p>
              <code>{setup.secret}</code>
              <button className="text-button" onClick={() => void copySecret(setup.otpauthUri).then(() => onNotice("Setup URI copied for 30 seconds."), (caught: unknown) => setError(messageFromError(caught)))} type="button">
                Copy setup URI
              </button>
              <input
                aria-label="Authenticator verification code"
                autoComplete="one-time-code"
                inputMode="numeric"
                onChange={(event) => setTotpCode(event.currentTarget.value)}
                placeholder="123456"
                value={totpCode}
              />
              <button className="primary-button" disabled={busy || totpCode.trim() === ""} onClick={() => void finishTotp()} type="button">Verify and enable</button>
            </div>
          )}
          {security.totpEnabled ? <button className="danger-button compact" disabled={busy} onClick={() => void disableTotp()} type="button">Disable TOTP</button> : null}
        </section>

        <section className="security-card">
          <div className="security-card-heading">
            <div><span>FIDO2 / WebAuthn</span><h3>Passkeys and security keys</h3></div>
            <span className={security.webauthnCredentials.length > 0 ? "status active" : "status neutral"}>{security.webauthnCredentials.length}</span>
          </div>
          <div className="credential-list">
            {security.webauthnCredentials.map((credential) => (
              <article key={credential.id}>
                <div><strong>{credential.name}</strong><p>Last used {credential.lastUsedAt === null ? "never" : formatDate(credential.lastUsedAt)}</p></div>
                <button className="danger-button compact" disabled={busy} onClick={() => void removePasskey(credential.id)} type="button">Remove</button>
              </article>
            ))}
          </div>
          <input aria-label="New passkey name" onChange={(event) => setCredentialName(event.currentTarget.value)} placeholder="MacBook Touch ID" value={credentialName} />
          <button className="quiet-button" disabled={busy} onClick={() => void registerPasskey()} type="button">Register passkey</button>
        </section>

        <section className="security-card">
          <div className="security-card-heading">
            <div><span>Emergency access</span><h3>Recovery codes</h3></div>
            <span className="status neutral">{security.recoveryCodesRemaining} left</span>
          </div>
          <p>Each high-entropy code works once. Rotating invalidates every previous code and all remembered-browser grants.</p>
          <button className="quiet-button" disabled={busy || (!security.totpEnabled && security.webauthnCredentials.length === 0)} onClick={() => void rotateRecoveryCodes()} type="button">Rotate recovery codes</button>
        </section>
      </div>

      {recoveryCodes.length > 0 ? (
        <section className="recovery-panel" aria-live="polite">
          <div><h3>Save these recovery codes now</h3><p>They will not be shown again.</p></div>
          <div className="recovery-grid">{recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div>
          <button className="quiet-button" onClick={() => void copySecret(recoveryCodes.join("\n")).then(() => onNotice("Recovery codes copied for 30 seconds."), (caught: unknown) => setError(messageFromError(caught)))} type="button">Copy all codes</button>
        </section>
      ) : null}

      <div className="account-columns security-account-columns">
        <section>
          <h3>Sessions</h3>
          <div className="account-list">
            {sessions.map((session) => (
              <article className="account-row" key={session.id}>
                <div>
                  <strong>{session.current ? "This session" : shortId(session.id)}</strong>
                  <p>Last active {formatDate(session.lastSeenAt)}</p>
                  <span className={session.revokedAt === null ? "status active" : "status revoked"}>{session.revokedAt === null ? "Active" : "Revoked"}</span>
                </div>
                {session.revokedAt === null ? <button className="danger-button compact" disabled={busy} onClick={() => void revoke(session)} type="button">Revoke</button> : null}
              </article>
            ))}
          </div>
        </section>
        <section>
          <h3>Devices</h3>
          <div className="account-list">
            {devices.map((device) => (
              <article className="account-row" key={device.id}>
                <div>
                  <strong>{device.name}</strong>
                  <p>{device.deviceType} · Last active {formatDate(device.lastSeenAt)}</p>
                  <span className={device.trusted ? "status active" : "status neutral"}>
                    {device.trusted && device.trustedUntil !== null ? `Trusted until ${formatDate(device.trustedUntil)}` : "Standard"}
                  </span>
                </div>
                {device.trusted ? <button className="danger-button compact" disabled={busy} onClick={() => void revokeTrust(device)} type="button">Forget</button> : null}
              </article>
            ))}
          </div>
        </section>
      </div>
    </Dialog>
  );
}

function shortId(value: string): string {
  return `Session ${value.slice(0, 8)}`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
