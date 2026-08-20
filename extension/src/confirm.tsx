import { StrictMode, useEffect, useMemo, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import browser from "webextension-polyfill";

import { MESSAGE_CHANNEL, type ExtensionResponse } from "./messages";
import type { PasskeyPrompt } from "./types";
import "./confirm.css";

function PasskeyConfirmation() {
  const requestId = decodeURIComponent(location.hash.slice(1));
  const [prompt, setPrompt] = useState<PasskeyPrompt | null | undefined>(undefined);
  const [selection, setSelection] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (requestId === "") {
      setPrompt(null);
      return;
    }
    void send<PasskeyPrompt | null>({ type: "GET_PASSKEY_PROMPT", requestId })
      .then((value) => {
        setPrompt(value);
        if (value?.kind === "get" && value.candidates[0] !== undefined) {
          setSelection(candidateValue(value.candidates[0].itemId, value.candidates[0].credentialId));
        }
      })
      .catch(() => setPrompt(null));
  }, [requestId]);

  const selectedCandidate = useMemo(() => {
    if (prompt?.kind !== "get") return null;
    return prompt.candidates.find((candidate) => (
      candidateValue(candidate.itemId, candidate.credentialId) === selection
    )) ?? null;
  }, [prompt, selection]);

  async function approve(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (prompt === null || prompt === undefined) return;
    let secret = password;
    setPassword("");
    setBusy(true);
    setError(null);
    try {
      await send({
        type: "RESPOND_PASSKEY_PROMPT",
        requestId,
        decision: "approve",
        itemId: prompt.kind === "create" ? selection || null : selectedCandidate?.itemId ?? null,
        credentialId: selectedCandidate?.credentialId ?? null,
        masterPassword: secret,
      });
      secret = "";
      window.close();
    } catch (caught) {
      secret = "";
      setError(errorMessage(caught));
      setBusy(false);
    }
  }

  async function decide(decision: "cancel" | "fallback"): Promise<void> {
    setBusy(true);
    await send({
      type: "RESPOND_PASSKEY_PROMPT",
      requestId,
      decision,
      itemId: null,
      credentialId: null,
      masterPassword: "",
    }).catch(() => undefined);
    window.close();
  }

  if (prompt === undefined) {
    return <main className="confirmation loading"><img alt="" className="logo" src="/icons/icon.svg" /><p>Loading passkey request…</p></main>;
  }
  if (prompt === null) {
    return <main className="confirmation expired"><img alt="" className="logo" src="/icons/icon.svg" /><h1>Request expired</h1><p>The website no longer has an active Hasilan Pass request.</p><button onClick={() => window.close()} type="button">Close</button></main>;
  }

  return (
    <main className="confirmation">
      <header><img alt="" className="logo" src="/icons/icon.svg" /><div><strong>Hasilan Pass</strong><small>Extension-owned confirmation</small></div></header>
      <section className="request-heading">
        <span className="passkey-glyph">◇</span>
        <p>{prompt.kind === "create" ? "Create a passkey" : "Use a passkey"}</p>
        <h1>{prompt.rpName}</h1>
        <code>{prompt.origin}</code>
      </section>
      <form onSubmit={(event) => void approve(event)}>
        {prompt.kind === "create" ? (
          <>
            <div className="identity"><span>Account</span><strong>{prompt.userDisplayName ?? prompt.userName}</strong><small>{prompt.userName}</small></div>
            <label>Save in
              <select onChange={(event) => setSelection(event.currentTarget.value)} value={selection}>
                <option value="">New login item</option>
                {prompt.targets.map((target) => <option key={target.itemId} value={target.itemId}>{target.name}{target.username === null ? "" : ` · ${target.username}`}</option>)}
              </select>
            </label>
          </>
        ) : (
          <label>Passkey
            <select onChange={(event) => setSelection(event.currentTarget.value)} required value={selection}>
              {prompt.candidates.map((candidate) => (
                <option key={candidateValue(candidate.itemId, candidate.credentialId)} value={candidateValue(candidate.itemId, candidate.credentialId)}>
                  {candidate.itemName} · {candidate.userDisplayName ?? candidate.userName ?? "Unnamed account"}
                </option>
              ))}
            </select>
          </label>
        )}
        <label>Master password
          <input
            autoComplete="current-password"
            autoFocus
            onChange={(event) => setPassword(event.currentTarget.value)}
            required
            type="password"
            value={password}
          />
          <small>Re-verifies you locally and sets WebAuthn user verification.</small>
        </label>
        {error === null ? null : <p className="error" role="alert">{error}</p>}
        <button className="approve" disabled={busy || password === "" || (prompt.kind === "get" && selectedCandidate === null)} type="submit">
          {busy ? "Verifying…" : prompt.kind === "create" ? "Verify and create" : "Verify and continue"}
        </button>
      </form>
      <footer>
        <button disabled={busy} onClick={() => void decide("fallback")} type="button">Use browser instead</button>
        <button disabled={busy} onClick={() => void decide("cancel")} type="button">Cancel</button>
      </footer>
      <p className="boundary">The website receives only this RP-scoped WebAuthn response. It cannot read your vault or master password.</p>
    </main>
  );
}

function candidateValue(itemId: string, credentialId: string): string {
  return `${itemId}:${credentialId}`;
}

async function send<T = unknown>(body: Record<string, unknown>): Promise<T> {
  const response = await browser.runtime.sendMessage({ channel: MESSAGE_CHANNEL, ...body }) as ExtensionResponse<T>;
  if (!response.ok) throw new Error(response.error);
  return response.data;
}

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message !== "" ? error.message : "The confirmation could not be completed.";
}

const root = document.getElementById("root");
if (root !== null) createRoot(root).render(<StrictMode><PasskeyConfirmation /></StrictMode>);
