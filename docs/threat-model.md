# Threat model

Status: reviewed against the implemented v1 slice, 2026-08-13

## Security goals

1. A server or database compromise alone does not reveal vault fields, TOTP seeds,
   attachment plaintext, or passkey private keys.
2. A malicious website cannot enumerate the vault or obtain a credential for another
   origin through the extension.
3. Authentication/session compromise is contained, visible, and revocable.
4. Offline and concurrent operation does not silently lose a secret version.
5. Self-hosting defaults fail closed and do not require a third-party cloud trust anchor.

Availability against a malicious server, protection after a client is fully compromised
while unlocked, and revocation of plaintext already copied by an authorized user are not
achievable cryptographic guarantees.

## Assets

- master password and derived master/stretched keys;
- user and organization keys;
- per-item and attachment keys;
- decrypted vault items, TOTP seeds/codes, and passkey private material;
- auth proofs, access/refresh tokens, recovery codes, device secrets;
- encrypted vault history and metadata;
- integrity of releases, WASM, extension bundle, and server images.

## Adversaries and controls

### Compromised server or database

Capabilities: read/modify all stored rows and blobs, observe metadata, serve stale or
malformed sync responses, attempt offline guessing of the authentication verifier, and
deny service.

Controls: client-only keys; memory-hard account KDF; server-side memory-hard hashing of
the client proof; authenticated item/wrapped-key envelopes; encrypted payload duplicates
security-sensitive routing metadata; optimistic revisions and client cursors; installed
extension/desktop clients as a separately distributed option; no plaintext server search
index or crypto telemetry.

Residual risk: email, membership, collection graph, IP/device events, access timing, item
counts and ciphertext sizes leak. A malicious server can substitute the Web Vault bundle
and steal a password from a future session. Self-hosters should pin/audit client builds;
browser extensions and installed desktop clients provide a separately distributed
client. Full protection from a malicious web-delivery server requires verifiable builds
or an installed client.

### Compromised browser page or malicious website

Capabilities: arbitrary page JavaScript, crafted forms, shadow DOM/iframes, postMessage
traffic, DOM mutation, clickjacking, and phishing lookalike origins.

Controls: isolated extension worlds; strict message schemas and sender validation;
content scripts never receive the whole vault; exact canonical origin/RP validation;
public-suffix-aware base-domain matching; HTTPS downgrade warnings; user confirmation
for passkeys and risky iframe fills; no remote code/eval/unsafe `innerHTML`; CSP; minimal
optional host permissions; secrets returned only after a background decision and user
gesture.

Residual risk: once intentionally filled, the target page can read the credential. A
compromised legitimate site is indistinguishable from that site. Visual phishing on a
lookalike registrable domain remains a user risk; the extension must show the actual
origin prominently.

### Compromised content script

Capabilities: abuse extension messaging for its injected origin and observe values sent
to it.

Controls: least-privilege request/response API, background validation of browser-provided
sender metadata rather than claimed origins, one operation at a time, no key APIs, no
arbitrary item IDs, zero vault dumps, and short-lived selected-credential responses.
Passkey signing stays in the background/WASM boundary where browser constraints permit.

Residual risk: a compromised script authorized for a legitimate origin can steal a
credential the user elects to fill there. Browser extension compromise itself is client
compromise and defeats these controls.

### Stolen device or encrypted cache

Capabilities: copy local files/storage and perform offline attacks; possibly inspect a
running unlocked process.

Controls: only encrypted vault records at rest; no persisted master/user key unless the user
explicitly enables a device envelope; automatic lock; desktop refresh/device secrets stored in
the OS credential service; Web/extension access tokens kept only in memory; extension refresh
tokens and optional user-key envelopes encrypted by a non-extractable IndexedDB key; clipboard
clearing; refresh-session revocation; and bounded KDF cost. Chromium service-worker suspension
can resume an authenticated extension session only through its encrypted refresh record, and
manual lock suppresses automatic key restore.

Residual risk: malware, debuggers, accessibility APIs, clipboard managers, swap/core
dumps, or physical access while unlocked can expose plaintext. Managed-language and
browser memory cannot be reliably zeroized; lock destroys references and reloads the
worker/page where possible. A compromised same-origin Web Vault can invoke its own WebCrypto
device key, so Web remembered unlock is not equivalent to a hardware-backed installed client.

### MITM and hostile network

Capabilities: intercept, replay, delay, reorder, and block traffic.

Controls: HTTPS-only production URL validation, HSTS at Caddy, platform certificate
validation, explicit bearer authorization, Secure/HttpOnly/SameSite=Strict Web refresh
cookies, authenticated ciphertext, nonces/challenges, access-token expiry, refresh
rotation/reuse detection, idempotency keys, revision checks, and request/body-size limits.

Residual risk: a locally installed malicious CA or compromised TLS endpoint can observe
auth proofs and tokens and alter metadata. It still cannot decrypt existing vault
ciphertext without a client secret, but may hijack a live session or serve malicious Web
Vault code.

### Brute force against vault

Capabilities: offline guessing after obtaining protected user key and account metadata.

Controls: Argon2id default, client/server parameter floors and upper bounds,
password-strength guidance, an in-process per-account online login limiter, optional
passkey/2FA, and no security questions. An IP limiter belongs at the reverse proxy; a
breached-password lookup is not currently shipped.

Residual risk: weak master passwords remain guessable offline. 2FA does not protect an
offline encrypted-vault copy. The UI must communicate this clearly.

### Malicious organization member

Capabilities: legitimately decrypt shared items/keys, retain old data, mutate accessible
items, attempt privilege escalation or malicious invitations.

Controls: server authorization on every read/write, collection-scoped access, least-
privilege roles, member-specific key wrappers, explicit confirmation before key sharing,
security events, optimistic concurrency, and key rotation after removal where warranted.

Residual risk: authorized members can copy anything they can decrypt; removal cannot
revoke prior knowledge. Organization recovery is explicit key escrow and changes the
trust model.

### Authentication and session attackers

Capabilities: credential stuffing, token theft, CSRF, fixation, refresh replay, challenge
replay, and MFA fatigue.

Controls: bounded per-account login attempts with generic login errors; server-generated
session IDs after auth; rotating hashed refresh tokens and reuse detection; short-lived
bearer access tokens; exact credentialed CORS; Web refresh cookies scoped to auth paths
with Secure/HttpOnly/SameSite=Strict attributes; exact-Origin plus constant-time
double-submit CSRF verification for Web cookie refresh/logout; WebAuthn RP
ID/origin/challenge checks; single-use recovery codes; and session/device UI and
revocation. Other mutations require an explicit bearer header. XSS remains able to act as
the in-memory session and read the in-memory CSRF value, though it cannot read the
HttpOnly refresh cookie directly.

### Server-side input attacks

Controls: SQLx bound queries; strict JSON and attachment limits; no server-side URL fetch
from vault values; attachment IDs/chunks stored without interpreting media; CORS
allowlist; security headers; body-free structured request logs; timeouts; and dependency,
license, source, frontend-sink, and secret checks. Vault-provided URLs are inert ciphertext
to the server. The only outbound adapter is explicitly configured SMTP: hostnames and
mailboxes are startup-validated, plaintext/opportunistic TLS modes do not exist, relay
timeouts are bounded, recipients come only from normalized existing accounts, and relay
errors roll back the invitation transaction. Operators still trust their SMTP relay with
recipient metadata and the short-lived invitation token.

### Supply-chain compromise

Controls: lockfiles, `cargo deny`, root and fuzz-lock `cargo audit`, production frontend
audit, commit-pinned CI actions, secret scanning, fixed Rust/Node/pnpm/WASM tool versions,
minimal container build contexts, and review of cryptographic dependency updates. The
release workflow generates an SPDX SBOM, checksum index, and OIDC/Sigstore SLSA and SBOM
attestations for exact package digests. A tag fails without Windows identity signing and
timestamping or macOS identity signing and notarization; native signatures are verified
after packaging and the resulting release remains a draft for review.

Residual risk: no protected tagged run or independent assessment has yet supplied
external evidence for this repository. GitHub-hosted builders, signing authorities, and
maintainer-controlled workflow source remain trusted. Installer/notarization timestamps
prevent a current bit-for-bit reproducibility claim. Published container digest pinning
and browser-store signing remain release work; Compose currently builds reviewed source
locally.

## Required security invariants

- Logs must never include passwords, auth proofs/tokens, any decrypted item, TOTP secret,
  passkey private key, user/item/attachment key, or plaintext import/export.
- The server has no code path accepting a decrypted vault item.
- A content script API cannot list all decrypted items or request by an arbitrary foreign
  origin.
- MAC/AEAD verification precedes plaintext parsing or use.
- Failed sync/conflict handling retains both versions.
- Production startup rejects default secrets and insecure public origins.
- Database inspection tests search all columns and attachment storage for known synthetic
  plaintext markers after the complete E2E flow.

## Security test plan

- unit and published-vector crypto tests plus mutation/negative cases;
- API authorization matrix and IDOR tests across users/organizations/collections;
- refresh-reuse, WebAuthn challenge replay, CORS/configuration, per-account rate-limit,
  trusted-device, and recovery-code tests;
- malicious-page extension tests for forged messages, nested/cross-origin frames, shadow
  DOM, HTTP downgrade, lookalike domains, and DOM replacement after fill;
- CSP/XSS tests using imported hostile strings;
- property tests/fuzzing for import, vault/protocol decoders and URI parsing;
- automated database/blob plaintext canary scan;
- backup/restore test proving ciphertext and revision integrity.

This model is reviewed whenever a new trust relationship, algorithm, browser permission,
recovery path, or server-visible metadata field is introduced.
