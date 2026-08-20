# Hasilan Pass architecture

Status: implemented baseline, 2026-08-13

## Product boundary

Hasilan Pass is a self-hosted, server-synchronized password manager. The server is an
untrusted encrypted-object store and authentication authority. Web Vault, browser
extension, and desktop are independent clients: each logs in directly, derives or
recovers the user's vault key locally, downloads ciphertext, and performs all vault
decryption and search locally. The browser extension never requires a desktop process.

The implemented vertical slice covers private Login items and folders, TOTP, encrypted
attachments, organizations/collections, per-member key sharing, account MFA/passkeys,
session control, browser autofill/capture, and cross-client synchronization. Imported
additional item types use the same encrypted-object protocol; their dedicated editors
remain a visible compatibility limit rather than client-specific cryptography.

## Repository layout

```text
crates/
  core/                 shared identifiers, time and error conventions
  crypto/               KDF, key hierarchy, EncString and item envelopes
  vault/                decrypted vault domain model, search, TOTP and generators
  protocol/             versioned HTTP request/response DTOs
  client/               API client and authenticated session abstraction
  sync/                 local outbox, cursor and deterministic conflict handling
  bitwarden-compat/     Bitwarden import/export models and converters
server/                 Axum application and SQLx persistence
web/                    Web Vault TypeScript UI consuming the Rust WASM package
extension/              Manifest V3 extension consuming the same Rust WASM package
desktop/                Tauri shell calling the shared Rust crates directly
migrations/             PostgreSQL migrations
docs/                   design, security and compatibility documents
tests/                   cross-component and E2E tests
docker/                  production-oriented container/reverse-proxy assets
```

Rust owns cryptography, vault serialization, URI matching, TOTP, password generation,
import/export, and synchronization rules. TypeScript owns DOM and browser integration.
The Web Vault and extension call the Rust implementation through WASM; they do not carry
a second cryptographic implementation.

## Trust boundaries and data flow

```text
master password
  -> local KDF -> master key -> unwrap user key
                                   |
Web / Extension / Desktop          +-> unwrap per-item key -> decrypt item -> local search
  |                                +-> unwrap attachment key -> stream decrypt attachment
  +---------- TLS /api/v1 ------------------------------+
                                                        |
                                             Axum + PostgreSQL
                                      auth verifier, wrapped keys,
                                      opaque ciphertext, revisions
```

The server may know account email, devices, sessions, object identifiers, ownership,
collection membership, ciphertext sizes, timestamps, revisions, IP/user-agent security
events, and access-control metadata. It must not receive master passwords, master keys,
user/organization keys, per-item keys in plaintext, decrypted item fields, TOTP seeds, or
passkey private material.

Browser content scripts are a second hostile boundary. A content script may request
matches for the active frame's origin, but never receives a whole decrypted vault. The
background worker validates `sender.tab`, frame URL, top-frame URL, and a one-use request
identifier, then returns only a user-selected credential. Page-context messages use a
fixed schema and an unpredictable per-frame channel token.

## Server responsibilities

- `/api/v1/auth/*`: prelogin KDF parameters, registration, login, refresh rotation,
  logout, session/device listing and revocation, TOTP/WebAuthn challenges, recovery codes.
- `/api/v1/sync`: a cursor-based encrypted-object change feed.
- `/api/v1/vault/objects`: optimistic-concurrency CRUD for opaque encrypted envelopes.
- `/api/v1/attachments`: metadata plus chunked ciphertext upload/download.
- `/api/v1/organizations` and `/collections`: membership and authorization metadata plus
  member-specific wrapped organization keys.
- `/health/live`, `/health/ready`, and generated OpenAPI.

Every mutation is transactional and advances a per-account monotonic revision. Object
writes require the last observed object revision and an idempotency key. SQLx uses bound
parameters. The server validates envelope syntax and bounded sizes but never attempts to
decrypt vault content.

Authentication uses short-lived bearer access tokens and rotating, opaque refresh
tokens. Only token hashes are stored; reuse of an already-rotated refresh token revokes
its session. Web Vault keeps the access token and a double-submit CSRF value in memory,
while its refresh token is sent only in a Path-scoped, HttpOnly, SameSite=Strict cookie
(`Secure` in production). Web login/cookie refresh/logout require an explicit transport
header and an exact configured `Origin`; refresh/logout additionally require the CSRF
header to match the independent cookie in constant time. Credentialed CORS is restricted
to exact configured origins. The extension keeps both tokens only in background memory
and never requests cookie transport. Desktop stores the refresh token in the OS
credential service and keeps the access token in memory. All other API mutations require
the explicit bearer header, so a cross-site form cannot authorize them. XSS or a
compromised extension/client remains a full client compromise.

## Client responsibilities

All clients implement the same state machine:

1. Fetch prelogin data without revealing a password.
2. Derive the master key and server authentication proof locally.
3. Authenticate, download the wrapped user key, and unwrap it locally.
4. Download encrypted changes and apply them to an encrypted local cache where the
   platform supports offline use.
5. Decrypt into memory only while unlocked; build an in-memory search index.
6. Encrypt mutations locally, enqueue them with their base revision, and synchronize.
7. Zeroize Rust-owned secret buffers and discard UI projections when locking.

Web storage is not treated as a safe place for plaintext or keys. Extension and desktop
persist only encrypted cache records. Desktop may wrap a device-local unlock secret with
the OS keychain. Biometric extension-to-desktop integration remains optional and is not
on the critical path.

## Vault object envelope

The internal server protocol is not the Bitwarden server protocol. A versioned object
contains public routing metadata and opaque, authenticated ciphertext:

```json
{
  "id": "uuid",
  "kind": "cipher",
  "owner": { "type": "user", "id": "uuid" },
  "collectionIds": [],
  "format": "hp.v1",
  "wrappedKey": "2.<iv>|<ciphertext>|<mac>",
  "payload": "2.<iv>|<ciphertext>|<mac>",
  "revision": 42,
  "deletedAt": null
}
```

`payload` is the canonical JSON serialization of the complete private vault item and is
encrypted under a random 64-byte item key. `wrappedKey` encrypts that item key under the
user or organization key. Encrypting the complete object avoids unauthenticated mixing
of independently encrypted fields. Public routing metadata is duplicated inside the
encrypted payload where meaningful and clients reject inconsistent data.

## Deployment

PostgreSQL is the only mandatory external service. The default Compose stack contains
the server, PostgreSQL, the built Web Vault, and a Caddy TLS/reverse-proxy example with
persistent volumes and health checks. Invitation delivery is an injected adapter: manual
mode shows a token once to an authorized administrator, while SMTP mode submits a
plain-text invitation over certificate-validated implicit TLS or mandatory STARTTLS and
withholds the bearer token from the API response. Delivery runs before the membership
transaction commits, so a failed relay leaves no active invitation. Tokens are never
written to request logs. No hosted cloud service is required.

Configuration is parsed into typed Rust structs and validated before a listener is
opened. Production mode refuses placeholder server secrets, non-HTTPS public/WebAuthn
origins, wildcard CORS, and malformed relying-party configuration.

## Architectural decisions

- ADR-001: clients, not the server, own vault cryptography and search.
- ADR-002: use a per-item content key and whole-object authenticated envelope.
- ADR-003: preserve Bitwarden's client-visible model and import/export format, not its
  private database schema or undocumented server API.
- ADR-004: use Rust/WASM for shared browser logic and TypeScript only at platform edges.
- ADR-005: reject silent conflict overwrites; retain both versions for explicit merge.
- ADR-006: ship extension functionality without native messaging or a desktop dependency.

See [crypto.md](crypto.md), [sync.md](sync.md),
[bitwarden-compatibility.md](bitwarden-compatibility.md), and
[threat-model.md](threat-model.md) for the corresponding detailed contracts. Native
cache, keychain, system-integration, and packaging behavior is specified in
[desktop.md](desktop.md).
