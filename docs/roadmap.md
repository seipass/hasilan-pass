# Delivery roadmap

Status date: 2026-08-13

The order is vertical: every milestone ends in a buildable, tested product path. A box is
only checked when the behavior, tests, and documentation exist; scaffolding alone does
not count.

## Phase 0 — researched design

- [x] Architecture and trust boundaries
- [x] Initial threat model
- [x] Cryptographic hierarchy and versioning contract
- [x] Sync/conflict contract
- [x] Bitwarden public format/current OSS implementation review
- [x] Explicit compatibility boundary
- [ ] ADRs extracted for changes to accepted decisions

## Phase 1 — encrypted server slice

- [x] Cargo workspace and shared domain/protocol crates
- [x] Argon2id and PBKDF2 master-key derivation with published/upstream vectors
- [x] type-2 `EncString`, user-key and per-item-key wrapping
- [x] Login/Secure Note/Card/Identity/SSH model, TOTP, URI matcher, and generators
- [x] Bitwarden plaintext JSON fixtures and semantic import/export/import round trips
- [x] Axum registration/login/refresh/logout and device/session revocation
- [x] PostgreSQL migrations and opaque encrypted-object CRUD/sync
- [x] OpenAPI, bounded per-account login attempts, health/readiness, and body-free request tracing
- [x] integration test proving known vault plaintext is absent from PostgreSQL and attachment storage

Exit gate: two API clients can register, unlock, create an encrypted Login+TOTP, sync it,
and revoke a session; all Rust tests/builds are green.

## Phase 2 — Web Vault

- [x] Rust/WASM package is the sole vault crypto implementation
- [x] register/login/unlock/lock and memory-only unlocked state
- [x] vault list/search/detail, Login create/edit/trash, and encrypted synchronized folders
- [x] local TOTP display/copy/QR import and password/passphrase/username generators
- [ ] encrypted Hasilan backup (plaintext Bitwarden import/export is implemented)
- [x] security/account/device/session/TOTP/WebAuthn/recovery/trusted-device settings
- [x] documented accessibility audit and complete keyboard-first navigation

Exit gate: clean browser completes register -> login -> unlock -> Login+TOTP -> sync ->
reload/unlock, with Playwright coverage and no plaintext persistence.

## Phase 3 — standalone browser extension

- [x] Chromium MV3 and Firefox build variants
- [x] direct server login/unlock/sync and encrypted offline cache
- [x] local search/create/edit/delete/generator/TOTP and encrypted attachments
- [x] login/signup/password-change detection and save/update prompts
- [x] exact/host/base-domain/starts-with/regex/never URI strategies
- [x] explicit/context/inline autofill, clipboard timeout, and auto-lock
- [x] hostile iframe and page-owned open-shadow-root regression suite with forged sender-URL checks
- [x] least-privilege optional host permissions and strict CSP

Exit gate: extension alone performs login -> sync -> detect -> select -> autofill -> save
new credential while the desktop application is absent.

## Phase 4 — desktop

- [x] Tauri app for Windows/macOS/Linux using shared Rust crates directly
- [x] login/unlock/vault/search/edit/generator/TOTP/import/export/sync
- [x] transactional encrypted offline cache and durable outbox
- [x] automatic lock, tray, clipboard timeout, OS-keychain device wrapper
- [ ] signed/packageable builds and platform smoke tests (Linux/Windows compile,
  packaging, signing, SBOM, and provenance automation exists; first signed tag and
  manual platform smoke remain; macOS is outside GitHub Actions)

Exit gate: desktop syncs the same account and works offline, with no extension dependency
in either direction.

## Phase 5 — WebAuthn and passkeys

- [x] standards-compliant account WebAuthn 2FA and single-use recovery codes
- [ ] WebAuthn PRF vault unlock (passwordless account authentication passkeys are implemented)
- [x] encrypted Bitwarden-compatible vault FIDO2 credential model
- [x] ES256 authenticator create/get with origin, RP ID, UV/UP, and counter handling
- [x] Chromium and Firefox injection/fallback adapters
- [ ] dedicated hostile-page passkey E2E suite (import/export and Rust negative fixtures exist)

Exit gate: real WebAuthn conformance flows pass; no UI-only placeholder is enabled.

## Phase 6 — organizations, attachments, hardening

- [x] organization create/invite/accept/confirm/remove and role matrix
- [x] per-member zero-knowledge organization key sharing
- [x] collection access and organization-owned items
- [x] streaming encrypted attachment upload/resume/download/delete
- [ ] CSV, KeePass XML, and 1Password import
- [ ] password-protected Bitwarden JSON and ZIP attachment export
- [ ] long-running randomized sync model tests (four parser/URI fuzz targets and CI smoke runs exist)
- [ ] SBOM/provenance and independent security review (release generation and signed
  attestations are automated; first tagged evidence and an independent review remain;
  clean-clone Compose and real backup/restore drills exist)

Exit gate: all completion scenarios in the root README work from a clean clone using the
documented Compose command, and CI exercises Rust, frontend, extension, desktop,
integration, E2E, audit, deny, and fuzz smoke gates.

## Definition of done

- Behavior is usable, not represented by static UI.
- Security-sensitive behavior has negative tests and failure UX.
- Documentation states residual risk and compatibility limits.
- No phase leaves default-branch builds broken.
- A clean environment can reproduce builds and migrations from lockfiles.
- Claims are backed by commands/tests that cover the full claim.
