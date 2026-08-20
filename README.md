# Hasilan Pass

Hasilan Pass is a self-hosted, zero-knowledge password manager with an Axum/PostgreSQL
server, React Web Vault, standalone Chromium/Firefox extension, and native Tauri desktop
client. Vault item bodies, TOTP seeds, passkey private keys, filenames, and attachment
contents are encrypted on the client before synchronization. The server stores routing
metadata and opaque authenticated ciphertext.

The Web Vault includes encrypted synchronized personal folders, local TOTP QR-image
decoding, password/passphrase/username generation, organization administration, account
TOTP/WebAuthn/recovery/trusted-device controls, and chunked attachments. QR pixels and
TOTP payloads stay in the browser and are never uploaded.

The project is usable end to end today, but it has not yet received an independent
security audit. Keep backups, use HTTPS outside localhost, and review the documented
[threat model](docs/threat-model.md) before protecting irreplaceable credentials.

## Run from a clean clone

Requirements: Docker Engine with the Compose plugin, and approximately 6 GiB of free
space for the first multi-stage build.

```console
git clone https://github.com/hasilan/hasilan-pass.git
cd hasilan-pass
docker compose up --build --detach --wait
```

Open <http://localhost:8080>, create the first account, and create a Login item. Compose
generates a random PostgreSQL password, token pepper, and independent MFA encryption key
in the `hasilan-secrets` volume. It exposes only Caddy on the host; PostgreSQL and Axum
remain on an internal Docker network. Migrations run automatically before readiness is
reported.

Useful operational commands:

```console
docker compose ps
docker compose logs --follow server web
curl --fail http://localhost:8080/health/ready
docker compose down
```

`docker compose down` preserves the database, deployment secrets, and Caddy state.
Deleting volumes destroys the installation, so do not add `--volumes` unless that is
intentional and a verified backup exists.

## Public HTTPS deployment

Point a DNS A/AAAA record at the host and allow inbound TCP 80/443 and UDP 443. Copy
`.env.example` to `.env`, set `HP_HOSTNAME` to the bare public DNS name, and run:

```console
docker compose -f compose.yaml -f compose.production.yaml up --build --detach --wait
```

The production overlay makes the public URL, CORS origin, and WebAuthn RP exact HTTPS
origins; enables the server's production validation; and lets Caddy obtain and renew TLS
certificates. Place the host behind a trusted reverse proxy only after adjusting the
published ports and preserving the original HTTPS origin. Never terminate public
password-manager traffic as plain HTTP.

All configuration variables are described in [.env.example](.env.example). Changing
`HP_DATABASE_USER` or `HP_DATABASE_NAME` after PostgreSQL has initialized requires a
database migration, not merely an environment edit. The generated secret volume must
move together with the database during disaster recovery.

Manual and TLS-only SMTP invitation delivery, including a Docker secret-file example,
are documented in [docs/self-hosting.md](docs/self-hosting.md).

## Backup and restore

Create a protected logical backup directory while the service is running:

```console
./scripts/backup.sh /secure/backup/location
```

The result includes a consistent PostgreSQL custom dump, all three deployment secrets,
checksums, and a manifest. Although vault payloads are ciphertext, this backup still
contains sensitive account metadata and server keys; encrypt it at rest and restrict
access.

Restore only into the intended Compose project. The explicit confirmation guards the
destructive database replacement:

```console
HP_RESTORE_CONFIRM=restore-hasilan-pass ./scripts/restore.sh \
  /secure/backup/location/hasilan-pass-YYYYMMDDTHHMMSSZ
```

For a production overlay, set `COMPOSE_FILE=compose.yaml:compose.production.yaml` and
`HP_HOSTNAME` for both scripts. Test restores periodically on an isolated host.

## Browser extension

Build the independent Manifest V3 extension; no desktop process or native-messaging
bridge is required:

```console
corepack enable
pnpm install --frozen-lockfile
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.127 --locked
pnpm build:extension
```

In Chromium, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**,
and select `extension/dist`. In Firefox, run `pnpm --dir extension build:firefox`, open
`about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select
`extension/dist/manifest.json`. The extension asks for site access per origin, keeps an
encrypted cache, performs URI matching and cryptography in Rust/WASM, supports autofill
and confirmed save/update capture, and can provide vault passkeys with native fallback.

For a durable Firefox artifact, run `pnpm --dir extension package:firefox`; the ZIP is
written under `extension/artifacts`. Store releases do not accept unsigned local builds
without their normal signing/review flow.

## Desktop client

Install the platform prerequisites from the Tauri 2 documentation, then run:

```console
pnpm install --frozen-lockfile
pnpm --dir desktop tauri dev
```

The desktop client calls the same native Rust crypto/vault/client crates, uses the OS
credential store for device/session material, keeps vault items and private attachment
metadata as ciphertext in its durable cache, supports offline edits and conflict review,
and streams attachment files through native commands so plaintext bytes do not cross the
webview IPC boundary. The cache contains opaque encrypted folder objects alongside encrypted
items, plus only server-visible account/organization metadata; see the documented desktop
boundary. Produce a platform installer with `pnpm build:desktop`.

## Android client

The Android app reuses the same Rust vault core and encrypted offline cache. It supports
Keystore-backed biometric unlock, Android Autofill, a Credential Manager password/passkey
provider, secure clipboard handling, and local TOTP QR scanning.

Install JDK 21, Android SDK 36, and NDK `27.3.13750724`. Set `ANDROID_HOME` and `NDK_HOME`.

```bash
pnpm install --frozen-lockfile
rustup target add aarch64-linux-android
pnpm build:android
```

The debug APK/AAB are Android-debug-key signed for installation smoke tests. Before a
release, set all four values together and build without `--debug`:

```bash
export HP_ANDROID_KEYSTORE=/secure/path/hasilan-release.jks
export HP_ANDROID_KEYSTORE_PASSWORD='…'
export HP_ANDROID_KEY_ALIAS='…'
export HP_ANDROID_KEY_PASSWORD='…'
pnpm build:android:release
```

Run the checks used by CI:

```bash
pnpm check:android
```

With an API 34+ emulator or physical device connected, run the concrete Android checks with:

```bash
cd desktop/src-tauri/gen/android
./gradlew :app:connectedUniversalDebugAndroidTest
```

See the [Android client guide](docs/android.md) for architecture, security boundaries, release
signing, Autofill, Credential Manager, passkeys, and the physical-device checklist.

## Development and verification

Native development uses Rust 1.92, the `wasm32-unknown-unknown` target,
`wasm-bindgen-cli` 0.2.127, Node.js 24, pnpm 10.28.2, and PostgreSQL 17. The generated
WASM bindings are deliberately not committed; `pnpm wasm` regenerates identical browser
artifacts from the shared crate.

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pnpm install --frozen-lockfile
pnpm check:web
pnpm test:web
pnpm build:web
pnpm --filter @hasilan/browser-extension check
pnpm --filter @hasilan/browser-extension test
pnpm build:extension
pnpm check:desktop
pnpm test:desktop
```

The PostgreSQL API journey in `server/tests/api_journey.rs` starts a real TCP server and
exercises registration, encrypted private and organization sync, account MFA, native
desktop sync, chunked attachments, removal recovery, and database plaintext scans. Set
`DATABASE_URL`, `HP_TOKEN_PEPPER`, and `HP_MFA_ENCRYPTION_KEY` to run it against an
isolated test database. Playwright journeys cover Web Vault and the installed extension.

Cross-platform candidate construction, native signing requirements, SPDX SBOMs,
Sigstore/GitHub provenance, checksum verification, and the manual platform checklist are
documented in [release engineering](docs/releasing.md). Tagged workflows only create a
draft release and fail closed when Windows or macOS signing material is missing.

## Compatibility and security boundaries

Hasilan Pass supports plaintext Bitwarden JSON import/export for Login, Secure Note,
Card, Identity, and SSH Key records, including folders, collections, ownership,
timestamps/trash, custom fields, URI matching, password history, TOTP, and FIDO2 fields.
Encrypted JSON, ZIP attachment archives, CSV, KeePass, 1Password, Bitwarden Send, and
drop-in compatibility with official Bitwarden clients or servers are not claimed. See
the tested [compatibility matrix](docs/bitwarden-compatibility.md).

The server necessarily observes account email, device/session data, object identifiers,
ownership and collection ACLs, ciphertext sizes, revisions/timestamps, and network
metadata. Organization membership and collection authorization are server-visible.
Account TOTP seeds are server-verifiable but encrypted at rest under the independent MFA
key. A compromised client, browser page with granted fill access, unlocked workstation,
or malicious extension update remains capable of stealing plaintext. Zero knowledge is
not a substitute for endpoint security.

The detailed design lives in [architecture](docs/architecture.md),
[cryptography](docs/crypto.md), [synchronization](docs/sync.md),
[import/export and portable backup](docs/import-export-design.md),
[browser extension](docs/browser-extension.md), and [desktop](docs/desktop.md).
The Web keyboard/focus model and its manual release checks are recorded in
[accessibility](docs/accessibility.md).

## License

Hasilan Pass is free software licensed under AGPL-3.0-or-later. See `LICENSE`.
