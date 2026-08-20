# Native desktop client

Status: implemented desktop client with three-OS compile gates and package/signature
automation. The companion Android client shares this Rust core; see
[Android client](android.md). First protected signed runs and manual device/platform
smoke remain release gates, 2026-08-13.

## Independence and trust boundary

Hasilan Pass Desktop is a Tauri 2 application whose webview is only a presentation
layer. The `hasilan-desktop-core` crate calls the versioned server API directly and uses
the shared Rust crypto, vault, sync, and Bitwarden compatibility crates. No browser
extension or native-messaging bridge is involved. Conversely, the extension never
connects to this process.

Master-key derivation, user-key unwrapping, item decryption, search, TOTP, generation,
import/export, and sync run in Rust. The webview receives a secret-free list projection;
it receives a complete decrypted item only after the user selects that item. Locking
drops the in-memory user key, decrypted map, access token, and editor/detail state.

## Durable state

The application stores one bounded JSON cache in the platform application-data
directory. It contains:

- server origin, normalized account identifier, device identifier, and KDF settings;
- the password-protected user key returned by the server;
- opaque encrypted item envelopes and the last authenticated sync cursor;
- encrypted outbox entries, idempotency keys, tombstones, and both sides of conflicts;
- server-visible organization/collection catalogs and last-sync time.

It does not contain the master password, decrypted user key, decrypted vault items,
access/refresh tokens, TOTP seeds, attachment filenames, passkey private material, or folder
names in plaintext. Personal folders use the same encrypted object/outbox/sync path as vault
items. Writes use a
same-directory temporary file, `fsync`, and an overwrite rename so a process interruption
cannot leave a partially written cache. Cache/version/profile/item/byte limits are
validated before parsing or decrypting.

The rotating refresh token and a random device secret are stored under per-account keys
in the native credential service through the Rust `keyring` backend:

- macOS: Keychain;
- Windows: Credential Manager;
- Linux: Secret Service-compatible keyring.

Biometric unlock is intentionally not implied by possession of that device secret. A
future biometric wrapper can use it, but current offline unlock always authenticates the
password-protected user key with the master password.

## Online and offline behavior

Registration and login send an authentication proof, never the master password. A
successful login pulls encrypted changes before rendering the vault. Every local edit is
encrypted and committed to the durable outbox before upload. Synchronization performs
pull → ordered upload → pull, refreshes an expired session once, and preserves the outbox
on transport failure.

When prelogin/login cannot reach a server, an existing profile can be unlocked from its
encrypted cache. Offline creates, edits, password history, and tombstones remain queued.
On reconnect, base revisions and idempotency keys prevent blind overwrite. A `409`
retains both encrypted versions and exposes an explicit “keep this device” / “keep
server” decision; there is no silent last-write-wins path.

## Native integrations

- The window closes to a tray icon with Open, Lock, and Quit actions.
- A single-instance plugin raises the existing window on a second launch.
- A native idle monitor clears unlocked state and emits a lock event to the webview.
- Clipboard writes happen in Rust and are cleared after 30 seconds only if the content
  is unchanged, avoiding deletion of a value the user copied afterward.
- Native file dialogs handle Bitwarden JSON. Import is bounded to 64 MiB. Export requires
  a separate explicit plaintext warning and labels the native save dialog as plaintext.
- The application CSP denies remote code, frames, objects, navigation bases, and network
  connections other than Tauri IPC.

## Current UI scope

The native UI supports account registration/password login with TOTP, account switching,
online and offline unlock, local search and categories, Login create/edit/trash,
password-history preservation, TOTP countdown/copy, stored-vault-passkey display/removal,
password/passphrase generation, Bitwarden JSON import/export, explicit conflict choice,
manual sync, automatic lock policy, and session logout. It lists organization and
collection destinations, applies collection write/hide-password policy, encrypts shared
Login items with the organization key, and streams attachment upload/resume/download/
delete through native commands. Login, Secure Note, Card, and Identity records have dedicated
editors, including private custom fields and personal-folder assignment.

Account WebAuthn/passkey login, recovery-code/trusted-device account flows, and organization
administration are not present in the desktop UI. Personal folder create, rename, delete, and
browse controls use encrypted Folder objects; deleting a folder retains its items and clears
their folder assignment. The Android client, rather than desktop, provides biometric vault unlock, system Autofill,
Credential Manager passkeys, and QR TOTP capture. Account authentication passkeys must
not be confused with the implemented display/removal of encrypted website passkeys stored
inside Login items.

## Build and verify

Install the platform prerequisites from the official [Tauri prerequisites guide](https://v2.tauri.app/start/prerequisites/).
On Fedora the native development packages used by the verified build are
`dbus-devel`, `gtk3-devel`, `webkit2gtk4.1-devel`,
`libappindicator-gtk3-devel`, `librsvg2-devel`, and `openssl-devel`.

From the repository root:

```bash
pnpm install --frozen-lockfile
pnpm check:desktop
pnpm test:desktop
pnpm build:desktop
```

`build:desktop` sets linuxdeploy's documented `NO_STRIP=1` compatibility switch. This is
needed when creating an AppImage on distributions whose system libraries contain modern
RELR sections that the older linuxdeploy-bundled `strip` cannot understand. It does not
disable Rust release optimization and is ignored by non-Linux packaging tools.

The Linux build produces the native binary plus `.deb`, `.rpm`, and `.AppImage` bundles.
The Tauri configuration also carries Windows `.ico` and macOS `.icns` resources. Normal
CI compiles the application on Windows and macOS as well as Linux. The protected release
workflow builds all three platform package sets, requires and verifies native signing and
notarization on tags, and records unsigned manual runs explicitly. Signing credentials
are operator/release secrets and are never committed. See
[release engineering](releasing.md) for the exact gate and manual smoke checklist.

The PostgreSQL integration journey is opt-in and destructive to the configured test
database:

```bash
HP_TEST_DATABASE_URL='postgres://.../hasilan_test' \
  cargo test -p hasilan-server --test api_journey -- --nocapture
```

That journey starts a real TCP listener, registers with native client A, synchronizes to
native client B, stops the listener, unlocks/edits offline, restarts the listener, flushes
the durable outbox, verifies the update on B, revokes the session, and searches both the
desktop cache and PostgreSQL ciphertext columns for known plaintext canaries.

## Operational notes

- Loopback HTTP is accepted for local development. Every non-loopback server URL must use
  HTTPS and cannot contain credentials, query parameters, or fragments.
- Linux desktop keyring behavior depends on an available Secret Service session. A
  headless installation must provide one; falling back to a plaintext token file is not
  permitted.
- Plaintext exports are outside the encrypted-cache guarantee. Treat them as secrets and
  remove them after use.
- Tray and clipboard behavior can be affected by desktop-environment policy. Platform
  smoke tests remain mandatory before publishing a release.
