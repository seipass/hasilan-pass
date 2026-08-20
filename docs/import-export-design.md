# Import, export, and portable backup design

Status: design accepted; only plaintext Bitwarden JSON is implemented, 2026-08-13

Import/export code runs in an unlocked client. The Axum server has no endpoint that
accepts a decrypted vault, import file, export file, archive password, or attachment
plaintext. Every importer is atomic: it parses and validates into a bounded staging model,
shows a count/warning summary, then encrypts locally. A failure commits no partial import.

## Currently shipped

Web Vault and desktop accept at most 64 MiB of plaintext Bitwarden JSON. The shared Rust
compatibility crate limits the file to 40,000 items, 2,000 folders, and 2,000 collections,
rejects encrypted input explicitly, and preserves the documented fields described in
[bitwarden-compatibility.md](bitwarden-compatibility.md). Export is plaintext JSON and is
created locally after an explicit warning. Bitwarden JSON does not contain attachment
bytes.

Deployment backup is separately implemented by `scripts/backup.sh`: it captures a
consistent PostgreSQL custom dump plus the server pepper/MFA/deployment secrets and
checksums. That is an operator disaster-recovery artifact, not a portable user-vault
export; it still exposes account and access metadata and must be encrypted at rest.

Everything below is a design gate, not a claim of working UI.

## Portable encrypted Hasilan backup (`.hpbk`)

The portable archive is independent of the account's current User Key so it can restore
into another account. The client asks for a dedicated backup password twice and derives a
32-byte archive key with bounded Argon2id parameters recorded in the authenticated header.
It never silently reuses or transmits the master password.

The binary format has a fixed `HPBK` magic, format version, KDF identifier/parameters,
random 32-byte salt, random nonce prefix, and an encrypted canonical manifest. Manifest
and attachment data are XChaCha20-Poly1305 frames with monotonically increasing indices.
AAD binds the complete immutable header, frame kind/index/length/final marker, logical
object ID, and previous frame tag so truncation, reordering, duplication, and cross-archive
splicing fail before any staged object is accepted. The final authenticated manifest
contains item/folder/collection counts and a digest of every logical attachment stream.

Import enforces the same object limits as live sync, a 64 GiB default total plaintext cap,
100 attachments per item, 100,000 frames per attachment, and deployment-adjustable lower
limits. It derives the archive key only after validating KDF floors and ceilings. A wrong
password, corrupt frame, unsupported version, duplicate ID, dangling folder/collection,
or missing attachment fails the entire staging transaction with one non-oracular error.
Secrets and failed plaintext buffers are zeroized where Rust ownership permits.

Export writes to a same-directory temporary file, flushes it, and atomically renames it.
Web uses a download stream when browser support permits and refuses an archive that would
require unbounded memory. Desktop performs all attachment reads and writes in native Rust
so bytes do not cross webview IPC.

## Password-protected Bitwarden JSON

Support must follow Bitwarden's documented password-protected envelope and fixed upstream
fixtures. The decoder will validate `encrypted`, `passwordProtected`, KDF type/parameters,
salt encoding, key-validation field, and encrypted data dimensions before allocation.
KDF work has hard upper bounds. Authentication and padding errors collapse into a single
wrong-password-or-corrupt-file result, and decrypted JSON then passes through the existing
bounded atomic importer.

Account-restricted Bitwarden exports are not portable. They may only be offered while the
matching source User Key is already unlocked and the UI must label them “same source
account only.” Hasilan will never ask a server to decrypt either form.

## Bitwarden ZIP with attachments

ZIP support first validates the documented layout against captured official fixtures.
Archive processing rejects absolute paths, `..`, symlinks, duplicate normalized names,
encrypted ZIP entries, unsupported compression methods, overlapping entries, excessive
entry counts, per-entry expansion, and aggregate compression ratios. JSON is parsed before
attachment association; every declared file must map to one known item/attachment and
unreferenced bytes require explicit user review. Extraction uses private temporary files
with cleanup on failure. Export uses stable opaque archive paths rather than secret item
names and includes a manifest mapping them to the client-encrypted metadata.

## CSV

CSV is inherently lossy. Import uses a streaming RFC 4180 parser with UTF-8 validation,
spreadsheet formula text treated as inert data, a 64 MiB/100,000-row ceiling, and an
explicit column-mapping preview. Presets may cover documented Bitwarden, Chrome, Firefox,
and generic `name,username,password,url,notes` layouts, but source-specific detection must
never guess silently when headers are ambiguous. Multiple URLs, custom fields, TOTP,
passkeys, attachments, folders, organization ownership, and history that cannot map are
reported before commit. CSV export is opt-in plaintext, Login-only, and prefixes cells
beginning with formula-control characters for spreadsheet safety while warning that the
result is not a full backup.

## KeePass XML

The target is KeePass's plaintext XML export, not KDBX decryption. A streaming XML parser
runs with DTDs, external entities, network access, and entity expansion disabled. Depth,
attribute, text, group, entry, and total-byte limits prevent XML bombs. Nested groups map
to personal folders; title/user/password/URL/notes, additional string fields, TOTP URI,
timestamps, tags, and history map where semantics are known. Protected-value placeholders,
binaries, custom icons, auto-type rules, and plugin extensions are summarized as omitted
unless a tested mapping exists. Raw XML is never rendered in the DOM.

## 1Password

The supported target is a documented `.1pux` export. It is a ZIP and receives the same
path, entry-count, expansion, and temporary-file controls as Bitwarden ZIP. The importer
parses `export.data` as bounded JSON Lines, validates each record independently into the
staging transaction, maps Login/Secure Note/Card/Identity/SSH and TOTP fields, and binds
document entries to their referenced files. It does not execute or display the bundled
HTML export. Unsupported category fields are preserved as named custom fields when that
is unambiguous and otherwise appear in the pre-commit omission report.

## Collision and ownership policy

Import never overwrites an existing item merely because IDs or names match. A new ID is
allocated by default while retaining source IDs in local import metadata; an advanced
same-vault restore may keep IDs only after proving the destination is empty or presenting
every collision. Organization ownership is not recreated without an existing writable
organization/collection and a locally available organization key. Otherwise items become
personal and the ownership change is disclosed before commit. Folder names are encrypted
and uploaded before the items that reference them.

## Verification gates

- published/source-owned fixtures plus synthetic fixtures containing no real credentials;
- import → export → import semantic equality for every supported field;
- wrong password, modified header/frame/tag, truncation, reordering, duplicate ID, dangling
  reference, ZIP traversal/bomb, XML entity, oversized CSV cell, and interrupted-write tests;
- fuzz targets for every parser and archive manifest, with seeded regression corpora;
- Web and native E2E that scan API bodies, PostgreSQL, cache files, and temporary paths for
  unique plaintext canaries;
- compatibility documentation updated in the same change that enables a format in UI.
