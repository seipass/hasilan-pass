# Bitwarden compatibility

Status: implemented plaintext-JSON baseline with explicit exclusions, 2026-08-13

## Scope and evidence

Compatibility means the user-visible vault data model and documented import/export
formats. It does not mean emulating Bitwarden's private cloud, undocumented server API,
database schema, licensing system, push infrastructure, or every transient client field.

Primary sources reviewed on 2026-08-12:

- Bitwarden export documentation and linked sample:
  https://bitwarden.com/help/export-your-data/
- Bitwarden import documentation:
  https://bitwarden.com/help/import-data/
- Bitwarden KDF documentation:
  https://bitwarden.com/help/kdf-algorithms/
- Bitwarden security whitepaper:
  https://bitwarden.com/pdf/help-bitwarden-security-white-paper.pdf
- Bitwarden passkey browser architecture:
  https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/provider/browser-extension/
- `bitwarden/sdk-internal` commit
  `23383b7c0ac01667a0ef78257230c1ceb030b07c` (Rust crypto, vault, exporter models).
- `bitwarden/clients` commit
  `a08d50a9e669f1c987d7c38460f387578ab911de` (JSON export types and browser behavior).
- `bitwarden/server` commit
  `e19a9bbc8ab6507a6c66a66f27d3a861825822bc` (Cipher persistence and sync response shape).

Public product documentation is treated as a supported contract. Export samples and
serialized public models are treated as observable format evidence. Source-only details
are labeled implementation observations and may change. We do not copy source code;
fixtures contain synthetic data and public standard vectors. Bitwarden names and marks
remain their owners' property.

## Plain JSON top level

Individual export:

```json
{
  "encrypted": false,
  "folders": [{ "id": "uuid", "name": "name" }],
  "items": []
}
```

Organization export replaces `folders` with `collections`. IDs are UUID strings.
Importers accept absent optional arrays and `null` where current exports use either, but
exporters produce one canonical shape. Unknown item, Login, URI, collection, and
type-specific properties are retained in extension maps. Unknown top-level export and
folder properties are not currently retained and must not be used as a generic JSON
round-trip guarantee.

## Cipher/item model

Common fields:

- `id`, `folderId`, `organizationId`, `collectionIds`
- `type`, `name`, `notes`, `favorite`, `reprompt`
- `fields[]` (`name`, `value`, `type`, `linkedId`)
- `passwordHistory[]` (`password`, `lastUsedDate`)
- `creationDate`, `revisionDate`, `deletedDate`, and newer `archivedDate`

Observed numeric item types as of the reviewed SDK are Login `1`, Secure Note `2`, Card
`3`, Identity `4`, SSH Key `5`, Bank Account `6`, Driver's License `7`, and Passport `8`.
Hasilan maps 1-5 into typed Rust models. It retains the type-specific properties of
6-8 and unknown numeric types as opaque JSON alongside all common fields, then emits them
again; synthetic executable fixtures cover 6, 7, 8, and 42. Dedicated editors are not
implied by format preservation.

Login fields:

- `username`, `password`, `totp`
- `uris[]` with `uri` and nullable `match`
- `fido2Credentials[]`

URI match values are Domain `0`, Host `1`, Starts With `2`, Exact `3`, Regular Expression
`4`, and Never `5`. A missing match uses the account default in Bitwarden; Hasilan Pass
uses Base Domain as its documented default. Regex is opt-in and bounded against denial of
service.

Secure Note carries `{ "type": 0 }`. Card and Identity preserve the current named string
fields, including null values. Folder/collection and organization ownership are routing
metadata as well as export fields.

## TOTP

Bitwarden stores the Login `totp` value as either a Base32 secret or an `otpauth://` URI.
Hasilan Pass accepts both, preserves the original URI parameters, and exports the same
semantic value. Issuer/account label, secret, algorithm, digits, and period are parsed
locally. Steam-style extensions are preserved but are not claimed as supported until
tested.

## Vault passkeys / FIDO2

The current JSON export credential fields are:

- `credentialId`
- `keyType` (`public-key`)
- `keyAlgorithm` (`ECDSA`)
- `keyCurve` (`P-256`)
- `keyValue` (private key material)
- `rpId`
- optional `userHandle`, `userName`, `rpName`, `userDisplayName`
- `counter` serialized as a string
- `discoverable` serialized as a string boolean
- `creationDate`

These fields are encrypted in synchronized Cipher records and plaintext only in a
plaintext export. The official extension architecture notes that browsers do not expose
an API for extension passkeys alongside native passkeys; providers replace/interpose
`navigator.credentials.create/get` and retain native fallback. We therefore separate
the shared WebAuthn authenticator from Chromium/Firefox injection adapters and require an
explicit user-presence confirmation for every operation.

## Attachments

Normal JSON exports historically omit attachment bytes. Current product documentation
offers a ZIP-with-attachments export containing JSON plus files. The observed synchronized
attachment model carries `id`, URL, ciphertext size/display size, encrypted file name,
and optional wrapped attachment key. New Bitwarden attachments have a per-attachment key
wrapped by the Cipher key; legacy variants also exist.

Hasilan's own server and clients support resumable encrypted attachments, but do not yet
import or export Bitwarden ZIP archives. Plain JSON never includes attachment bytes. The
clients warn that a plaintext JSON export omits those bytes; use Hasilan's deployment
backup for disaster recovery until a client-portable encrypted archive is implemented.

## Encryption representations

Stable legacy `EncString` forms observed in current SDK:

- type 0: `0.<base64(iv)>|<base64(ciphertext)>` (decrypt-only, unauthenticated)
- type 2: `2.<base64(iv)>|<base64(ciphertext)>|<base64(mac)>`
- type 7: `7.<base64(COSE_Encrypt0)>` (new evolving family)

Type 2 is AES-256-CBC/PKCS#7 plus HMAC-SHA256 over IV and ciphertext with a 64-byte
composite key. Hasilan Pass parses 0 and 2, emits 2 for legacy-compatible wrapping, and
does not yet claim type-7 interoperability. See [crypto.md](crypto.md).

Bitwarden's current implementation is migrating from per-field `EncString`s to encrypted
Cipher data blobs. That representation and COSE algorithms are implementation-level and
still changing. Hasilan Pass uses its own explicitly versioned whole-item envelope on its
server while maintaining decrypted export compatibility.

## Encrypted JSON exports

Two forms exist:

- account-restricted: tied to the originating account encryption key and invalidated by
  key rotation;
- password-protected: portable between accounts.

The current password-protected envelope has `encrypted`, `passwordProtected`, `salt`,
`kdfType`, `kdfIterations`, optional `kdfMemory`/`kdfParallelism`,
`encKeyValidation_DO_NOT_EDIT`, and encrypted `data`. An implementation observation is
that the displayed Base64 salt string itself is passed to the KDF. Neither encrypted form
is decoded by the current compatibility crate: it returns a specific encrypted-export
error before importing any item. Password-protected support requires upstream fixtures;
account-restricted data can only be meaningful with the matching source account key and
is not a generic migration format.

Plaintext export is generated entirely on the client and accompanied by a prominent
warning. It is never uploaded back to the server.

## Organizations and key sharing

Bitwarden creates a random organization symmetric key, protects it separately for each
member using that member's RSA public key (RSA-OAEP), and stores each member's encrypted
copy server-side. The member's RSA private key is itself encrypted by the user key.

Hasilan preserves the high-level per-member wrapper hierarchy but uses a versioned
`hp-share.v1` construction: ephemeral X25519, HKDF-SHA256, and XChaCha20-Poly1305 with
recipient- and organization-bound AAD. This is not RSA wire compatibility. Collections
remain server-visible authorization groupings, while organization-owned item bodies and
organization keys remain client-encrypted. See [crypto.md](crypto.md).

## Sync compatibility boundary

Bitwarden sync returns profile/key material, folders, collections, Ciphers, policies,
Sends, and other account state. Its server entity stores encrypted Cipher `Data`, `Key`,
attachments and server metadata. Neither the exact response nor internal database schema
is documented as a stable third-party protocol.

Hasilan Pass does not advertise drop-in compatibility with official Bitwarden clients or
servers. Migration uses import/export; Hasilan clients use `/api/v1` documented by this
repository's OpenAPI. A future Bitwarden protocol adapter must be isolated and tested
against a declared server/client release.

## Tested round-trip guarantees

The checked-in synthetic suite verifies:

1. Official-style plaintext JSON for Login, Secure Note, Card, Identity, and SSH Key maps
   to the typed Hasilan model.
2. Export emits the documented Bitwarden field names and numeric type values.
3. import -> export -> import preserves semantic model equality, including folders,
   custom fields, URI policy, password history, TOTP, and FIDO2 fields.
4. Type-specific payloads for newer types 6-8 and an unknown type 42 survive without
   interpretation, including trash state.
5. Malformed, oversized, encrypted, or semantically invalid input fails atomically.

Semantic equality normalizes JSON object ordering and timestamps but does not discard
IDs, folder/collection membership, ownership, password history, deletion state, passkey
fields, or TOTP parameters. Tests must use synthetic credentials only.

## Current compatibility matrix

| Area | Current behavior | Evidence/status |
|---|---|---|
| Plain JSON Login/Note/Card/Identity/SSH | typed read/write | synthetic semantic round-trip tests pass |
| folders, collections, ownership, timestamps, trash | read/write | format tests; personal folders also sync as encrypted Hasilan objects in Web |
| custom fields, URI strategies, password history | read/write | checked-in fixture and URI matcher tests |
| TOTP values | read/write + local RFC generation | Base32/`otpauth` parser and RFC vector tests |
| FIDO2 export fields | read/write | fixture plus vault-passkey crypto tests |
| types 6-8 and unknown numeric types | opaque type-specific payload preservation | synthetic 6/7/8/42 round-trip test; no dedicated editor |
| password-protected JSON | rejected atomically | not implemented |
| account-restricted JSON | rejected atomically | not implemented; source key required by design |
| ZIP attachments | rejected/not produced | not implemented |
| CSV, KeePass XML, 1Password | not accepted | design only; see [import-export-design.md](import-export-design.md) |
| Bitwarden server/API | none | explicitly out of scope |
| COSE/type-7 Cipher storage | none | not claimed |
