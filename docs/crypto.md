# Cryptographic design

Status: implemented v1 contract with explicitly listed future work, 2026-08-13

This document is a protocol contract, not a claim that cryptography alone makes a client
safe. Algorithms are provided by maintained RustCrypto crates. No primitive is
implemented from scratch. Secret key containers use `secrecy` and `zeroize`; production
`Debug` and tracing output redact all secret-bearing values.

## Research basis

Bitwarden's current security whitepaper describes a locally derived 256-bit master key,
HKDF expansion to a 512-bit stretched master key, a random 512-bit user symmetric key,
and client-side decryption. It also describes random 64-byte per-Cipher keys, attachment
keys, RSA-OAEP organization key sharing, and ES256 vault passkeys. Hasilan's import
format follows the user-visible model; its server-side organization wrapper is deliberately
not Bitwarden-RSA-compatible:

- https://bitwarden.com/pdf/help-bitwarden-security-white-paper.pdf
- https://bitwarden.com/help/kdf-algorithms/
- https://contributing.bitwarden.com/architecture/cryptography/crypto-guide/

The public `bitwarden/sdk-internal` implementation was examined at commit
`23383b7c0ac01667a0ef78257230c1ceb030b07c` (2026-08-11). It confirms current KDF
defaults, email normalization, Argon2 salt pre-hashing, HKDF labels, and the serialized
`EncString` variants. The repository is dual-licensed GPL-3.0-only or under the Bitwarden
SDK license outside `bitwarden_license`. Hasilan Pass is an independent implementation;
no Bitwarden source is copied.

## Key hierarchy

```text
Master password (user input; never persisted)
  |
  +-- Argon2id or PBKDF2-HMAC-SHA256(email salt) -> Master Key (32 bytes)
        |
        +-- HKDF-SHA256(info="enc") -> wrapping encryption key (32 bytes)
        +-- HKDF-SHA256(info="mac") -> wrapping MAC key (32 bytes)
        +-- PBKDF2-HMAC-SHA256(password, purpose=1) -> authentication proof
              |
              +-- server-side Argon2id hash -> stored authentication verifier

random User Key (64 bytes: encryption || MAC)
  +-- encrypted by stretched Master Key -> Protected User Key (server stores)
  +-- wraps random per-item keys
  +-- encrypts the user's private organization-sharing key

random Item Key (64 bytes)
  +-- encrypts one complete vault item payload
  +-- wraps random per-attachment keys

random Attachment Key (64 bytes)
  +-- streaming-encrypts one attachment

random account X25519 sharing private key (32 bytes)
  +-- encrypted by the User Key; matching public key is server-visible
  +-- opens recipient-specific organization-key wrappers
```

Master passwords, master keys, stretched keys, plaintext user keys, plaintext item keys,
and plaintext attachment keys never cross the client/server boundary.

## KDF parameters

New accounts default to the current Bitwarden Argon2id settings:

- Algorithm: Argon2id version 0x13
- Output: 32 bytes
- Email normalization: trim and Unicode-lowercase for the initial implementation;
  compatibility fixtures use ASCII email addresses
- Salt: SHA-256 of normalized UTF-8 email, matching current SDK behavior
- Memory: 32 MiB
- Iterations: 6
- Parallelism: 4

PBKDF2 compatibility mode uses PBKDF2-HMAC-SHA256, normalized UTF-8 email directly as
salt, a 32-byte output, and 600,000 iterations. Clients reject parameters below the
server policy and impose upper bounds before allocation to prevent malicious KDF
resource exhaustion.

KDF parameters and salt identity are returned by prelogin and are authenticated again in
the login response. Parameter migration rewraps only the user key and replaces the auth
verifier; it does not decrypt vault data on the server.

The authentication proof follows the stable Bitwarden v1 construction for
interoperability tests: PBKDF2-HMAC-SHA256 with the 32-byte Master Key as password, the
UTF-8 master password as salt, one iteration for server authorization. The server then
stores a memory-hard Argon2id password hash of that 32-byte proof. The proof is a bearer
secret during login and is never logged.

## `EncString` v1

Hasilan Pass parses legacy Bitwarden symmetric types 0 and 2 but emits only authenticated
type 2 in v1. The textual form is:

```text
2.<base64(iv)>|<base64(ciphertext)>|<base64(mac)>
```

- composite key: 64 bytes, first 32 AES key and last 32 HMAC key
- IV: 16 fresh CSPRNG bytes for every encryption
- encryption: AES-256-CBC with PKCS#7 padding
- authentication: HMAC-SHA256 over `IV || ciphertext`
- verification: constant-time and performed before decryption
- AAD: none; type 2 has no associated-data facility

Type 0 (`0.<iv>|<ciphertext>`) is unauthenticated and decrypt-only. Type 7 is Bitwarden's
new COSE Encrypt0 family and remains read-research-only until its public contract and
migration behavior stabilize. Unknown types fail closed.

The lack of AAD in type 2 is addressed by encrypting the entire private item, including
its ID, owner, and schema version, as one payload. Clients compare duplicated public
routing fields after decryption. A future `hp.v2` envelope will use an audited AEAD with
canonical AAD; the envelope's `format` field makes mixed-version migration explicit.

## Serialization and canonical data

Private payloads are UTF-8 JSON with a required `schemaVersion`. Deserialization has
depth, size, string-length, and collection-count limits. Encryption does not rely on JSON
object order. Any value used as authenticated routing data is encoded in a fixed binary
AAD format in future AEAD versions rather than ad-hoc JSON concatenation.

Random IDs use UUIDv4. Nonces/IVs and all content keys use the operating system CSPRNG.
Keys are never derived from object IDs or timestamps.

## Attachments

An attachment has its own random key wrapped by the parent item key. Metadata that may
reveal content, including file name, media type, and plaintext size, is inside encrypted
metadata. The server sees ciphertext length, chunk count, ownership, and object IDs.

V1 streaming uses independently authenticated XChaCha20-Poly1305 frames rather than
treating a whole file as one `EncString`. HKDF-SHA256 derives a 32-byte file key from the
random 64-byte attachment key, item ID, attachment ID, and file nonce. Each 24-byte nonce
is the random 16-byte file nonce followed by the checked big-endian chunk index. AAD binds
the format context, item and attachment IDs, file nonce, total plaintext and ciphertext
sizes, chunk size/count/index, current plaintext length, and final-chunk marker.

The client accepts 64 KiB–2 MiB chunks (1 MiB default), at most 100,000 chunks and 64 GiB
of plaintext; a deployment may configure a lower server quota. Empty files are one
authenticated zero-length frame. Truncation, reordering, duplication, size substitution,
and cross-file or cross-item splicing fail authentication. Rust tests cover round trips
and every one of those mutation cases before the Web, extension, or desktop path accepts
downloaded bytes.

## Organization key sharing

Each account has an X25519 key pair. Its 32-byte private key is encrypted as a type-2
`EncString` under the user's 64-byte User Key; only the public key is exposed by the
directory endpoint. An inviter generates a random 64-byte organization key and creates
one `hp-share.v1` wrapper per confirmed recipient using ephemeral X25519, HKDF-SHA256,
and XChaCha20-Poly1305. AAD binds the organization UUID, recipient public key, and
ephemeral public key. Low-order shared points and non-canonical base64url are rejected.

This construction is versioned and zero-knowledge, but it is not wire-compatible with
Bitwarden's RSA-OAEP organization-key wrapper. Organization migration therefore uses
decrypted client-side export/import rather than copying Bitwarden server key records.

## Passkeys and TOTP

Vault passkeys use WebAuthn ES256/P-256 initially. Credential ID, RP ID, COSE/private key
material, public key, user handle, names, signature counter, discoverability, transports,
and creation metadata live in the encrypted item payload. Private key material is only
decrypted for a confirmed, origin-validated WebAuthn operation and is never sent to a
content script as part of a vault listing.

TOTP seeds are stored as an `otpauth://` URI or Base32 secret inside the encrypted Login
payload. Codes are generated locally according to RFC 6238. The default is SHA-1, six
digits, and a 30-second period only when fields are omitted; SHA-256 and SHA-512 are
supported. Secret material is not included in logs, analytics, crash reports, or search
indexes.

## Rotation and recovery

The currently shipped account flows rotate refresh tokens, recovery codes, trusted-device
tokens, TOTP enrollment, and WebAuthn credentials. Master-password/KDF change and whole
User-Key rotation are future migration operations: they must rewrap the User Key or every
personal item/private sharing key respectively, and must not be represented as available
until their atomic server transaction and interruption tests land.

- Item edit: generate a new IV. A new item key is optional for ordinary edits and required
  when ownership changes.
- Organization removal: revokes server access immediately but cannot make ciphertext or
  keys already copied by a formerly authorized member disappear.

Recovery codes are generated with the CSPRNG, shown once, and stored server-side only as
salted hashes. They recover authentication access, not a lost zero-knowledge vault key,
and no admin escrow or recovery-key feature is currently shipped.

## Required verification

- RFC and upstream published vectors for PBKDF2, Argon2id, HKDF, AES-CBC, HMAC, and TOTP.
- Current Bitwarden SDK compatibility vectors for KDF, master hash, stretched key, and
  type-2 `EncString` parsing/decryption.
- Negative tests for modified type, IV, ciphertext, MAC, padding, wrapped key, item ID,
  owner, and oversized parameters.
- Property/fuzz tests for parsers; round-trip tests alone are insufficient.
- `cargo audit`, `cargo deny`, secret scanning, and a ban on unreviewed `unsafe`.
