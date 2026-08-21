# Device unlock and session lifecycle

Hasilan Pass has three deliberately separate states:

1. **Unauthenticated** – no server session is held and no decrypted vault key is in memory.
2. **Authenticated + locked** – the server session may be refreshed, but the user/vault key,
   decrypted objects, folders, and search index have been cleared.
3. **Authenticated + unlocked** – the access token and decrypted vault are held only for the
   active client runtime.

`Lock` moves from unlocked to authenticated+locked. It never calls the server logout endpoint.
`Log out` (or revoking the current session) revokes the server session, clears access/refresh
session state, deletes the remembered device envelope, and returns to unauthenticated. A manual
lock also sets a per-device suppression flag, so the next restart/resume cannot silently unlock;
entering the master password clears that flag.

## Web Vault

The Web Vault uses the server's HttpOnly, Secure, SameSite=Strict refresh cookie for session
resume. The access token is memory-only. The CSRF value and non-secret resume metadata are stored
inside an encrypted IndexedDB envelope; neither access nor refresh tokens are written to
`localStorage` or `sessionStorage`.

When **Remember unlock on this device** is selected, the WebCrypto store creates a non-extractable
AES-GCM device key in IndexedDB. The 64-byte Rust user key is encrypted with an envelope version
and AAD binding the application, account, device, and record purpose. A non-secret SHA-256 key
version binds the envelope to the current protected user-key/KDF tuple; a password/key rotation
therefore invalidates the old remembered key and requires a fresh password unlock. On reload the
cookie resumes the authenticated session first; only then is the envelope considered for automatic
unlock. A missing, corrupted, or account-mismatched envelope fails closed and leaves the vault
locked. The UI warns that device access is weaker than memory-only mode.

WebCrypto protects storage at rest, not a compromised same-origin page: code executing as the
origin can ask WebCrypto to decrypt. The Web Vault therefore keeps the device option explicit and
documents the stronger installed-client boundary below.

## MV3 extension

The service worker keeps access tokens only in memory. Its rotating refresh token, session
metadata, and optional wrapped user key are encrypted in IndexedDB by a non-extractable AES-GCM
device key. Worker suspension can therefore restore the authenticated session without placing a
plaintext refresh token in extension storage. A manual lock keeps the refresh session but blocks
the wrapped-key restore until the user enters the master password. `Log out` removes all three
encrypted records and sends the server revoke request.
The popup exposes the same automatic-lock choices as the Web Vault, including 4 hours and Never.
Its Settings view also lets the user enable or remove the encrypted remembered-unlock envelope
without signing in again.
The worker keeps encrypted records through temporary network failures, but an explicit 401/403
session rejection removes the refresh token and remembered unlock.

## Desktop and Android

Desktop uses a random device wrapping key in the OS credential store (Keychain, Credential
Manager, or Secret Service). Password unlocking an already cached profile is local and does not
create a second server session. The wrapped user key is an authenticated XChaCha20-Poly1305 envelope
with versioned AAD bound to the cached profile. Refresh credentials remain separate OS secrets;
access tokens are never serialized. The desktop resume command rotates the refresh credential and
then restores the wrapped key only when the option is enabled and manual-lock suppression is clear.

Android's storage alias and biometric alias are Android Keystore AES-GCM keys. The biometric
envelope is private-app ciphertext of the Rust user key, requires `BIOMETRIC_STRONG`, prefers
StrongBox, and is invalidated by biometric-enrollment changes. Its versioned envelope stores no
plaintext key: context-bound AAD authenticates the active server/account/device and key version,
so an envelope from another cached account or after key rotation is rejected. Android clears the
native vault coordinator when the activity leaves the foreground; when remembered unlock is
enabled, foregrounding restores that envelope without revoking the server session, otherwise the
user enters the master password. Autofill and Credential Manager require a fresh biometric
prompt. Keystore invalidation clears the unusable envelope rather than weakening the policy.

## Operational guarantees

- Master passwords, KDF-derived keys, plaintext user/vault keys, decrypted objects, and access
  tokens are not durable application data.
- Ciphertext caches may survive a lock; their keys and decrypted projections do not.
- Remote session revocation removes local remembered-unlock material on the next authenticated
  error or explicit account-security action.
- Device-unlock storage is versioned and authenticated. Corruption, wrong AAD, wrong account, or
  wrong device is treated as a locked state, never as a best-effort decrypt.
- Temporary network failure preserves the encrypted session record for a later resume; explicit
  server rejection, logout, or a local corruption fallback removes the affected resume material.
