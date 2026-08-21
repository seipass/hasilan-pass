# Android security boundary

This document describes the Android-specific boundary. The vault format, KDF, authenticated
encryption, URI matching, TOTP generation, passkey validation, and sync outbox are shared Rust
code. Kotlin does not keep a second vault or a plaintext mirror of the cache.

## Local data and keys

The offline cache is the same encrypted Rust document used by the desktop client. Android only
stores opaque device/session values and the optional offline-unlock user key envelope in private
app storage. Each is wrapped by an Android Keystore AES-GCM key; plaintext exists only while an
operation is running and byte arrays are cleared after use where the platform permits.

Two aliases are used:

- The storage alias protects opaque values the core delegates to the operating system.
- The biometric alias requires `BIOMETRIC_STRONG`, has no validity window, and encrypts only the
  Rust user key for optional offline unlock. It is invalidated when biometric enrollment changes.

New aliases prefer StrongBox on API 28+ when the device advertises it, then fall back to the
normal Android Keystore when StrongBox is unavailable or full. The Security screen reports
StrongBox availability and the actual hardware/StrongBox protection of aliases that exist. A
device migration, app-data reset, lock-screen reset, or biometric enrollment change can make an
envelope unrecoverable; Hasilan Pass clears that envelope and requires normal account login. It
does not silently weaken biometric requirements or derive a replacement vault key.

## Locking, lifecycle, and privacy

The main activity clears the Rust coordinator in `onStop`; system Autofill and Credential Manager
activities each require a separate biometric unlock. On foregrounding, the webview asks the native
coordinator for status before showing the prior vault view, clearing stale list/detail state if it
was locked. With Remember unlock enabled, it restores the OS-wrapped key and keeps the server
session; with it disabled, the normal password unlock screen is shown. The user can set the
in-app inactivity timeout (1 minute through 4 hours, or Never); background locking is deliberately
immediate. Locking clears decrypted Rust state but does not revoke the authenticated server
session. Logout/revocation removes refresh/device envelopes and ends the session.

`FLAG_SECURE` is set on the main, Autofill, Credential Manager, save, and QR activities. Android
backup and device-transfer rules exclude app data. The manifest uses no cleartext traffic in
release builds, the app has no analytics SDK, and QR payloads, secrets, keys, and credential
responses must not be logged.

Attachments use Android's Storage Access Framework rather than a broad storage permission. The
selected plaintext is copied to a bounded app-private cache staging file only while the shared
Rust core encrypts/uploads it. A downloaded attachment is authenticated/decrypted into an
app-private temporary file and copied to a user-selected URI. Both temporary paths are
best-effort overwritten and removed on completion, failure, and next plugin initialization; flash
storage makes physical overwrite non-guaranteed. The final user-selected download is intentionally
outside the vault cache and is subject to that storage provider's retention policy.

## Biometrics and system services

Biometric unlock is explicit and opt-in. It is available only to a Class 3 /
`BIOMETRIC_STRONG` enrollment. Every Autofill fill/save and Credential Manager password or
passkey operation prompts again. The versioned biometric envelope authenticates a non-secret
context containing the active profile, device, and protected-user-key/KDF version as AES-GCM AAD;
switching accounts or rotating the server key therefore fails closed instead of decrypting a
different profile. System-service processes never keep a persistent user key, access token, or
second network session.

If the Keystore, biometric prompt, package-signature check, Digital Asset Links check, or native
cache opening fails, the operation fails closed. A cancelled prompt does not return a partial
dataset or credential response.

## Clipboard and camera

Copy uses Android's clipboard and, by default, clears the exact unchanged value after 30 seconds.
The device setting permits 15, 30, 60, or 120 seconds, or disabling automatic clearing. The clear
operation never overwrites a value that another app placed on the clipboard later. Clipboard
contents are necessarily visible to the operating system and eligible keyboard/clipboard apps, so
automatic clearing is a convenience rather than a confidentiality guarantee.

Camera permission is requested only after **Scan QR**. CameraX and the bundled Apache-2.0 ZXing
decoder process the frame on the device; only a bounded `otpauth://totp/` string is returned to
the Login form and validation is performed by the shared Rust TOTP parser. Images and QR strings
are not uploaded. QR decoding has no Google Play Services or Firebase dependency.

## Incident and recovery behavior

- On logout, the shared client revokes the current device session when online, drops plaintext,
  removes remembered-unlock material, and keeps only encrypted offline data needed for normal
  account recovery.
- A revoked session, changed password, or unavailable self-hosted server must be resolved through
  the normal account flow; no Android-only recovery secret is created.
- Users should remove the app's Autofill/Credential Manager service in Android Settings before
  transferring an unmanaged device, then delete the app data after confirming their server sync.
- A security report should include the Android version, device model, and non-secret log timing;
  never include a vault export, passkey challenge, QR value, token, or Keystore ciphertext.

## Threat analysis and residual risk

| Threat | Boundary and response | Residual risk |
| --- | --- | --- |
| Stolen Android device | The app locks on backgrounding, keeps the vault cache encrypted, and requires the master password or an opt-in Class 3 biometric Keystore unwrap. Remove the account session/server device trust remotely if the device is lost. | An already-unlocked, foreground device can be used by whoever has physical control. |
| Malicious Android app | Android sandboxing protects private storage; Autofill and provider requests are origin/package/certificate checked and non-exported Activities are screen-protected. | Accessibility, keyboard, overlay, or device-admin malware can deceive a user or observe input; users must remove it at the OS level. |
| Rooted or bootloader-unlocked device | Keystore status is shown but never assumed to be StrongBox; rooting is not treated as a supported trusted state. | A kernel-level adversary can inspect memory or instrument the process. Hasilan Pass cannot make a rooted device safe. |
| Compromised WebView | Crypto, cache parsing, URI matching, TOTP generation, and passkey signing remain in Rust. The WebView does not receive a decrypted cache file or persisted tokens. | A compromised renderer while the app is unlocked can still ask the native command boundary for user-authorized actions; lock immediately and update/reinstall. |
| Malicious website | Web pages cannot invoke this Android provider directly. Browser delegated origins must be verified by `CallingAppInfo`; native callers require matching DAL. | A valid but malicious relying party can request only its own origin's credential, so users must inspect the system selector and relying-party name. |
| Autofill phishing | The Autofill service validates browser signatures or app/domain/certificate DAL before even exposing an unlock action, then Rust applies URI matching and collection policy. | A compromised trusted browser or a genuine lookalike domain can still mislead the user outside the exact origin boundary. |
| Clipboard leakage | Copy is explicit and clears the unchanged value according to the device policy. | Clipboard managers, keyboards, and the OS may read a copied value before expiry; prefer Autofill/passkeys. |
| Screenshot/recording leakage | `FLAG_SECURE` covers vault, Autofill, provider, save, and camera Activities. | Rooted devices, external cameras, and OS/vendor vulnerabilities are outside this flag's guarantee. |
| ADB/debugging | Release builds are non-debuggable/minified; secrets and QR payloads must not be logged. Debug artifacts are for isolated test data only. | A user who enables debugging on a compromised device expands the local attack surface. |
| Local encrypted-cache theft | The cache is bounded authenticated Rust ciphertext; refresh/device values use Keystore wrapping. | A weak master password or a future cryptographic break can make copied ciphertext attackable. |
| Attachment staging theft | Upload/download staging stays in app-private cache for the minimum operation duration, is bounded, and is removed on completion/failure/restart. | Flash storage does not guarantee physical erase; a rooted device can inspect temporary plaintext and a user-selected downloaded file is outside the vault cache. |
| Keystore compromise | Separate storage and biometric aliases prefer StrongBox and fail closed on invalidation. | Hardware/firmware compromise or a trusted execution environment exploit can defeat platform protections. |
| Biometric bypass | Only `BIOMETRIC_STRONG` is accepted, with no reuse window, and enrollment changes invalidate the envelope. | A platform biometric false accept or coercion is possible; disable biometric unlock and use the master password if this is unacceptable. |
| Malicious intent/deep link | The native allowlist accepts only fixed non-secret actions and rejects parameters; verified HTTPS links are deployment-host bound. | The user can still be socially engineered to open the app; no link is treated as authorization. |
