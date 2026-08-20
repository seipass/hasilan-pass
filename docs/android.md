# Android client

Status: Android native client, Autofill, Credential Manager provider, account passkey
enrollment/login, QR TOTP capture, signed-release automation, and Android device smoke testing
are complete. A production signing-key ceremony and deployment-specific browser/provider matrix
remain release-owned checks, 2026-08-20.

## Architecture and trust boundary

The Android application is a Tauri 2 shell with the existing `hasilan-desktop-core`
crate behind it. It does not implement another vault, KDF, crypto format, sync engine,
or passkey store in Kotlin. Login, offline cache opening, encrypted mutations, matching,
TOTP, passkey creation/assertion, and the outbox stay in the shared Rust core.

The main app uses an `AndroidSecretStore`: opaque refresh/device values are wrapped with
an Android Keystore AES-GCM key. The offline cache remains the same authenticated Rust
ciphertext document as desktop. Android system services can be started without a Tauri
activity, so they open a short-lived Rust coordinator over that exact cache and never
persist a second vault, user key, access token, or network session. Once the activity is
running, system services use its exact shared Rust coordinator, preventing a service-side
save from being hidden by a stale foreground cache. A system-service save queues the normal
encrypted outbox mutation; the app synchronizes it at the next normal sync.

The app identifier is `org.hasilan.pass`; the minimum API level is 24, Android Autofill
is available on API 26+, and the Credential Manager provider is available on Android 14
(API 34)+. The target and compile SDK are 36. This was checked against Android's July 2026
[Google Play target-API requirement](https://developer.android.com/google/play/requirements/target-sdk):
new mobile uploads must target API 36 from 31 August 2026. The provider's API-34 boundary follows
the official [Credential Provider integration guide](https://developer.android.com/identity/sign-in/credential-provider).

## Device security

- The main activity, Autofill authentication/save activities, Credential Manager
  activities, and QR camera view use `FLAG_SECURE`.
- Android backup and device-transfer rules exclude the entire application root.
- An Android Keystore key encrypts local secret-store values. New aliases prefer StrongBox where
  supported; the settings screen reports available and actual hardware/StrongBox protection. A separate
  Keystore key requires `BIOMETRIC_STRONG`, is invalidated by biometric enrollment, and
  wraps only the Rust user key needed for offline unlock.
- The UI lets a user enable or remove biometric unlock. It is never enabled merely by
  logging in. Every Autofill, save, password-provider, passkey assertion, and passkey
  creation route displays a fresh biometric prompt.
- The native clipboard clears the secret after 30 seconds by default only when the clipboard still
  contains Hasilan Pass's original value. Users can select 15/30/60/120 seconds or disable
  automatic clearing for this device.
- Locking or backgrounding drops decrypted items, keys, access session, and detail state.
- Android predictive Back uses a non-secret WebView history entry while an item editor is open,
  so the first gesture dismisses that editor. It does not place item names or fields in browser
  history; when no in-app editor is open, Back follows normal Android activity behavior.

## Autofill and Credential Manager

`HasilanAutofillService` parses only the system-provided `AssistStructure`. It verifies a
browser package/signing certificate or an app/domain/certificate Digital Asset Links relationship
*before* it returns an unlock affordance. The shared `uri_matches` routine enforces URI match
modes, HTTPS downgrade protection, deleted-item filtering, and organization collection
password-hiding policy. The service first returns a system authentication response; only after a
biometric unlock does it construct a dataset. Saving is a separate explicit system save flow and
is written locally encrypted before a later sync. See [Android Autofill](android-autofill.md).

On Android 14+, `HasilanCredentialProviderService` declares password and public-key
capabilities. It returns non-secret selector entries after unlock; selecting one causes
another biometric check before either a `PasswordCredential` or WebAuthn assertion is
returned. Passkey creation asks the user to choose a matching existing Login. The shared
Rust passkey layer validates RP-ID/origin scope, RP binding, allow/exclude lists, and
user-verification before generating or signing. This is a software authenticator; it
does not claim hardware-bound passkey private keys.

For passkeys delegated by a browser, the app fetches Google's published privileged-browser
allowlist over HTTPS and asks Android's `CallingAppInfo` to verify the caller's package and
signing certificate before it accepts the supplied HTTPS origin. It never replaces the origin
with the RP ID. A direct native-app passkey request is accepted only when the requested RP host's
Digital Asset Links statement delegates `get_login_creds` to the calling installed package and
signing certificate; otherwise it fails closed. The app never accepts an arbitrary webview
`postMessage` as a credential request. See [Android passkeys](android-passkeys.md) for the full
scope and release gate.

The account-security screen uses the existing server account API for TOTP enrollment/replacement,
recovery-code rotation, account-passkey enrollment/removal, session revocation, trusted-device
revocation, and device/session listing. The Android login surface can start the server's
passwordless account-passkey ceremony through Credential Manager, but still needs the master
password locally to unwrap the existing zero-knowledge vault key. To enable this on a deployment,
the operator must configure the release APK signing-certificate origin as described in
[Android passkeys](android-passkeys.md); no Android package is trusted automatically.

## Links and callbacks

`hasilan-pass://account/open`, `/verify-email`, `/invitation`, and `/passkey` are the only custom
scheme routes accepted by the native layer. They contain no accepted token or credential value;
the app emits only a non-secret action to its UI. Arbitrary hosts, ports, query parameters,
fragments, usernames, and passwords are rejected. This prevents an external app from turning a
deep link into an account operation.

For an HTTPS verified App Link, set `HP_ANDROID_APP_LINK_HOST` while building and publish the
matching `/.well-known/assetlinks.json` statement for `org.hasilan.pass` and the release signing
certificate. The manifest accepts `https://<host>/android/open`; its default host is invalid so a
generic self-hosted build does not claim someone else's domain. Server-side email and invitation
flows must perform their own authenticated token validation; the Android app never receives one
through this link route.

## TOTP QR import

The Android Login editor exposes **Scan QR**. It asks for `CAMERA` only after the user
taps that control, scans locally with CameraX and the bundled Apache-2.0 ZXing decoder, accepts only bounded
`otpauth://totp/...` payloads, and returns the value directly to the Login form. The
value is validated by the shared Rust `TotpConfig` when the Login is saved. No image or
QR payload is uploaded.

ZXing replaces Google ML Kit here, so the runtime dependency graph contains no Google Play
Services or Firebase artifacts. Google services are not required for login, sync, vault editing,
copying, TOTP, or QR import; Credential Manager is an Android 14+ operating-system capability,
not a Google Play Services dependency.

## Folders and item types

The Android UI can create, rename, browse, and delete personal folders; assignments are available
when editing Login, Secure Note, Card, and Identity items alongside private custom fields. Folder
labels are encrypted `Folder` objects in the same durable Rust outbox as item mutations, not
Android-only preferences. Deleting a folder clears the assignment on affected personal items and
keeps the encrypted items themselves. Organization-owned items cannot be placed in personal
folders.

## Attachments

The Android item view uses the system Storage Access Framework for attachment selection and
download destinations; it does not request broad storage permission. A selected file is copied to
an app-private cache staging directory (up to 1 GiB) only long enough for the shared Rust core to
derive attachment metadata, encrypt authenticated chunks, and use the existing upload/retry flow.
The staging file is best-effort overwritten and deleted after either success or failure.

For download, Rust authenticates and decrypts into a private temporary file first. Kotlin copies
that file only to the user-selected SAF URI, deletes a partially written destination where the
provider permits it, then best-effort overwrites and removes the private temporary file. Flash
storage cannot guarantee physical erasure; a user-selected download destination is necessarily
outside the vault's encrypted cache and remains under that provider's retention policy.

## Build and test

Install JDK 21, Android SDK platform/build-tools 36, NDK `27.3.13750724`, Rust 1.92,
and the `aarch64-linux-android` Rust target. Set `ANDROID_HOME` and `NDK_HOME`.

```bash
pnpm install --frozen-lockfile
rustup target add aarch64-linux-android
export PATH="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
pnpm --dir desktop tauri android build --debug --target aarch64 --apk --aab --ci
```

The debug APK/AAB are Android-debug-key signed for installation smoke tests. Before a
release, set all four values together and build without `--debug`:

```bash
export HP_ANDROID_KEYSTORE=/secure/path/hasilan-release.jks
export HP_ANDROID_KEYSTORE_PASSWORD='…'
export HP_ANDROID_KEY_ALIAS='…'
export HP_ANDROID_KEY_PASSWORD='…'
pnpm --dir desktop tauri android build --target aarch64 --apk --aab --ci
```

The Gradle build fails when only a subset of signing values is present. The protected
release workflow accepts the base64-encoded keystore as `ANDROID_KEYSTORE` plus the
corresponding `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and
`ANDROID_KEY_PASSWORD` secrets; it verifies APK and AAB signatures before attestation.
No release keystore or password belongs in the repository.

Run the checks used by CI:

```bash
cargo check --package hasilan-desktop --target aarch64-linux-android
cd desktop/src-tauri/gen/android
./gradlew :app:testUniversalDebugUnitTest :app:lintUniversalDebug :app:compileUniversalDebugAndroidTestKotlin
```

With an API 34+ emulator or physical device connected, run the concrete Android checks with:

```bash
./gradlew :app:connectedUniversalDebugAndroidTest
```

They verify a real Keystore round-trip, the absence of an explicitly cleared biometric envelope,
and the secure-window/lifecycle policy. They do not replace the physical Credential Manager,
Autofill, and offline-vault journey in the release checklist.

The `android` CI job first builds the shared Rust/JNI library through Tauri for `x86_64`, then
runs this instrumentation suite on an API 35 AOSP emulator. It is intentionally an AOSP image
rather than a Google Play image, so the device gate also guards against accidentally making
basic vault operation depend on Play Services. A physical API 34+ device remains required for
the release checklist's biometric enrollment, Autofill, and Credential Manager journeys.

## Release smoke checklist

1. Install the signed APK on a physical API 34+ device with a Class 3 biometric.
2. Login, enable biometric unlock, background the app, then confirm a fresh prompt is
   required to open the offline cache.
3. Enable Hasilan Pass in Android Autofill settings; test exact/host/domain matches,
   password-hidden collections, a cancelled prompt, and explicit save while offline.
4. Enable the Credential Manager provider; test password selection, discoverable browser and
   Digital-Asset-Links-verified native-app passkey assertion, and passkey creation for a matching
   saved Login. Confirm that an untrusted browser and an unverified native-app request fail closed.
5. Scan a valid and an invalid QR code, check camera permission denial/cancellation, and
   confirm no QR content appears in logs or network traffic.
6. Create a folder, save a Login, Secure Note, Card, and Identity with custom fields, then
   verify offline edits and folder deletion/reassignment synchronize after reconnect.
7. Upload and download a small attachment through the system picker; cancel both picker flows
   once and confirm the vault stays usable with no broad storage permission.
8. Confirm clipboard clearing, screenshot blocking, backup exclusion, lock, logout, and
   reconnect/outbox synchronization.

Useful upstream references: [Tauri Android distribution](https://v2.tauri.app/distribute/android/),
[Android Autofill](https://developer.android.com/identity/autofill), and
[Credential Manager provider integration](https://developer.android.com/identity/sign-in/credential-provider).
The Android-specific security boundary is documented in [Android security](android-security.md).
