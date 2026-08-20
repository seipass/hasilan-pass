# Android passkeys and Credential Manager

On Android 14 (API 34) and later Hasilan Pass declares a Credential Manager provider for password
and public-key credentials. The provider uses the shared Rust encrypted cache and passkey model;
Kotlin only translates Android requests/responses and presents system UI.

## Provider flow

1. Android asks the provider for candidate entries. Entries contain non-secret display metadata
   only.
2. Choosing a password or passkey opens a screen-protected, non-exported Activity and requires a
   fresh `BIOMETRIC_STRONG` prompt.
3. The Activity verifies a browser-delegated HTTPS origin with Android `CallingAppInfo` and the
   signed privileged-browser allowlist. For a direct native caller, it uses `https://rpId` only
   after that RP host's Digital Asset Links statement delegates `get_login_creds` to the calling
   installed package and signing certificate. It never treats an unverified RP ID as an origin.
4. Rust validates the RP ID/origin, allow/exclude credential IDs, discoverability, and user
   verification, then creates the WebAuthn assertion or credential creation result. The native
   coordinator is locked immediately after the response.

Passkeys created by this provider are software-authenticator credentials encrypted inside the
shared vault. They are not represented as hardware-bound private keys, so the UI and release notes
must not claim device-bound or sync-provider attestation.

## Account passkeys

Account passkeys are separate from passkeys stored in Login items. On Android, the lock screen
offers **Use account passkey**. It starts the existing server-side passwordless WebAuthn ceremony,
passes the server-generated public-key options to Android Credential Manager, then sends the
unmodified Credential Manager response to the existing `/auth/webauthn/finish` endpoint.

Server authentication returns the usual protected user key and session tokens. The Android client
still asks for the master password and performs the KDF/unwrapping in Rust locally: an account
passkey authenticates the account but deliberately is not a replacement for the password-derived
zero-knowledge vault unlock key. The password never appears in the passkey HTTP request.

While unlocked, **Settings → Account security** can register, list, and remove account passkeys.
Registration requires a fresh locally-derived reauthentication proof, invokes Credential Manager
to create the credential, and finishes the server's existing account-WebAuthn registration
ceremony. It shares TOTP, recovery-code, session, and trusted-device management with every other
first-party client.

Credential Manager generates Android client data with an opaque origin of the form
`android:apk-key-hash:<base64url-sha256-signing-certificate>`. A deployment must explicitly add
that exact value to `HP_WEBAUTHN_ADDITIONAL_ORIGINS`; a package name alone is never sufficient.
The server validates the value as a 32-byte base64url certificate digest and `webauthn-rs` requires
an exact allowed-origin match. For a release artifact signed with a deployment key, derive it with:

```bash
keytool -exportcert -alias "$HP_ANDROID_KEY_ALIAS" -keystore "$HP_ANDROID_KEYSTORE" \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '='
```

For example, append `android:apk-key-hash:<result>` (comma-separated) to the server environment
before registering or using the account passkey. A debug, Play App Signing, or enterprise signing
certificate has a different digest and must be opted in separately. Do not place a certificate
digest in the app source as a server allowlist substitute.

## Scope and limits

Browser-delegated relying-party passkeys require Android to confirm the calling browser's package
and signing certificate. Direct native-app public-key requests require an HTTPS, bounded,
non-redirected `assetlinks.json` statement for the requested RP host with
`delegate_permission/common.get_login_creds`, the exact calling package, and a SHA-256 certificate
fingerprint of the installed caller. A missing, stale, malformed, or mismatched statement fails
closed before a signature or new credential is created.

The Android Credential Provider is available on Android 14 (API 34)+. On older supported Android
versions the app continues to provide username/password Autofill; Android Credential Manager
consumer behavior depends on the device's installed Credential Manager implementation. Account
passkey registration/login, provider selection, and browser/direct-app relying-party ceremonies
must be validated on the target physical device before release. A cancelled provider or
Credential Manager prompt emits no partial credential and locks the native coordinator.

## Device test requirements

Use a physical API 34+ device with a Class 3 biometric and an installed supported browser. Test
account-passkey registration, passwordless account authentication plus local master-password
unlock, an unconfigured Android certificate origin rejection, password selection, discoverable
passkey assertion, passkey creation into an existing matching Login, cancelled biometric prompts,
wrong RP ID, modified allow/exclude lists, an invalid browser signature, and a native app with
both valid and invalid `get_login_creds` Asset Links statements.
