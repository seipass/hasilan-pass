# Android Autofill

Hasilan Pass implements `AutofillService` on Android 8.0 (API 26) and later. It consumes only the
Android-provided `AssistStructure`; it does not inspect another app's webview, accessibility tree,
or disk.

## Trust gate

No vault title, username, password, or TOTP is returned until the request identity is verified.

1. The service extracts candidate username, password, and one-time-code field IDs plus an optional
   HTTPS `webDomain` and requesting package name.
2. A web request is accepted when the requesting browser's installed signing certificate matches
   Google's public privileged-browser allowlist. The browser-provided HTTPS origin is then used.
3. A native request that supplies a web domain is accepted only when
   `https://host/.well-known/assetlinks.json` contains the exact package and installed SHA-256
   signing certificate with the relation
   `delegate_permission/common.get_login_creds`.
4. A native request without a web domain is accepted on API 31+ only after Android's
   `DomainVerificationManager` says the app-link domain is verified *and* that domain's Asset
   Links statement contains the same `get_login_creds` relation. Android 8--11 native requests
   without a web domain fail closed because this verifier cannot establish the equivalent
   domain-to-app relationship on those versions.

Asset Links downloads are HTTPS-only, reject redirects, use short timeouts, and cap response size.
The service repeats the complete verification against the authentication Activity's fresh
`AssistStructure` before it prompts for biometrics. Saving repeats verification after the user's
save confirmation.

## Fill and save sequence

The verified service response shows only a generic **Unlock Hasilan Pass** affordance. Selecting
it launches a non-exported, screen-protected Activity. After a fresh `BIOMETRIC_STRONG` prompt it
opens the shared encrypted cache, asks Rust for URI-matched records for each verified origin,
builds at most 50 datasets, locks the Rust coordinator, and sends the dataset to Android.

The shared URI matcher applies the item URI match mode, deleted-item filtering, HTTPS downgrade
protection, and organization collection `hide_passwords` policy. A current TOTP value is generated
in shared Rust only after authentication and is placed only in one-time-code fields. It is never
precomputed or retained by the Android service.

Android's save request is separate. The user sees a save confirmation and a biometric prompt, then
the Login is written to the local encrypted cache and queued through the normal encrypted sync
outbox. API 26--27 cannot return an authenticated `SaveCallback` intent sender, so Hasilan Pass
does not save a secret there rather than skipping biometric confirmation.

## Setup and test matrix

Enable **Hasilan Pass** in Android Settings → Passwords, passkeys & accounts → Autofill service.
Test at minimum:

- signed Chrome/Firefox web forms with exact, host, and domain URI modes;
- an Android app whose verified App Link and `assetlinks.json` contain `get_login_creds`;
- a spoofed package/domain, untrusted browser, stale Asset Links statement, and cancelled prompt
  (each must show no credential selector);
- username/password, OTP-only, and mixed forms; hidden-password organization collections;
- explicit save while offline, process recreation, then reconnect/outbox synchronization.

The pure parsers for candidate JSON and Asset Links relation/package/certificate matching have JVM
unit tests. Full service flows, Android package signature states, and form behavior require an
instrumented device/browser matrix because `AssistStructure` is issued by the Android framework.
