# Browser extension

Hasilan Pass ships a standalone Manifest V3 extension for Chromium and Firefox. It uses the same Rust/WASM cryptographic and vault core as the Web Vault; it does not embed or depend on the Web Vault UI.

## Security boundaries

- The master password, account key, item keys, access token, and refresh token live only in the extension background runtime's memory. Suspending a Chromium service worker therefore locks the extension instead of persisting key material.
- `storage.local` contains only the server URL, account email, a random device identifier, and opaque encrypted sync objects. IndexedDB is scoped by server and account ID.
- Server and website access are optional host permissions requested by a direct user action. The checked-in manifest has no always-on wildcard host access.
- Dynamically registered content scripts receive only secret-free matching summaries. A fill action requests one credential by ID; the background runtime repeats the URL-match check before releasing it.
- Content messages must originate from an HTTP(S) tab and claim the exact sender-frame URL. Fragments are ignored; the saved URI policy is still enforced by the Rust vault core.
- Autofill follows composed focus and keyboard events into page-owned open shadow roots and observes their form submissions without traversing closed page roots. Every iframe performs its own URL-matched background request; a child frame cannot reuse its parent's match.
- Submitted credentials remain in background memory for at most two minutes and are saved or used to update an existing item only after explicit confirmation in the extension UI.
- Menu content is created with DOM APIs and inert `textContent` inside a closed shadow root. No remote scripts, remote WASM, or `eval` are used.

Autofill necessarily places a credential in page DOM inputs. JavaScript running on that page can observe the resulting value, so users should enable and invoke autofill only on sites they trust. The isolated content-script world protects extension state, not a value intentionally disclosed to the page.

## Permissions

| Permission | Purpose |
| --- | --- |
| `storage` | Non-secret settings and the encrypted local cache |
| `scripting` | Register the packaged content script for user-approved origins |
| `activeTab` | One-time interaction with the page selected by the user |
| `alarms` | Enforce the inactivity lock without a long-running timer |
| `contextMenus` | Open the credential chooser on demand |
| `clipboardWrite` | Copy a selected secret and attempt to clear it after 30 seconds |
| Optional HTTP(S) hosts | Connect to the chosen server or enable autofill for a chosen site |

The implementation follows the browser vendors' guidance for [optional host permissions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/optional_host_permissions), [dynamic content-script registration](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/scripting/registerContentScripts), and [Manifest V3 remote-code restrictions](https://developer.chrome.com/docs/extensions/develop/migrate/improve-security). Both `background.scripts` and `background.service_worker` are declared in the cross-browser source manifest because [Firefox still uses background scripts while Chromium uses a service worker](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background). The Firefox packaging step removes the ignored service-worker key from its generated manifest.

Firefox 140+ on desktop (142+ on Android) displays its built-in data-transmission consent at install time. Hasilan declares authentication data, saved-site URLs, payment data, and identifying data because encrypted vault sync moves those categories between the browser and the server selected by the user. It does not declare telemetry because the extension sends none. These disclosures follow Mozilla's current [data collection and transmission taxonomy](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/).

## Build and load

```bash
pnpm install
pnpm build:extension
```

Load `extension/dist` as an unpacked extension from `chrome://extensions` with Developer mode enabled, or as a temporary add-on from `about:debugging` in Firefox. The server must use HTTPS except for `localhost`, `127.0.0.1`, or `[::1]` development URLs.

Run the unit and production-build checks with:

```bash
pnpm --filter @hasilan/browser-extension test
pnpm --filter @hasilan/browser-extension check
pnpm --filter @hasilan/browser-extension lint:firefox
pnpm --filter @hasilan/browser-extension package:firefox
```

The Playwright journey requires a running Hasilan API and a Playwright Chromium install. It copies the production bundle to its isolated output directory and grants local test hosts only in that disposable copy; it never broadens the product manifest.

```bash
HP_E2E_API_URL=http://127.0.0.1:18080 \
  pnpm --filter @hasilan/browser-extension test:e2e
```

The journey covers account creation, encrypted object upload, per-origin script registration, keyboard autofill, submission capture, confirmed password update, re-encryption, and session revocation. Its hostile-page fixture exercises an open shadow-root form, same- and cross-origin frames, closed-menu isolation, and forged frame URL claims. It also asserts that the master password, username, and item passwords never occur in API request bodies.

`web-ext lint` currently reports two `innerHTML` warnings inside the bundled React DOM renderer. Hasilan source never calls `innerHTML` or `dangerouslySetInnerHTML`; user- and server-controlled strings are passed as React text children. The warnings are retained in lint output for reviewer visibility rather than hidden with an ignore rule.
