# Accessibility and keyboard audit

Status: Web Vault keyboard and semantic audit completed for the implemented v1 flows,
2026-08-13. This is an engineering audit, not a third-party WCAG certification.

## Keyboard model

All Web Vault actions use native links, buttons, inputs, selects, textareas, and file
inputs; clickable `div`/`span` substitutes are prohibited. The vault search is the first
control in the main work area, categories and folders are buttons in labeled navigation,
and secrets can be revealed or copied without a pointer. Browser-native Tab and
Shift+Tab ordering follows DOM order.

Every modal:

- exposes `role="dialog"`, `aria-modal`, a unique accessible name, and an optional unique
  description;
- moves focus to the dialog container so its title and warning are announced without
  accidentally activating a destructive control;
- loops Tab from the last control to the close button and Shift+Tab back to the last
  control, including a safe no-action state;
- closes on Escape and returns focus to the still-connected opener;
- can also be dismissed by its explicitly labeled close button.

Global focus indicators are visible for keyboard navigation. Animation is disabled when
`prefers-reduced-motion: reduce` is set. Errors use `role="alert"`, loading and notice
regions use live-region semantics where state changes without navigation, password and
private-key fields are masked by default, and reveal controls carry explicit accessible
names.

## Automated evidence

`Dialog.test.tsx` checks accessible naming/description, initial focus, forward and reverse
focus containment, Escape, empty-dialog behavior, and focus restoration. Auth tests prove
untrusted server error text remains inert. The complete Web Playwright journey exercises
authentication, item editors for every typed item, folders, organizations, invitation
acceptance, and encrypted sharing using role/label locators; selector failures therefore
also catch many lost labels and semantic control regressions.

Frontend security lint rejects raw HTML and dynamic-code sinks and runs TypeScript checks
for all clients. CSS contains an explicit `:focus-visible` treatment and a reduced-motion
media query.

## Manual release checks

Before publishing a release, repeat the core Web journey with only the keyboard at 200%
browser zoom and with OS/browser reduced motion enabled. Confirm focus never disappears
behind a modal, the search/item list remain operable without horizontal page scrolling,
errors are announced once, masked values are not spoken before reveal, and TOTP countdown
updates do not continuously interrupt the screen reader.

Check one current Chromium screen reader combination and one current Firefox combination.
Color contrast should be remeasured whenever palette tokens change; do not infer WCAG
conformance solely from the current visual design. QR image decoding, native browser
WebAuthn prompts, and operating-system file pickers inherit platform accessibility and
must be included in manual platform testing.
