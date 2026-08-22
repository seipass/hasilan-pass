#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

dangerous_dom_pattern='innerHTML|outerHTML|insertAdjacentHTML|document\.write|(^|[^[:alnum:]_])eval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\('
if command -v rg >/dev/null 2>&1; then
  if rg --line-number --glob '*.{ts,tsx,js,jsx}' "$dangerous_dom_pattern" web/src extension/src desktop/src; then
    echo "frontend security lint rejected a raw HTML or dynamic-code sink" >&2
    exit 1
  fi
elif grep -REn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' "$dangerous_dom_pattern" web/src extension/src desktop/src; then
  echo "frontend security lint rejected a raw HTML or dynamic-code sink" >&2
  exit 1
fi

node <<'NODE'
const { readFileSync } = require("node:fs");
const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const requiredHosts = new Set(manifest.host_permissions ?? []);
const expectedHosts = new Set(["http://*/*", "https://*/*"]);
if (requiredHosts.size !== expectedHosts.size || [...expectedHosts].some((host) => !requiredHosts.has(host))) {
  throw new Error("extension must declare only the reviewed HTTP(S) wildcard hosts for default autofill");
}
const optionalHosts = manifest.optional_host_permissions ?? [];
if (optionalHosts.length !== 0) {
  throw new Error("extension no longer needs optional host permissions when default autofill is enabled");
}
const csp = manifest.content_security_policy?.extension_pages ?? "";
if (!csp.includes("script-src 'self'") || csp.includes("'unsafe-eval'") || !csp.includes("object-src 'none'")) {
  throw new Error("extension CSP no longer enforces local scripts and disabled objects");
}
NODE

pnpm --recursive --if-present check
