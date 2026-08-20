#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

dangerous_dom_pattern='innerHTML|outerHTML|insertAdjacentHTML|document\.write|(^|[^[:alnum:]_])eval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\('
if rg --line-number --glob '*.{ts,tsx,js,jsx}' "$dangerous_dom_pattern" web/src extension/src desktop/src; then
  echo "frontend security lint rejected a raw HTML or dynamic-code sink" >&2
  exit 1
fi

node <<'NODE'
const { readFileSync } = require("node:fs");
const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const requiredHosts = manifest.host_permissions ?? [];
if (requiredHosts.some((host) => host.includes("*"))) {
  throw new Error("extension wildcard hosts must remain optional and user-granted");
}
const optionalHosts = manifest.optional_host_permissions ?? [];
const allowedOptionalHosts = new Set(["http://*/*", "https://*/*"]);
if (optionalHosts.some((host) => !allowedOptionalHosts.has(host))) {
  throw new Error("extension optional host permissions exceeded the reviewed HTTP(S) set");
}
const csp = manifest.content_security_policy?.extension_pages ?? "";
if (!csp.includes("script-src 'self'") || csp.includes("'unsafe-eval'") || !csp.includes("object-src 'none'")) {
  throw new Error("extension CSP no longer enforces local scripts and disabled objects");
}
NODE

pnpm --recursive --if-present check

