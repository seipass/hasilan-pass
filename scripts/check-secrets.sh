#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

secret_pattern='-----BEGIN (OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----|A(KIA|SIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-(proj-)?[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{30,}|HP_(TOKEN_PEPPER|MFA_ENCRYPTION_KEY)=[A-Za-z0-9_-]{43}'
synthetic_fixture='tests/fixtures/bitwarden/plain.json'
synthetic_fixture_sha256='c39c62c1f091b26926ac7a20345d4e3ea8025ea3b863153cc57b0b7e4cd40d7e'

# The compatibility fixture deliberately contains an inert OpenSSH PEM marker. Pin the
# complete file before excluding it so a real key cannot be hidden behind this exception.
actual_fixture_sha256=$(sha256sum "$synthetic_fixture" | awk '{print $1}')
if [[ $actual_fixture_sha256 != "$synthetic_fixture_sha256" ]]; then
  echo "synthetic Bitwarden fixture changed; review it and update the pinned hash intentionally" >&2
  exit 1
fi

mapfile -t suspect_files < <(
  rg --files-with-matches --hidden --no-ignore-vcs \
    --glob '!.git/**' \
    --glob '!target/**' \
    --glob '!fuzz/target/**' \
    --glob '!node_modules/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/dist/**' \
    --glob '!scripts/check-secrets.sh' \
    --glob "!$synthetic_fixture" \
    -- "$secret_pattern" . || true
)

if (( ${#suspect_files[@]} > 0 )); then
  echo "high-confidence secret patterns found in:" >&2
  printf '  %s\n' "${suspect_files[@]}" >&2
  echo "matching contents were deliberately not printed" >&2
  exit 1
fi

echo "no high-confidence committed-secret patterns found"
