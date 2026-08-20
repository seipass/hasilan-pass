#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wasm_path="${repo_root}/target/wasm32-unknown-unknown/release/hasilan_wasm.wasm"
web_output_dir="${repo_root}/web/src/generated"
extension_output_dir="${repo_root}/extension/src/generated"

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "wasm-bindgen-cli 0.2.127 is required (cargo install wasm-bindgen-cli --version 0.2.127 --locked)." >&2
  exit 1
fi

cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --package hasilan-wasm \
  --target wasm32-unknown-unknown \
  --release

mkdir -p "${web_output_dir}" "${extension_output_dir}"
wasm-bindgen \
  --target web \
  --out-dir "${web_output_dir}" \
  --out-name hasilan_wasm \
  "${wasm_path}"

wasm-bindgen \
  --target web \
  --out-dir "${extension_output_dir}" \
  --out-name hasilan_wasm \
  "${wasm_path}"
