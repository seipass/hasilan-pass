# Fuzzing

The fuzz package is deliberately outside the production workspace. It covers four
untrusted-input boundaries independently:

- `bitwarden_import`: bounded plaintext Bitwarden JSON import and canonical re-export;
- `vault_json`: decrypted private vault-item JSON parsing and serialization;
- `protocol_json`: versioned API request, response, encrypted-object, attachment, and
  organization DTO decoding;
- `uri_match`: URL parsing, public-suffix matching, normalization, and bounded regexes.

Install nightly Rust and cargo-fuzz, then run one target or the full smoke loop:

```console
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run bitwarden_import fuzz/corpus/bitwarden_import
cargo +nightly fuzz run vault_json fuzz/corpus/vault_json
cargo +nightly fuzz run protocol_json fuzz/corpus/protocol_json
cargo +nightly fuzz run uri_match fuzz/corpus/uri_match
```

Do not add real vault exports to a corpus or crash artifact. Minimize synthetic crash
inputs before reporting them. CI compiles every target and gives each a short smoke run;
long-running campaigns belong on a dedicated machine with sanitizers enabled by
`cargo-fuzz`.

