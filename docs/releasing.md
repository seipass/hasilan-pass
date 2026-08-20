# Release engineering

Status: automated candidate construction, native-signing gates, SPDX SBOMs, checksums,
and GitHub artifact attestations are implemented; a first protected tagged run and
independent security review are still required, 2026-08-13.

## What the workflows prove

The ordinary `CI` workflow compiles and tests the desktop application on Linux and
Windows. Linux also builds the native executable in the existing full desktop job. The
additional Windows platform job runs the TypeScript tests, native Rust tests, and a
complete Tauri `--no-bundle` build, then requires the expected platform executable to
exist. macOS is intentionally not scheduled by GitHub Actions.

The `Release candidate` workflow has two modes:

- a manual run builds unsigned/ad-hoc packages for packaging smoke tests; its desktop
  metadata says `unsigned-smoke` and it never creates a GitHub Release;
- a pushed `v*` tag is a publication candidate. It fails unless Windows Authenticode
  credentials are complete. It verifies the resulting native signatures, produces a
  draft GitHub Release, and never publishes that draft automatically.

Both modes build Linux `.deb`, `.rpm`, and `.AppImage` packages, Windows NSIS `.exe` and
MSI installers, a signed Android arm64-v8a APK/AAB, the Web Vault, Chromium and Firefox
extension ZIPs, and an x86-64 GNU/Linux server binary. macOS packaging is intentionally
outside this workflow. The server binary is built on Ubuntu 22.04 and ships with an
`ldd` runtime inventory; Docker Compose remains the recommended server delivery path
because the container owns its runtime dependencies.

Every build job creates GitHub OIDC/Sigstore SLSA provenance for its exact package
digests. Assembly generates an SPDX 2.3 JSON SBOM from the clean source plus staged
packages, creates a signed SBOM attestation, writes a sorted `SHA256SUMS`, and attests
that checksum index. The offline Sigstore bundles are included beside the packages.

## One-time protected environment setup

Create a GitHub environment named `release`. Require reviewers and restrict it to the
default branch for manual smoke runs plus the intended protected tags. Store signing
material in that environment, not in repository files, workflow inputs, build logs, or
local `.env` files.

Windows environment secrets:

- `WINDOWS_CERTIFICATE`: base64 of a code-signing `.pfx` with its private key;
- `WINDOWS_CERTIFICATE_PASSWORD`: the `.pfx` password.

Set the non-secret environment variable `WINDOWS_TIMESTAMP_URL` to the certificate
issuer's absolute HTTPS RFC 3161 timestamp endpoint. The workflow rejects partial
configuration, an expired certificate, a certificate without a private key, an insecure
timestamp URL, any package whose Authenticode status is not `Valid`, and any package
without a timestamp certificate. The imported certificate is deleted from the ephemeral
runner store at the end.

Android environment secrets:

- `ANDROID_KEYSTORE`: base64 of the Android release `.jks` / `.keystore` file;
- `ANDROID_KEYSTORE_PASSWORD`: the keystore password;
- `ANDROID_KEY_ALIAS`: the signing-key alias;
- `ANDROID_KEY_PASSWORD`: the signing-key password.

All four values are required for every release candidate, including a manual run. The
workflow materializes the keystore only in the runner temporary directory, configures the
Gradle `HP_ANDROID_*` values, builds an arm64-v8a APK and AAB, then verifies both package
signatures before provenance is recorded. Google Play upload, Play App Signing enrollment,
and store review remain deliberate maintainer actions.

Browser-store signing is intentionally separate. Firefox AMO and Chrome Web Store apply
their own upload/review/signing processes; a locally generated ZIP must not be described
as store-signed.

## Cut a candidate

First run the release workflow manually and inspect all platform artifacts. Complete the
manual platform checklist below. Update all versions together; the verifier compares the
Cargo workspace, root/Web/extension/desktop packages, extension manifest, and Tauri
configuration:

```console
pnpm verify:release-version
```

For version `0.1.0`, create a protected tag whose spelling exactly matches the version:

```console
git tag -s v0.1.0
git push origin v0.1.0
```

The workflow also requires the tagged commit to be on the repository's default branch.
After it succeeds, inspect the draft release, its platform metadata, signatures, SBOM,
attestations, and checksums. Publishing the draft is a deliberate maintainer action.

## Verify a downloaded candidate

Download all assets from the draft/release into one directory. `SHA256SUMS` deliberately
uses unique flat asset names because GitHub Release attachments do not retain source
directories:

```console
mkdir hasilan-pass-0.1.0
gh release download v0.1.0 --repo hasilan/hasilan-pass --dir hasilan-pass-0.1.0
cd hasilan-pass-0.1.0
sha256sum --check SHA256SUMS
```

Verify online provenance and bind it to this workflow and tag:

```console
gh attestation verify packages/hasilan-pass-0.1.0-chromium.zip \
  --repo hasilan/hasilan-pass \
  --signer-workflow hasilan/hasilan-pass/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0
```

The included bundle supports verification without fetching the attestation from the
GitHub API (the verifier still needs a trusted Sigstore root unless one is supplied):

```console
gh attestation verify packages/hasilan-pass-0.1.0-chromium.zip \
  --repo hasilan/hasilan-pass \
  --bundle metadata/hasilan-pass-0.1.0-portable-provenance.sigstore.json \
  --source-ref refs/tags/v0.1.0
```

To verify the SPDX assertion rather than the default SLSA predicate, add:

```console
--predicate-type https://spdx.dev/Document/v2.3 \
--bundle metadata/hasilan-pass-0.1.0-sbom-attestation.sigstore.json
```

On Windows, independently inspect installers with `Get-AuthenticodeSignature`. A
checksum or Sigstore provenance signature does not replace native OS trust.

## Manual platform release checklist

Before publishing, use clean supported Windows and Linux machines to:

1. install the package and launch the application through the normal OS launcher;
2. verify the displayed publisher/notarization identity and absence of trust warnings;
3. register or log in, unlock, create and edit a Login, and synchronize it with Web;
4. disable the network, unlock the encrypted cache, edit an item, reconnect, and flush
   the outbox;
5. exercise clipboard clearing, tray lock/quit, automatic lock, import/export warnings,
   attachment upload/download, and OS credential-store persistence;
6. uninstall normally and confirm that release notes describe whether encrypted local
   data is retained.

The workflow proves construction and signature properties, not interactive desktop
behavior. Installers and notarization contain timestamps and are not claimed to be
bit-for-bit reproducible. Published container digests, store-signed browser packages,
and an independent security assessment remain separate release gates.
