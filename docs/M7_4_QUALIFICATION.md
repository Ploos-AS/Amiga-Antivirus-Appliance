# M7.4 qualification — signed signature distribution

Status: **CODE-QUALIFIED**

M7.4 defines and implements a deterministic, fail-closed signed distribution path for signature material produced by M7.0–M7.3.

## Qualified scope

- **M7.4a — canonical release manifest**
  - strict schema and validation
  - deterministic canonical encoding
  - semantic release version validation/comparison
  - payload metadata with exact SHA-256 and size
- **M7.4b — Ed25519 signing and trust**
  - Ed25519 signatures only for schema v1
  - independently supplied trusted public keys
  - key IDs derived from SHA-256 of raw public keys
  - unknown signers, malformed keys/signatures, and modified manifests fail closed
  - private keys are not generated or persisted by the production trust API
- **M7.4c — bundle verification**
  - strict canonical manifest verification
  - signature verification before payload acceptance
  - every declared payload must be a regular file with exact size and SHA-256
  - unsafe paths and symlink components are rejected
- **M7.4d — atomic install/update state**
  - bundles are verified before persistent installation
  - staged copies are verified again before activation
  - active state is updated atomically only after successful verification
  - downgrade is rejected by default
  - reuse of a version with a different manifest identity is rejected
  - exact same-version reinstall is idempotent
  - previous active state is preserved until the replacement is ready
- **M7.4e — CLI and release workflow**
  - `aaa signatures bundle build --version <version> --output <dir>`
  - `aaa signatures bundle sign --private-key <file> <dir>`
  - `aaa signatures bundle verify --trusted-key <file> <dir>`
  - `aaa signatures bundle install --trusted-key <file> <dir>`
  - build and signing remain separate operations
  - verification and installation remain separate operations
  - unsigned/untrusted installation has no fallback path

## Distribution contract

The logical bundle is:

```text
manifest.json
manifest.sig
aaa/bootblocks.json
clamav/aaa.hsb
```

Installed versions live below:

```text
/data/aaa/signatures/distributions/<version>/
```

The active distribution state is recorded in:

```text
/data/aaa/signatures/current.json
```

The manifest identity is the SHA-256 of its exact canonical bytes.

## Security properties qualified in code

The implementation is intentionally fail closed. A bundle is not accepted when its manifest is malformed or non-canonical, its signer is unknown, its signature is invalid, a payload is missing or changed, payload metadata disagrees with the file, an install path is unsafe, the release is a downgrade, or an installed version is reused with a different manifest identity.

Private signing keys are not bundle artifacts and are not stored under `/data/aaa/signatures`. Tests use ephemeral synthetic Ed25519 keys in memory.

## CI evidence

The final M7.4e implementation HEAD before this qualification document is:

```text
bae9a15fda645dc0f7c825a536083afe97117135
```

GitHub Actions CI run **#220** completed successfully for that HEAD.

The qualification-document commit must itself pass the repository CI before M7.4 is considered finally closed on `main`.

## Qualification boundary

**CODE-QUALIFIED** means the repository implementation, tests, formatting, vetting, and supported architecture builds are qualified by CI.

This does not claim field qualification of signing-key custody, release-operator procedures, network distribution infrastructure, or Orange Pi Zero 3/DietPi runtime behavior. Those remain operational/runtime qualification work.

## Result

M7.4 is complete at the code level once CI for this closing commit is green. The repository then has a complete deterministic path from promoted M7 signature material to a signed, verified, versioned and atomically activated distribution bundle.
