# M7.4 — Signed and versioned signature distribution

## Goal

M7.4 defines a deterministic, fail-closed distribution format for AAA signature databases produced by the already-qualified M7.0–M7.3 pipeline. The milestone adds versioned release metadata, cryptographic authenticity, integrity verification and an explicit install/update boundary without weakening promotion, corpus or export rules.

M7.4 does **not** create trust in an unqualified signature. It only transports already-promoted/generated signature material with verifiable provenance.

## Status

**Foundation / implementation in progress.**

M7.4 starts from the M7.3 code-qualified closure HEAD. No signed distribution format is considered production-qualified until the contracts below are implemented and exercised in CI.

## Trust model

M7.4 is fail-closed and offline-verifiable:

- private signing keys are never committed to Git or embedded in release artifacts;
- verification uses explicitly trusted public keys;
- every distributed payload is bound by SHA-256 and byte size;
- the release manifest itself is signed;
- verification covers the exact canonical manifest bytes, not a reparsed semantic approximation;
- an unknown key, malformed signature, changed payload, missing payload or metadata mismatch fails verification;
- signature verification never silently falls back to unsigned mode;
- installation remains an explicit action after verification;
- existing generated databases are not modified in place until the replacement bundle has fully verified.

HTTPS may be used as a transport, but transport security is not a substitute for artifact signature verification.

## Cryptographic profile

The initial M7.4 signing profile is intentionally narrow:

- algorithm: Ed25519;
- public keys: raw 32-byte Ed25519 public keys encoded as lowercase hexadecimal for configuration/metadata;
- signatures: raw 64-byte Ed25519 signatures encoded as lowercase hexadecimal;
- key ID: lowercase SHA-256 of the raw public key bytes;
- digest algorithm for payload identity: SHA-256;
- no algorithm negotiation in schema v1;
- no X.509/PKI dependency;
- no private-key generation or custody inside AAA runtime code.

A future algorithm migration requires a new schema/versioned contract rather than silently changing schema-v1 semantics.

## Distribution bundle

A release bundle is a directory or archive containing a canonical manifest plus the exact payload files named by that manifest.

The initial logical layout is:

```text
manifest.json
manifest.sig
aaa/bootblocks.json
clamav/aaa.hsb
```

Only payloads that actually exist in the release are listed. Additional future payload kinds require explicit schema support and validation.

The manifest and signature are metadata. Signature database payloads remain the products of the qualified export pipeline.

## Version contract

Each bundle has an immutable release version.

Schema v1 uses a SemVer-style version string:

```text
MAJOR.MINOR.PATCH
```

with non-negative decimal components and no implicit normalization. Leading zeros are forbidden except for the single digit `0`.

Version comparison is numeric by component. A verifier/installer must not treat lexical string order as version order.

The manifest also records a UTC creation timestamp. Time is descriptive metadata; version is the update-order identity.

Downgrade behavior is explicit:

- normal install/update refuses a version lower than the currently installed version;
- reinstall of the identical version is allowed only when the manifest identity is byte-identical;
- a future explicit recovery/rollback command may override downgrade refusal, but M7.4 does not make rollback implicit.

## Manifest schema

Schema v1 manifest contains at least:

- schema version;
- release version;
- UTC creation timestamp;
- signer key ID;
- deterministic list of payload entries.

Each payload entry contains:

- logical target/name;
- relative path;
- SHA-256;
- byte size.

Payload paths must be relative, slash-separated and traversal-safe. Absolute paths, empty segments, `.` segments and `..` segments are rejected. Duplicate logical targets, duplicate paths or duplicate payload identities that create ambiguity fail validation.

The manifest has one canonical JSON representation used for both identity and signing. Canonicalization must be deterministic and covered by tests.

## Manifest identity and signature

The manifest identity is the SHA-256 of the exact canonical manifest bytes.

`manifest.sig` represents an Ed25519 signature over those exact canonical bytes.

Verification order is fail-closed:

1. decode and structurally validate manifest metadata;
2. canonicalize the manifest and bind verification to those exact bytes;
3. resolve the declared signer key ID against the trusted key set;
4. verify the Ed25519 signature;
5. verify every payload exists as a regular file;
6. verify exact byte size and SHA-256 for every payload;
7. reject unexpected install targets or path escape;
8. only then mark the bundle verified/eligible for installation.

A valid signature with invalid payload hashes is a failed bundle. Valid payload hashes with an invalid signature are also a failed bundle.

## Trusted public keys

AAA must distinguish trust configuration from release metadata.

The bundle may declare only a key ID; it cannot introduce trust in its own signer.

Trusted public keys are supplied independently, initially via explicit local configuration/file input. The verifier must:

- reject malformed public keys;
- derive and verify the key ID from the raw public key;
- reject duplicate key IDs with different key material;
- reject a bundle signed by an unknown key.

Key rotation is later work unless an explicit multi-key trust configuration is implemented and qualified within this milestone. Schema v1 must not silently trust a replacement key merely because the old key signed metadata that mentions it.

## Build/sign boundary

Private signing is deliberately separated from normal appliance verification.

M7.4 code may provide a deterministic signing utility that accepts a private key through an explicit local file/descriptor input, but:

- no private key is stored under `/data/aaa/signatures` by default;
- no private key is generated automatically;
- no private key appears in logs, JSON output or GitHub Actions fixtures;
- CI uses ephemeral synthetic Ed25519 keys generated only inside tests;
- production key custody remains an operational/release responsibility outside the appliance repository.

## Installation/update contract

Verified bundles install into a versioned staging location before activation.

A safe logical model is:

```text
/data/aaa/signatures/distributions/<version>/
/data/aaa/signatures/current.json
```

The exact on-disk layout may evolve during implementation, but activation must remain atomic from the consumer's perspective.

The installer must:

- verify before writing active state;
- never partially activate a bundle;
- preserve the previous active version until the new version is completely staged and verified;
- record active release version and manifest identity;
- reject a different manifest reusing an already-installed version;
- refuse downgrade by default;
- make repeated installation of the exact same verified bundle idempotent.

## CLI direction

The intended explicit CLI surface is:

```text
aaa signatures bundle build --version <version> --output <dir>
aaa signatures bundle sign --private-key <file> <dir>
aaa signatures bundle verify --trusted-key <file> <dir>
aaa signatures bundle install --trusted-key <file> <dir>
```

Final flag names may be refined during implementation, but the trust boundaries must not be weakened: build does not imply sign, verify does not imply install, and unsigned install is not permitted.

Network fetching is not required for the first M7.4 implementation. A later fetch/update command may download a bundle, but it must feed the exact same verifier before activation.

## CI qualification strategy

CI must use only synthetic generated signature payloads and ephemeral test keys. Tests must cover at least:

- canonical manifest bytes and deterministic manifest SHA-256;
- strict version parsing/comparison;
- deterministic payload ordering;
- safe relative path validation;
- Ed25519 sign/verify success;
- unknown signer rejection;
- wrong key rejection;
- changed manifest rejection;
- changed payload rejection;
- size mismatch rejection;
- missing payload rejection;
- malformed signature rejection;
- malformed/incorrect key ID rejection;
- same-version different-manifest rejection;
- default downgrade rejection;
- idempotent reinstall of the identical bundle;
- atomic activation behavior;
- no private-key material appearing in generated public metadata;
- linux/amd64 and linux/arm64 builds remain green.

## Planned implementation slices

### M7.4a — Versioned canonical release manifest

Implement strict release-version parsing, manifest/payload structs, safe relative-path rules, deterministic canonical serialization and manifest identity. No signing or installation yet.

### M7.4b — Ed25519 signing and trusted-key verification

Implement the fixed schema-v1 Ed25519 profile, key-ID derivation, strict signature decoding and fail-closed trusted-key verification using synthetic test keys.

### M7.4c — Bundle payload verification

Bind signed manifest entries to exact regular-file payload size/SHA-256 and reject missing, changed, escaped or ambiguous payloads.

### M7.4d — Atomic install/update state

Stage verified bundles, enforce version/downgrade/same-version conflict rules and atomically activate a verified distribution while preserving the previous active version.

### M7.4e — CLI and qualification

Expose explicit build/sign/verify/install commands, qualify the full mechanics in CI and record the exact green HEAD. Real production signing-key custody and release operations remain separately documented operational work.

## Non-goals

M7.4 does not:

- weaken M7.0–M7.3 promotion or corpus gates;
- auto-promote signatures;
- create or commit real malware samples;
- commit production private keys;
- use TOFU as the default trust model;
- make HTTPS alone sufficient authenticity proof;
- implement a public transparency log;
- implement TUF/Sigstore/X.509 PKI in schema v1;
- automatically rotate trust roots;
- require network access;
- claim real-corpus qualification;
- complete M8 historical Amiga scanner runtime qualification;
- complete Orange Pi runtime qualification.

## Exit criteria

M7.4 can be called **code-qualified** only when canonical versioned manifests, Ed25519 signing/trusted-key verification, exact payload verification, fail-closed atomic install/update semantics and the explicit CLI are implemented and the qualification record identifies an exact green CI HEAD.

Production release readiness additionally requires a documented real signing-key custody/rotation procedure and at least one intentionally signed release bundle. Code qualification with synthetic CI keys is not a claim that production key operations have been qualified.
