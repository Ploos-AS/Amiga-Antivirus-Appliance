# M7.5 — Signature release and appliance update workflow

## Goal

M7.5 operationalizes the code-qualified M7.4 signed distribution mechanics without weakening its trust boundaries. The milestone defines how qualified generated signature material becomes an intentionally published release artifact and how an appliance discovers, downloads, verifies and installs a newer signed signature distribution.

M7.5 is deliberately split between **release production** and **appliance consumption**. Publishing is not an implicit side effect of ordinary CI, and downloading never implies trust or installation.

## Status

**Foundation / implementation in progress.**

M7.4 is code-qualified. M7.5 starts from the M7.4 closing HEAD and must preserve all M7.4 canonicalization, signing, verification, version, downgrade and atomic activation contracts.

## Core boundaries

The release/update flow is fail closed:

- build does not imply sign;
- sign does not imply publish;
- download does not imply verify;
- verify does not imply install;
- install always uses the M7.4 verifier;
- unsigned release artifacts are never installable through the update path;
- an untrusted signer is never accepted because the artifact came from GitHub or HTTPS;
- ordinary pull-request/push CI never receives or requires a production private signing key;
- release creation must be an explicit, auditable action;
- a failed or incomplete update leaves the currently active signature distribution unchanged.

## Release artifact contract

The canonical M7.4 logical bundle remains unchanged:

```text
manifest.json
manifest.sig
aaa/bootblocks.json
clamav/aaa.hsb
```

M7.5 packages those files into one deterministic transport artifact:

```text
aaa-signatures-<version>.tar.gz
```

The archive is transport only. Authenticity and payload integrity continue to come from `manifest.json` + `manifest.sig` and the independently trusted Ed25519 public key.

The release may additionally publish a transport checksum file:

```text
aaa-signatures-<version>.tar.gz.sha256
```

The transport SHA-256 is useful for download corruption diagnostics but is **not** a substitute for M7.4 signature verification.

## Archive rules

Schema-v1 release archives must be deterministic enough for reproducible release tooling:

- paths are relative and slash-separated;
- no absolute paths;
- no `.` or `..` path components;
- no symlinks, hard links, devices or FIFOs;
- only the four logical M7.4 bundle paths are permitted;
- entries are sorted lexicographically;
- regular-file modes are normalized;
- owner/group identity is normalized;
- timestamps are normalized to a deterministic release timestamp derived from the manifest `created_at` value;
- extraction must reject path traversal and unexpected entry types before materializing files.

The unpacked directory must pass the existing M7.4 bundle verifier byte-for-byte before installation.

## Release version and tag contract

Signature distribution versions continue to use the exact M7.4 `MAJOR.MINOR.PATCH` contract.

The release tag namespace is:

```text
signatures-v<MAJOR.MINOR.PATCH>
```

Examples:

```text
signatures-v0.1.0
signatures-v1.0.0
```

The tag version, archive filename version and signed manifest version must all match exactly. Any mismatch fails release qualification or appliance update verification.

Signature-data releases are intentionally namespaced separately from future application/container releases.

## Release production workflow

M7.5 release production is an explicit sequence:

1. start from an exact clean commit on `main`;
2. run the existing qualification/CI gates;
3. generate current qualified signature exports through the existing M7 pipeline;
4. build an unsigned M7.4 bundle for the requested version;
5. sign the manifest with an explicitly supplied release private key;
6. verify the signed bundle against the corresponding independently supplied trusted public key;
7. package the verified bundle into the deterministic transport archive;
8. compute the optional transport SHA-256 file;
9. verify tag/archive/manifest version agreement;
10. publish the tag and immutable release artifacts only after all preceding gates pass.

The workflow must never modify an existing published release in place to represent different signature content under the same version.

## Signing-key custody

Production private-key custody remains outside the repository and outside ordinary appliance state.

The release workflow may consume a private key only through an explicit protected release input, for example a GitHub Actions environment secret or a locally supplied release file descriptor. The implementation must ensure:

- the private key is not committed;
- the private key is not uploaded as an artifact;
- the private key is not printed in logs;
- the private key is not copied into the generated bundle/archive;
- ordinary CI does not depend on the production key;
- tests use ephemeral synthetic Ed25519 keys only.

A future hardware-backed signing system may replace secret-file handling without changing the M7.4 bundle signature semantics.

## GitHub Actions release policy

The first automated publication workflow should be manually dispatched rather than automatically triggered by every tag push.

The intended shape is:

```text
workflow_dispatch:
  version: <MAJOR.MINOR.PATCH>
```

Before publication it must prove:

- requested version is syntactically valid;
- `main`/selected release commit is clean and explicitly identified;
- repository CI is green for that exact commit;
- no GitHub release/tag already exists for `signatures-v<version>`;
- generated bundle verifies using the trusted public key;
- archive contents are exactly the allowed bundle files;
- manifest version equals requested version;
- artifact filename version equals requested version.

Production release jobs should use the minimum GitHub token permissions required for release/tag publication and should not grant write permissions to ordinary CI jobs.

## Release metadata

A GitHub signature release should record at least:

- signature release version;
- source commit SHA;
- manifest SHA-256 identity;
- signer key ID;
- archive SHA-256;
- creation timestamp from the signed manifest;
- explicit note that the artifact still requires M7.4 signature verification before installation.

This metadata is descriptive and auditable. The signed manifest remains authoritative for bundle identity.

## Appliance update discovery

M7.5 adds a non-mutating update discovery step. The appliance may query a configured release source for the latest available signature release metadata.

The initial source may be GitHub Releases, but source transport is not trusted implicitly. Discovery may identify a candidate version and artifact URL only.

The update checker must:

- know the currently active installed version from M7.4 state;
- parse remote candidate versions with the existing numeric version rules;
- ignore malformed versions;
- report when no active distribution exists;
- report when no newer release exists;
- never install or activate merely because a newer version was discovered.

## Download contract

A download command stores the release artifact in a temporary/staging location separate from active signature state.

It must:

- use bounded HTTP timeouts;
- use bounded maximum download size;
- require successful HTTP status;
- not follow unsafe local/file schemes;
- write to a temporary file first;
- fsync/close before promotion to a completed download path;
- optionally validate the published transport SHA-256 when supplied;
- leave active M7.4 state untouched on any failure.

Transport checksum failure is fatal for that download attempt.

## Archive extraction contract

Downloaded archives are extracted into a fresh temporary directory.

Extraction must reject:

- absolute paths;
- path traversal;
- duplicate logical paths;
- unexpected files;
- symlinks/hard links;
- non-regular entries;
- entries exceeding configured size bounds;
- archives exceeding configured aggregate expanded-size bounds.

Only after safe extraction does M7.4 `VerifyDistributionBundle` run.

## Appliance update/install contract

The update flow reuses M7.4 installation semantics rather than implementing a second installer.

The logical command sequence is:

```text
aaa signatures update check
aaa signatures update download --version <version>
aaa signatures update verify <artifact-or-extracted-dir>
aaa signatures update install <artifact-or-extracted-dir>
```

A convenience command may eventually combine stages, but even then the internal trust gates must remain identical and independently testable.

For M7.5, an optional explicit convenience command may be introduced:

```text
aaa signatures update apply --trusted-key <file> [--version <version>]
```

If implemented, `apply` must still execute discovery/download/extraction/M7.4 verification/M7.4 installation in that order, and failure at any stage must leave the previous active version unchanged.

## Trusted-key configuration

The first implementation keeps trusted public key input explicit.

A command may accept:

```text
--trusted-key <file>
```

A later appliance configuration file may define one or more trusted release public keys, but M7.5 must not introduce trust-on-first-use or trust a public key delivered inside the same release artifact.

## Update source configuration

The initial source definition should be explicit and narrow. For GitHub Releases, the default repository may be the AAA repository itself, but the code should isolate source discovery from cryptographic verification.

A source configuration must never be allowed to override the trusted-key decision silently.

## Network and privacy behavior

Update checks are explicit operations in the first M7.5 implementation. No mandatory background telemetry or periodic outbound request is introduced by this milestone.

If automatic scheduled checks are added later, they require an explicit appliance configuration and must remain non-installing unless the user separately opts into an automatic update policy.

## Failure semantics

The update path must fail safely for at least:

- network timeout/failure;
- HTTP error;
- malformed release metadata;
- malformed or mismatched version/tag;
- oversized download;
- transport SHA-256 mismatch;
- malformed archive;
- archive path traversal;
- unexpected archive entries;
- missing manifest/signature/payload;
- unknown signer;
- invalid signature;
- changed payload;
- downgrade;
- same-version different manifest;
- staging/install error.

None of those failures may alter `current.json` or replace the active distribution.

## CI qualification strategy

Ordinary CI uses no production private keys and no mandatory external network access.

Tests should use local HTTP fixtures/test servers and ephemeral synthetic Ed25519 keys to cover at least:

- deterministic archive creation;
- exact allowed archive layout;
- archive traversal/symlink rejection;
- tag/archive/manifest version agreement;
- transport checksum success/failure;
- release metadata parsing;
- numeric latest-version selection;
- no-update behavior;
- malformed-version rejection;
- bounded download behavior;
- successful download -> extract -> verify -> install pipeline;
- unsigned bundle rejection;
- unknown signer rejection;
- corrupted archive/bundle rejection;
- downgrade rejection;
- same-version conflict rejection;
- failed update preserving prior active state;
- linux/amd64 and linux/arm64 builds remaining green.

GitHub publication itself can be separately exercised with a dry-run/package job before an intentionally signed real release is created.

## Planned implementation slices

### M7.5a — Release/update contract

Define this specification, artifact/tag naming, release policy, key boundary, update discovery/download/extraction/install boundaries and CI qualification plan.

### M7.5b — Deterministic release archive

Implement deterministic `.tar.gz` packaging, strict archive extraction, transport SHA-256 handling and version agreement checks around the existing M7.4 bundle.

### M7.5c — Release workflow

Add explicit GitHub Actions/manual release tooling with protected signing-key input, dry-run support, exact commit/version checks and immutable release artifact publication.

### M7.5d — Appliance update client

Implement explicit check/download/verify/install commands, bounded HTTP behavior, local staging and reuse of the M7.4 verifier/installer.

### M7.5e — Qualification

Exercise the complete synthetic release/update lifecycle in CI, record the exact green HEAD and document remaining operational/runtime work.

## Non-goals

M7.5 does not:

- change M7.4 cryptographic algorithms or trust semantics;
- auto-generate production signing keys;
- store production private keys on the appliance;
- trust GitHub/HTTPS instead of Ed25519 verification;
- silently auto-install updates by default;
- implement key rotation/transparency/TUF/Sigstore;
- claim production signing-key custody is operationally qualified merely because code tests pass;
- claim Orange Pi Zero 3/DietPi runtime qualification;
- change M7.0–M7.3 promotion/corpus gates;
- complete M8 historical Amiga scanner runtime qualification.

## Exit criteria

M7.5 can be called **code-qualified** when deterministic release packaging, explicit protected publication mechanics, bounded update discovery/download/extraction, reuse of the M7.4 verifier/installer, failure-state preservation and the CLI surface are implemented and the qualification record points to an exact green CI HEAD.

A **production-ready signature release channel** additionally requires an intentionally provisioned production signing key, documented custody/backup/rotation/revocation procedures, and at least one intentionally signed published release whose artifact is successfully verified and installed on the target appliance platform.
