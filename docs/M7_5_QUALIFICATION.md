# M7.5 — Qualification record

## Status

**Code-qualified.**

M7.5 implements the signature release and appliance update workflow defined by `docs/M7_5_SPEC.md` while preserving the M7.4 trust boundary. This record closes the code-qualification milestone; it does not claim production signing-key custody or Orange Pi Zero 3/DietPi runtime qualification.

## Qualified baseline

The implementation qualification baseline is:

- branch: `main`
- green implementation HEAD: `99daa8a5904b902cf72af55d6cc9a343043279f2`
- CI workflow run: `#236`
- CI conclusion: `success`

The documentation-only closure commit follows that green implementation HEAD and must itself pass ordinary CI before the closure is considered repository-green.

## Qualified scope

M7.5a–e are implemented:

- release/update contract, artifact naming, trust boundaries and failure semantics;
- deterministic `aaa-signatures-<version>.tar.gz` packaging;
- strict archive extraction and transport SHA-256 support;
- exact version agreement between release/tag, archive and signed manifest;
- explicit manually dispatched GitHub release workflow with dry-run support and protected signing-key inputs;
- non-mutating release discovery with numeric version selection;
- bounded staged HTTP download with optional SHA-256 validation;
- explicit update `check`, `download`, `verify` and `install` CLI stages;
- reuse of the M7.4 verifier and atomic installer rather than a parallel trust/install path;
- synthetic CI lifecycle qualification from signed bundle through archive, discovery, download, extraction, verification, installation and active-state validation;
- failure-state qualification showing a corrupt update does not replace the active distribution.

## Trust boundary preserved

M7.5 does not trust release transport as authenticity evidence. A downloaded artifact must still pass M7.4 Ed25519 verification using an independently supplied trusted public key before installation. GitHub metadata, HTTPS and transport SHA-256 remain transport/provenance aids only.

Ordinary CI uses ephemeral synthetic Ed25519 keys and does not require the production signing key. The production private key is neither committed nor part of appliance state.

## Lifecycle qualification

The M7.5e synthetic lifecycle test exercises:

1. generation of deterministic signature exports;
2. construction of an M7.4 distribution bundle;
3. signing with an ephemeral Ed25519 key;
4. verification with the corresponding independently constructed trusted-key set;
5. deterministic release archive creation and archive SHA-256 calculation;
6. local release metadata discovery and candidate version selection;
7. bounded staged download with expected SHA-256 verification;
8. strict archive extraction;
9. M7.4 bundle verification after extraction;
10. M7.4 atomic installation;
11. active installation-state verification.

A separate failure-path test starts from an installed signed distribution, rejects a corrupt update archive, and proves the previously active installation state is unchanged.

## CI evidence

The final implementation correction was committed as:

`99daa8a5904b902cf72af55d6cc9a343043279f2` — `Fix M7.5e lifecycle qualification test`

GitHub Actions CI run `#236` completed successfully for that exact HEAD.

## Remaining operational work

The following are intentionally outside this code-qualification claim and remain required before calling the signature release channel production-ready:

- provision a real production Ed25519 signing key through an explicit protected release environment;
- document production key custody, backup, rotation and revocation procedures;
- intentionally exercise the manual publication workflow with qualified generated signature input;
- publish at least one intentionally signed immutable signature release;
- verify and install that published release on the target Orange Pi Zero 3/DietPi appliance;
- complete target-platform runtime qualification, including network/download behavior and persistent-storage semantics.

The manual release workflow should also be operationally exercised before relying on it for production publication; ordinary CI qualification does not by itself prove GitHub environment/secret provisioning or a real release publication path.

## Closure

M7.5 satisfies its code-level exit criteria: deterministic release packaging, explicit protected publication mechanics, bounded update discovery/download/extraction, M7.4 verifier/installer reuse, failure-state preservation, explicit CLI stages and a green synthetic end-to-end lifecycle are present.

**M7.5 is therefore closed as code-qualified.**
