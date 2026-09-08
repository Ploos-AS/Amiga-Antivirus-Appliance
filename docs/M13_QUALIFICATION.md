# M13 — Portable Evidence Bundles qualification

Status: CODE-QUALIFIED — CI qualification complete through M13.7; no physical hardware required

## Scope

M13 makes AAA evidence portable, independently verifiable and optionally authenticated without changing malware classification or the acquisition provenance established by earlier milestones.

The qualified chain covers:

- **M13.0** — portable evidence manifest contract;
- **M13.1** — deterministic manifest model, strict portable-path validation and offline file verification;
- **M13.2** — public `aaa evidence create` / `verify` CLI;
- **M13.3** — deterministic single-file evidence ZIP and offline `verify-bundle`;
- **M13.4** — detached Ed25519 bundle signatures;
- **M13.5** — operator-controlled evidence signing-key trust store and lifecycle policy;
- **M13.6** — root-authenticated trust-store updates with monotonic sequence rollback/replay protection;
- **M13.7** — persistent rollback state and crash-safe trust-store installation.

## Qualification result

The repository CI gates have qualified the M13 implementation through M13.7 on both amd64 and arm64. The final M13.7 public-help reconciliation passed CI #478.

The normal repository qualification chain includes formatting, shell/policy checks, module metadata validation, `go vet`, the complete Go test suite, AmiGuard compatibility validation, amd64 build and arm64 build.

No Orange Pi, Amiga, emulator, Greaseweazle, floppy drive or physical disk is required to establish the M13 code claims. M13 operates on already-produced evidence bytes and cryptographic metadata.

## Qualified security properties

The M13 code-qualified boundary includes:

1. deterministic evidence-manifest serialization;
2. portable relative names with unsafe/absolute/traversal names rejected;
3. exact SHA-256 and size binding for every manifest entry;
4. offline verification without executing evidence content;
5. deterministic ZIP transport with no undeclared, compressed, directory, symlink or special members;
6. detached Ed25519 signatures bound to the exact evidence ZIP SHA-256 and signer key ID;
7. independently supplied trust policy for multiple signing keys, rotation, validity windows and revocation;
8. independently pinned root-key authentication for trust-store updates;
9. strict monotonic update sequence enforcement against replay and rollback;
10. durable local sequence state under `/data/aaa/state/evidence-trust`;
11. immutable sequence-addressed installed trust stores and atomic state-pointer replacement;
12. fail-closed local-state validation when the active trust store is missing, changed or malformed.

## Provenance boundaries

M13 does not promote a submitted or unknown artifact to verified malware. It proves identity, packaging integrity and — when signatures/trust are used — possession of approved signing keys according to the selected trust policy.

M12 acquisition semantics remain authoritative. Carrying raw SCP flux and ADF reads in one M13 bundle does not assert SCP-to-ADF derivation.

Historical scanner binaries, Amiga ROMs and operating-system files are not automatically included and retain their own licensing constraints.

## Trust boundaries intentionally left outside M13

M13 does not claim:

- trusted signing timestamps or archival timestamp authority;
- public certificate-chain identity;
- transparency logging;
- remote automatic trust-store discovery/download;
- automatic root-key rotation or recovery from root-private-key compromise;
- TPM/hardware-backed monotonic rollback counters;
- protection when an attacker can rewrite both the complete local trust-state directory and the independently pinned root-key source.

These are future policy/infrastructure concerns rather than incomplete M13 code qualification.

## Optional later runtime exercise

When M12 physical acquisition hardware is available, an end-to-end demonstration may acquire real media, create an M13 bundle, sign it, transfer it to an independent machine and verify it offline. Such a demonstration is useful integration evidence but is not required to code-qualify M13.

## Conclusion

M13.0–M13.7 are code-qualified as a complete portable-evidence and trust-distribution chain. Remaining physical/runtime gates belong to the earlier appliance/acquisition milestones and do not block closure of M13.
