# M13.0 — Portable evidence bundle specification

Status: COMPLETE — implemented and code-qualified through M13.7; see `docs/M13_QUALIFICATION.md`

## Purpose

M13 makes AAA scan and acquisition evidence portable without requiring the reference Orange Pi or Greaseweazle hardware. M13.0 defines the bundle contract before implementation.

An evidence bundle is a deterministic manifest that binds already-produced AAA evidence by cryptographic hash. It is intended for archival, transfer, independent review and later verification. It is not a malware classification by itself and it must not weaken the provenance rules established by M7–M12.

## Scope

M13.0 defines a versioned JSON manifest for a single evidence bundle. Later M13 steps implement CLI creation and verification, deterministic ZIP transport, detached signatures, trust policy, authenticated trust-store updates and persistent rollback state.

The bundle may reference:

- original submitted/acquired artifact SHA-256 and size;
- AAA scan result/report;
- attributed engine results;
- acquisition evidence sidecars;
- M12 repeatability and acquisition-session manifests;
- raw SCP preservation evidence;
- signature/provenance material when explicitly selected by the operator.

The bundle must not silently include arbitrary host paths or secrets.

## Security and provenance contract

1. Every included file is identified by relative bundle name, byte size and SHA-256.
2. Absolute host paths are forbidden in the portable manifest.
3. Bundle creation never modifies or deletes source evidence.
4. Verification is offline and does not execute bundled content.
5. Verification must fail closed on missing files, size mismatch, hash mismatch, duplicate logical names, unsafe relative paths or unsupported schema versions.
6. Malware verdicts remain attributed evidence; bundling does not promote an unknown or submitted sample to verified malware.
7. M12 raw SCP and ADF evidence retain their existing relationship semantics. A bundle must not imply that an ADF was derived from an SCP merely because both are present.
8. Historical third-party scanner binaries, ROMs and operating-system files are not included automatically. Their redistribution remains subject to their own licenses.

## Schema

Schema identifier:

`aaa-evidence-bundle-v1`

Required top-level fields:

- `schema`
- `created_at`
- `aaa_version`
- `entries`

Each entry contains:

- `name` — normalized safe relative name;
- `kind` — controlled evidence category;
- `sha256` — lowercase 64-hex SHA-256;
- `size` — non-negative byte count.

Optional metadata may include a human operator note and relationships between entries, but relationships must be explicit and must never infer derivation from proximity.

Initial controlled kinds:

- `artifact`
- `scan-report`
- `engine-evidence`
- `acquisition-evidence`
- `repeatability`
- `acquisition-session`
- `raw-flux`
- `signature-evidence`

## Determinism

Entries are sorted by normalized name before serialization. Canonical bundle identity is computed over the exact manifest bytes produced by AAA. Timestamps are evidence metadata and must not be regenerated during verification.

M13.3 adds a deterministic archive container that packages the manifest and selected files while retaining the manifest contract as the primary semantic boundary.

## CLI

Implemented M13 commands include:

```text
aaa evidence create ...
aaa evidence verify <manifest>
aaa evidence pack ...
aaa evidence verify-bundle <bundle.zip>
aaa evidence sign ...
aaa evidence verify-signed ...
aaa evidence trust validate ...
aaa evidence verify-trusted ...
aaa trust-update sign ...
aaa trust-update verify ...
aaa trust-update install ...
aaa trust-update status ...
```

Creation is explicit about selected evidence. Verification works without network access and without running scanners.

## Qualification

M13.0–M13.7 are code-qualified as a complete chain. See `docs/M13_QUALIFICATION.md` for the consolidated qualification boundary.

Qualification covers deterministic manifest generation, safe relative-path validation, duplicate-name rejection, missing-entry rejection, size/hash mismatch rejection, unsupported-schema rejection, absence of source host paths from portable manifests, deterministic ZIP transport, detached signatures, trust policy, authenticated trust updates, persistent rollback state and preservation of M12 no-SCP-to-ADF-derivation semantics.

Physical appliance qualification is not required for M13. A later end-to-end appliance exercise may export and independently verify a bundle produced from real M12 acquisition evidence without changing the M13 code-qualified status.
