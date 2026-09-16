# M15.1 — Evidence Replica Core

Status: CODE-QUALIFIED.

## Scope

M15.1 implements the local mounted-directory replica core specified by M15.0. It preserves selected M13/M14 evidence objects outside the AAA appliance in a deterministic, content-addressed, write-once namespace and emits a portable receipt that can later be used for offline byte verification.

M15.1 does not add a network transport, cloud provider, remote attestation, trusted time, WORM guarantee, or automatic trust promotion.

## CLI

```text
aaa evidence replicate \
  --destination /mnt/aaa-archive \
  --kind evidence-bundle \
  case.aaa-evidence.zip

aaa evidence replica verify \
  --root /mnt/aaa-archive \
  case.aaa-evidence.zip.replica.json
```

`replicate` accepts an optional `--receipt` path and optional operator `--note`. The default receipt is written alongside the source as `SOURCE.replica.json`. The `aaa-replica-v1/receipts/` namespace from M15.0 is reserved for a later replica-side receipt catalogue/session layer; M15.1 does not silently make a receipt stored on the same replica object store authoritative.

## Object store

Objects are stored as exact bytes at:

```text
<root>/aaa-replica-v1/objects/sha256/<first-two>/<sha256>
```

Supported object kinds are:

- `evidence-bundle`
- `evidence-signature`
- `evidence-ledger`
- `ledger-checkpoint`
- `checkpoint-trust-store`
- `checkpoint-trust-update`

Existing objects are idempotent successes only when size and SHA-256 match the receipt. Conflicting content fails closed and is never overwritten.

## Receipt

Schema: `aaa-evidence-replica-receipt-v1`.

The deterministic LF-terminated JSON receipt contains `schema`, `created_at`, `object_kind`, `sha256`, `size`, `replica_name`, and optional `note`.

`created_at` must be canonical UTC RFC3339Nano. It is operator-observed metadata, not trusted time. `replica_name` is the canonical portable relative content-addressed name. Absolute host paths and backslash paths are rejected.

Strict decoding rejects unknown fields, trailing JSON, missing LF termination, non-deterministic JSON representation, unsupported kinds, malformed/lowercase violations in SHA-256, noncanonical timestamps, invalid replica names, and control characters in notes.

## Copy safety

The source is opened and checked with the established AAA regular-file identity pattern: opened `Stat`, path `Lstat`, and `SameFile`. The source is copied from the already-open descriptor. Size and modification time are checked after the copy, and copied size/SHA-256 must match the prebuilt receipt.

A temporary file is created in the final content-addressed destination directory, fsynced, and published without overwrite by hard-linking to the final name. Failed unpublished temporary files are removed. The final object is re-opened and SHA-256/size verified before success.

M15.1 does not claim `O_NOFOLLOW`/`openat` race-free Linux semantics. The source identity check substantially narrows path substitution risk because copied bytes come from the validated opened descriptor.

## Namespace safety

The replica root must be a real directory rather than a symlink. Creation walks `aaa-replica-v1`, `objects`, `sha256`, and the SHA prefix component, checking each with `Lstat` as a real directory.

Offline `replica verify` performs the same intermediate namespace checks before opening the content-addressed object. A namespace component replaced by a symlink therefore fails closed instead of being followed by the verifier.

## Verification semantics

`aaa evidence replica verify` strictly decodes the receipt, validates the replica namespace, hashes the named content-addressed object, and requires exact SHA-256 and size equality.

Verification proves that the bytes reachable in that replica match the receipt at verification time. It does not prove malware authenticity, signer authorization, trusted creation time, continued future existence, or independence of the underlying physical storage.

## Qualification boundary

M15.1 is code-qualified by ordinary GitHub Actions CI. Tests cover deterministic receipts and naming, canonical UTC timestamps, strict receipt decoding, exact replication, idempotence, conflicting-object rejection, source/root/namespace symlink rejection, verify-time namespace-symlink rejection, tamper detection, missing-object detection, and successful-copy temporary-file cleanup. The normal CI also validates formatting, vet/tests, and amd64/arm64 builds.

No Orange Pi, AmigaOS, FS-UAE, Greaseweazle, historical scanner binary, malware sample, proprietary ROM, or proprietary operating-system image is required for M15.1 code qualification.

## Remaining limitations

M15.1 is deliberately a single-object local-filesystem primitive. It does not claim multi-object transaction atomicity, exactly-once remote delivery, a replica-side receipt catalogue, remote availability, storage durability, or independent failure-domain deployment merely because a second directory exists. Operators must place the replica on genuinely independent storage to obtain the preservation goal described by M15.
