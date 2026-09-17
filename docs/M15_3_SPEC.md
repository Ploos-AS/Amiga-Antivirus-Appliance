# M15.3 — Replica-side Immutable Catalogue

Status: SPECIFIED — implementation pending.

## Purpose

M15.3 adds a replica-side catalogue for M15.1 receipts and M15.2 completed session documents. The catalogue makes a mounted replica self-describing enough to inventory and verify retained objects without depending on the operator's original local receipt/session files.

M15.3 does not make replica-adjacent metadata an independent witness. Independent retention remains a deployment property.

## Principles

1. Existing M15.1 content-addressed evidence objects remain authoritative by SHA-256.
2. Catalogue records are immutable, content-addressed metadata; no mutable database is introduced.
3. Publication never overwrites or deletes an existing catalogue record.
4. Exact existing metadata is idempotent success; conflicting bytes fail closed.
5. Catalogue publication must not weaken M15.1/M15.2 strict decoding or namespace checks.
6. Catalogue metadata contains no absolute host paths.
7. Inventory is derived from immutable records and may be rebuilt by scanning the catalogue namespace.
8. Catalogue presence proves retained metadata bytes, not malware authenticity, trusted time, signer authorization, remote availability, or independent failure-domain placement.

## Layout

The namespace reserved in M15.0 becomes:

```text
<replica-root>/
└── aaa-replica-v1/
    ├── objects/
    │   └── sha256/<first-two>/<sha256>
    └── receipts/
        └── sha256/<first-two>/<sha256>
```

The file under `receipts/sha256/...` contains the exact canonical LF-terminated M15.1 receipt or M15.2 session document. The name is the SHA-256 of the metadata document itself, not an evidence-object hash.

No source basename is authoritative. No mutable `latest`, index pointer, symlink, or deletion marker is required for M15.3.

## Supported catalogue documents

Initial document types:

- `aaa-evidence-replica-receipt-v1` from M15.1;
- `aaa-evidence-replica-session-v1` from M15.2.

A document must pass its existing strict decoder before publication. Unknown schemas fail closed.

For a receipt, publication additionally verifies the referenced replica object against the receipt before accepting the catalogue record.

For a session, publication verifies every object marked `replicated` or `already-present`. A session containing `failed` entries is a valid historical record and may be catalogued, but it remains explicitly incomplete and must never be reported as a fully replicated session.

## Publication

Proposed commands:

```text
aaa evidence replica catalogue-add \
  --root /mnt/aaa-archive \
  case.aaa-evidence.zip.replica.json

aaa evidence replica catalogue-add \
  --root /mnt/aaa-archive \
  session.json
```

Publication flow:

1. Open and validate the metadata source as the same regular file using the established `Stat` + `Lstat` + `SameFile` pattern.
2. Enforce a bounded metadata size.
3. Strictly decode the document as a supported receipt/session schema.
4. Verify referenced replica object(s) under M15.1/M15.2 rules.
5. Hash the exact canonical metadata bytes.
6. Ensure every existing catalogue namespace component is a real directory, not a symlink.
7. Publish write-once under `receipts/sha256/<prefix>/<metadata-sha256>`.
8. Verify the published metadata bytes before reporting success.

A byte-identical existing record is idempotent success. Any conflicting destination bytes fail closed.

## Inventory

Proposed command:

```text
aaa evidence replica catalogue-list --root /mnt/aaa-archive
```

The inventory scans only the versioned `receipts/sha256` namespace. It does not trust filenames beyond validating their lowercase SHA-256 form and verifying each record's bytes against that name.

For each valid record it reports at least:

- metadata SHA-256;
- schema/document type;
- metadata size;
- receipt object kind/SHA when the record is a receipt; or
- session ID, object count and complete/incomplete state when the record is a session.

Ordering is deterministic by metadata SHA-256. Machine-readable JSON output should be deterministic and portable.

Malformed, tampered, misnamed or unsupported catalogue entries cause verification/inventory failure rather than being silently ignored in a clean-verification mode.

## Verification

Proposed command:

```text
aaa evidence replica catalogue-verify --root /mnt/aaa-archive
```

Verification checks:

- catalogue namespace components are real directories;
- every record filename matches the SHA-256 of its exact bytes;
- every record strictly decodes as a supported schema;
- receipt-referenced objects still match size/SHA;
- session identity is recomputed and every successful/already-present object still matches size/SHA;
- failed session entries remain incomplete rather than promoted to success.

The verifier performs no evidence execution and no scanner invocation.

## Security boundary

M15.3 does not provide:

- trusted timestamps;
- signed catalogue heads;
- rollback/suffix-deletion detection for the catalogue itself;
- remote replication or synchronization;
- remote availability proof;
- WORM hardware guarantees;
- encryption at rest;
- consensus/blockchain semantics;
- protection when all copies are compromised together.

Because the catalogue is stored beside the replica, deletion of both an object and every catalogue record referring to it is not detectable from that replica alone. A later milestone may bind catalogue state to signed snapshots/checkpoints retained independently.

## Planned qualification

CI qualification should cover:

- deterministic metadata addressing;
- strict receipt/session decoding before publication;
- exact-byte publication and post-write verification;
- idempotent repeated publication;
- destination conflict rejection;
- root/catalogue namespace symlink rejection;
- receipt object verification;
- complete and incomplete session handling;
- deterministic inventory ordering;
- tampered metadata detection;
- misnamed metadata detection;
- missing/tampered referenced object detection;
- unknown schema rejection;
- no absolute host paths in machine-readable inventory;
- amd64 and arm64 builds.

No Orange Pi, AmigaOS, emulator, Greaseweazle, malware sample, ROM or proprietary scanner binary is required for M15.3 code qualification.
