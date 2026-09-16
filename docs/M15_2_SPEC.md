# M15.2 — Deterministic Replication Sessions

Status: SPECIFIED — implementation pending.

## Purpose

M15.2 builds a deterministic multi-object session layer on top of the M15.1 single-object replica primitive. A session records which independently content-addressed objects an operator intended to replicate together and the outcome for each object, without claiming that the set was committed as one atomic filesystem transaction.

M15.2 does not change M13 evidence semantics, M14 ledger/checkpoint trust, or M15.1 object verification.

## Principles

1. Each object remains independently immutable and content-addressed by SHA-256.
2. A session never weakens M15.1 source, namespace, conflict, or verification checks.
3. Session ordering is deterministic and independent of command-line input order.
4. A later object failure does not invalidate objects already replicated and verified.
5. No deletion propagation or destination overwrite is introduced.
6. Session metadata contains portable names and hashes, never absolute host paths.
7. Session completion means every listed object reached an explicit terminal result; it does not mean filesystem transaction atomicity.
8. No receipt or session document promotes malware authenticity, signer authorization, trusted time, or storage durability.

## Session schema

Schema: `aaa-evidence-replica-session-v1`.

Required top-level fields:

- `schema`
- `created_at` — canonical UTC RFC3339Nano metadata timestamp, not trusted time
- `session_id` — deterministic SHA-256 identity derived from the canonical session intent
- `objects` — deterministically ordered array of object records

Optional:

- `note` — operator note subject to the same portable/control-character restrictions as M15.1

Each object record contains:

- `object_kind`
- `sha256`
- `size`
- `replica_name`
- `result` — `replicated`, `already-present`, or `failed`
- optional `error` for a failed item

Absolute source/destination paths must not be serialized. The session must not serialize the operator's source filename as authoritative identity.

## Deterministic intent and session identity

Before copying, M15.2 constructs a canonical intent from each selected object's `object_kind`, SHA-256, size, and canonical M15.1 `replica_name`. Intent records are sorted by `object_kind`, then SHA-256, then size/name as deterministic tie breakers.

`session_id` is the lowercase SHA-256 of the deterministic intent encoding. Timestamps, result state, error strings, source paths and destination paths are excluded from this identity. Therefore the same selected bytes/kinds produce the same session identity even when attempted at a different time or supplied in another CLI order.

Duplicate intent entries with the same kind/SHA/size/name are rejected rather than silently collapsed. A SHA with inconsistent size/name also fails closed.

## Execution semantics

The implementation invokes the M15.1 replica primitive once per sorted object. Every successful object is re-verified under M15.1 rules before its result is recorded.

The session executor continues after an individual object failure so that the final document records a terminal result for every intended object. The command exits non-zero when any object failed.

A successfully replicated object is never removed as rollback for a later failure. M15.2 explicitly makes no multi-object atomicity claim.

## Session publication

The deterministic session document is LF-terminated JSON. A completed document is written only after every object attempt has reached a terminal result.

The default operator-held session path should be explicit or derived outside the replica object namespace. A later milestone may add content-addressed replica-side session/catalog storage. M15.2 must not silently treat metadata stored only beside the replica as an independent witness.

## Proposed CLI

Initial CLI shape:

```text
aaa evidence replicate-session \
  --destination /mnt/aaa-archive \
  --session session.json \
  --object evidence-bundle:case.aaa-evidence.zip \
  --object ledger-checkpoint:checkpoint.json
```

Repeated `--object KIND:PATH` values select source objects. `KIND` must be one of the M15.1 object kinds. The path is operator input only and is never serialized into the portable session document.

Verification should be available as:

```text
aaa evidence replica verify-session \
  --root /mnt/aaa-archive \
  session.json
```

`verify-session` strictly decodes the session, recomputes its deterministic identity, applies M15.1 namespace safety checks, and verifies every object marked `replicated` or `already-present`. A session containing `failed` entries remains a valid record of a partial attempt but verification returns a distinct incomplete/failed status rather than presenting the session as fully replicated.

## Security boundary

M15.2 adds no network transport, encryption at rest, trusted timestamp, remote attestation, WORM guarantee, consensus mechanism, remote availability proof, key escrow, or independent-failure-domain guarantee.

Error strings must be sanitized so serialized failures do not leak absolute host paths. If an underlying error cannot be represented portably, the session records a stable error class rather than the raw error text.

## Planned qualification

M15.2 CI should prove:

- identical intent yields identical `session_id` independent of CLI input order and timestamp;
- deterministic object ordering and LF-terminated strict JSON;
- duplicate/inconsistent intent rejection;
- no absolute source/destination paths in session documents;
- successful multi-object replication and verification;
- `already-present` behavior on a repeated session;
- one-object failure does not delete earlier successful objects;
- failed session exits non-zero while recording all terminal results;
- tampered/missing objects are detected by `verify-session`;
- namespace symlink rejection is retained for every object;
- unknown fields, unsupported kinds, malformed hashes and noncanonical timestamps fail closed;
- sanitized failure metadata cannot leak host paths;
- amd64 and arm64 builds remain green.

No Orange Pi, AmigaOS, FS-UAE, Greaseweazle, malware sample, proprietary scanner, ROM, or operating-system image is required for M15.2 code qualification.
