# M15.2 — Deterministic Replication Sessions

Status: CODE-QUALIFIED.

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

Duplicate intent entries with the same kind/SHA/size/name are rejected rather than silently collapsed. Invalid or inconsistent object identity fails closed through the strict M15.1-compatible object validation.

## Execution semantics

The implementation invokes the M15.1 replica primitive once per object. Successful objects are content-addressed and verified under M15.1 rules before the session is published.

The session executor continues after an individual replication failure so that the final document records a terminal result for every prepared intended object. The command exits non-zero when any object failed.

A successfully replicated object is never removed as rollback for a later failure. M15.2 explicitly makes no multi-object atomicity claim.

## Session publication

The deterministic session document is LF-terminated JSON. A completed document is written only after every prepared object attempt has reached a terminal result.

The operator supplies `--session`; that file remains operator-held metadata outside the content-addressed replica object namespace. M15.2 does not treat metadata stored only beside a replica as an independent witness.

## CLI

```text
aaa evidence replicate-session \
  --destination /mnt/aaa-archive \
  --session session.json \
  --object evidence-bundle:case.aaa-evidence.zip \
  --object ledger-checkpoint:checkpoint.json
```

Repeated `--object KIND:PATH` values select source objects. `KIND` must be one of the M15.1 object kinds. The path is operator input only and is never serialized into the portable session document.

Verification:

```text
aaa evidence replica verify-session \
  --root /mnt/aaa-archive \
  session.json
```

`verify-session` strictly decodes the session, recomputes its deterministic identity, applies M15.1 namespace safety checks, and verifies every object marked `replicated` or `already-present`. A session containing `failed` entries remains a valid record of a partial attempt, but verification returns an incomplete/failed result rather than presenting the session as fully replicated.

## Security boundary

M15.2 adds no network transport, encryption at rest, trusted timestamp, remote attestation, WORM guarantee, consensus mechanism, remote availability proof, key escrow, or independent-failure-domain guarantee.

Serialized replication failures use stable portable error classes rather than raw host errors, preventing source/destination paths from being copied into session metadata.

## Qualification

M15.2 model and CLI behavior are code-qualified by the normal repository CI on amd64 and arm64. Qualification includes deterministic identity/order, strict session decoding, portable failure metadata, multi-object replication and verification, idempotent `already-present` behavior, partial-failure/no-rollback behavior, and the public command dispatch.

The final dispatcher integration passed CI run #540 (`35162907869`) at commit `348cf540b6129bc863d0e078f3f5d1023e88d090`. The preceding CLI/integration test commit passed CI run #539 (`35152606363`).

No Orange Pi, AmigaOS, FS-UAE, Greaseweazle, malware sample, proprietary scanner, ROM, or operating-system image is required for M15.2 code qualification.

M15.2 code qualification does not claim remote/off-site transport, trusted time, physical storage independence, or hardware runtime qualification.
