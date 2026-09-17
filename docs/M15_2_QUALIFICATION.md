# M15.2 Qualification — Deterministic Replication Sessions

Status: CODE-QUALIFIED

Date: 2026-09-17

## Qualified scope

M15.2 adds deterministic multi-object replication sessions on top of the M15.1 immutable content-addressed replica primitive.

The qualified implementation provides:

- schema `aaa-evidence-replica-session-v1`;
- deterministic session intent ordering and SHA-256 `session_id`;
- identity independent of metadata timestamp, result state, CLI ordering, host source path and destination path;
- strict LF-terminated JSON decoding and validation;
- terminal per-object results: `replicated`, `already-present`, or `failed`;
- stable portable error classes for serialized failures;
- `aaa evidence replicate-session`;
- `aaa evidence replica verify-session`;
- continuation after an individual replication failure without rollback of already published immutable objects;
- verification of every object reported as replicated/already-present;
- non-success verification for sessions containing failed entries;
- M15.1 replica-root and namespace safety checks retained during verification.

## CI evidence

The M15.2 model was made green before CLI integration. CLI/integration tests then passed CI #539, run `35152606363`, at commit `40b6875e8e748f6e35f7144de702897b85a70b9e`.

The public `aaa evidence replicate-session` dispatcher integration passed CI #540, run `35162907869`, at commit `348cf540b6129bc863d0e078f3f5d1023e88d090`.

The normal CI includes formatting, vet/tests and amd64/arm64 build coverage.

## Precision and limitations

M15.2 is not a multi-object filesystem transaction. A successful object remains valid when a later object fails.

Session timestamps are metadata and are not trusted timestamps. Session identity binds canonical object intent, not execution time or outcome.

The session document is operator-held metadata. It is not automatically replicated into the content-addressed object namespace and is not an independent witness merely because it is stored beside a replica.

The implementation does not claim network transport, remote attestation, encryption at rest, WORM storage, consensus/blockchain semantics, remote availability, physical failure-domain independence, or protection when every copy is compromised by the same actor.

M15.2 requires no Orange Pi, AmigaOS, emulator, Greaseweazle, malware sample, ROM, proprietary scanner, or other historical binary for code qualification.

## Result

M15.2 is CODE-QUALIFIED. Physical deployment of a replica on genuinely independent storage remains an operational/deployment concern rather than a prerequisite for this code qualification.
