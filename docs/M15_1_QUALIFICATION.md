# M15.1 Qualification — Evidence Replica Core

Status: CODE-QUALIFIED

Date: 2026-09-16

## Qualified scope

M15.1 qualifies the local mounted-directory evidence-replication core and offline replica verification path described in `docs/M15_1_SPEC.md`.

The qualification is intentionally hardware-independent. It validates deterministic evidence-replica metadata and filesystem safety behavior in CI; it does not claim qualification of a particular NAS, removable disk, Orange Pi, remote transport, filesystem durability property, or independent physical failure domain.

## CI evidence

GitHub Actions CI run #530 (`35099094610`) completed successfully for commit `9cfa34d5dbbf8d344a36ef43144db109901ff70c` after the final M15.1 security tests were added.

The qualified implementation includes the earlier namespace-verification hardening and canonical UTC receipt timestamp validation. Run #530 exercised the repository's normal CI after those changes.

## Qualified behavior

The automated suite establishes:

- deterministic SHA-256 content-addressed object naming;
- deterministic LF-terminated receipt serialization and strict round-trip decoding;
- canonical UTC RFC3339Nano `created_at` generation and validation;
- rejection of unsupported schemas/object kinds, malformed SHA-256, invalid size, nonportable names and unsafe notes;
- exact-byte replication and destination SHA-256/size verification;
- idempotent success for an already-present identical object;
- fail-closed handling of conflicting destination content;
- source symlink rejection;
- replica-root symlink rejection;
- namespace symlink rejection during replication;
- namespace symlink rejection during offline verification;
- detection of tampered and missing replica objects;
- no leftover temporary replica files after the successful tested publish path;
- repository formatting/vet/tests and supported amd64/arm64 builds through normal CI.

## Qualification precision

M15.0 called for partial-copy cleanup. The implementation contains deferred cleanup for unpublished temporary files, but the current dedicated test named `TestReplicaLeavesNoTemporaryFiles` proves cleanup after the successful publish path; it does not inject a failure after temporary-file creation. M15.1 therefore does not overstate this point as failure-injection-qualified.

The implementation also does not claim Linux `O_NOFOLLOW`/`openat` race-free semantics. Namespace components are checked with `Lstat`; source bytes are copied from an already-opened descriptor validated with `Stat` + `Lstat` + `SameFile`.

## Receipt placement

M15.0 reserved a `receipts/` directory in the replica namespace. M15.1 deliberately defaults the operator receipt to `SOURCE.replica.json` (or an explicit `--receipt` path). Replica-side receipt cataloguing is deferred rather than silently treating metadata co-located with the replica as independently authoritative.

## Result

M15.1 is **CODE-QUALIFIED** for the implemented local-filesystem evidence-replica primitive.

Physical/off-appliance deployment qualification remains a separate concern: a replica on the same physical disk does not satisfy M15's intended independent-failure-domain preservation goal.
