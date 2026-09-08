# M14 — Authenticated Evidence Ledger qualification

Status: CODE-QUALIFIED through M14.7. No physical hardware gate is required.

## Qualified scope

M14 adds a local append-only evidence ledger and independently portable signed checkpoints without changing malware classification or replacing M13 evidence verification.

The qualified chain covers:

- deterministic `aaa-evidence-ledger-v1` JSONL records with exact sequence enforcement;
- semantic record hashes plus exact serialized-line hash chaining;
- full-ledger fail-closed verification before append;
- object SHA-256 derivation from opened regular files;
- append persistence with advisory locking, file/path identity checks and fsync;
- detached Ed25519 ledger checkpoints that bind a verified ledger sequence to the exact line SHA-256;
- verification of older checkpoints after legitimate later appends while rejecting truncation below, or rewriting at, the checkpointed sequence;
- checkpoint signer trust stores with active/revoked state and optional validity windows;
- root-authenticated checkpoint trust-store updates with monotonic sequence/replay and rollback rejection;
- persistent immutable checkpoint trust-store versions plus atomic active-state pointer;
- direct `verify-installed` consumption of the authenticated installed checkpoint trust policy.

M14.7 CI #515 passed the repository gates including formatting, vet, tests, AmiGuard compatibility and amd64/arm64 builds.

## Security and provenance boundaries

The ledger is not a malware classifier, blockchain, public transparency service or trusted timestamp authority. `recorded_at` is metadata, not trusted time. A `bundle-verified` ledger event records that an event was asserted; independent consumers must still use the M13 evidence verifier for the referenced object.

The local hash chain alone cannot prove that the newest suffix, or the entire ledger, was not removed. Detection of rollback is relative to a checkpoint that survives independently and whose signer is trusted. If an attacker can delete both the ledger suffix and every independently retained trusted checkpoint/reference, the ledger alone cannot detect that deletion.

Checkpoint signatures have no trusted signing timestamp. Signer validity and revocation are evaluated under the trust policy at verification time.

The persistent checkpoint trust state provides authenticated monotonic update policy at the application/filesystem layer. It is not TPM-backed monotonic storage. It does not protect against an attacker able to rewrite the entire checkpoint-trust state directory together with the independently pinned root-key source. Root-key rotation, remote transparency/replication and trusted timestamping are outside M14.

Advisory file locking serializes cooperating AAA writers; it does not stop privileged or non-cooperating processes that ignore those locks. File hardening uses opened-file `Stat`, path `Lstat` and `SameFile` identity checks rather than claiming `O_NOFOLLOW` semantics.

## Relationship to M13

M13 remains the authority for portable evidence manifests/bundles, detached evidence signatures and evidence-signing trust. M14 records and checkpoints evidence-related events. Checkpoint signer authorization is a separate trust role and is not implicitly granted to M13 evidence-signing keys.

M12 acquisition semantics also remain unchanged: a same-session SCP and ADF relationship does not assert that the ADF was derived from the SCP.

## Qualification result

M14.0–M14.7 are closed as code-qualified. No Orange Pi, Greaseweazle, Amiga emulator or historical scanner runtime is required to qualify this milestone. Existing M0/M8/M9/M10/M11/M12 hardware/runtime gates remain pending independently.
