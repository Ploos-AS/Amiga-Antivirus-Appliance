# M15.0 — Off-appliance Evidence Replication

Status: SPECIFIED — implementation pending.

## Purpose

M15 extends the M13 Portable Evidence Bundle and M14 Authenticated Evidence Ledger chain beyond the local AAA appliance. The objective is to retain independently verifiable evidence objects and ledger checkpoints on storage whose failure and compromise domain is separate from the appliance.

M15 is preservation and replication infrastructure. It does not change malware classification, signature qualification, M13 evidence verification, or M14 ledger semantics.

## Threat model

M14 can detect ledger rollback only relative to a trusted checkpoint that survives independently. If an attacker or storage failure destroys the appliance ledger and every copy of its checkpoints, the local hash chain cannot prove the removed suffix existed.

M15 therefore creates an explicit export/replication boundary so that selected evidence and checkpoint material can survive loss or compromise of the AAA appliance.

The first implementation targets a local mounted destination directory. The destination may in deployment be a separately mounted NAS, removable medium, read-mostly archive volume, or another host-mounted filesystem. Network protocols and cloud providers are not part of M15.0.

## Principles

1. **Push only.** AAA exports selected immutable evidence to a destination; the replica never becomes scanner input automatically.
2. **No deletion propagation.** Missing local source objects never cause deletion from a replica.
3. **Content addressed.** Replicated objects are named and verified by SHA-256 rather than trusted source paths.
4. **Write once.** Existing destination objects are accepted only when their bytes match the expected SHA-256 exactly; conflicting bytes fail closed.
5. **No execution.** Replication and verification never execute evidence payloads.
6. **Portable metadata.** Host absolute paths are not serialized into replica manifests.
7. **Independent checkpoint retention.** M14 checkpoint documents are first-class replica objects.
8. **Verification before success.** A copy is successful only after destination bytes have been re-opened and verified.
9. **No false atomicity.** Replicating multiple objects is not claimed to be one atomic filesystem transaction. Completed immutable objects remain valid if a later object fails.
10. **No automatic trust promotion.** Replication proves byte identity and retention, not malware authenticity or signer authorization.

## M15 replica layout

A replica root uses a versioned namespace:

```text
<replica-root>/
└── aaa-replica-v1/
    ├── objects/
    │   └── sha256/
    │       └── <first-two-hex>/
    │           └── <64-hex-sha256>
    └── receipts/
```

Objects contain exact source bytes. File extensions and source basenames are deliberately not authoritative in the object store.

## Initial object kinds

M15.1 should support at least:

- `evidence-bundle` — M13 deterministic evidence ZIP;
- `evidence-signature` — M13 detached evidence signature;
- `evidence-ledger` — exact M14 JSONL ledger snapshot;
- `ledger-checkpoint` — M14 detached checkpoint;
- `checkpoint-trust-store` — checkpoint signer policy when explicitly selected;
- `checkpoint-trust-update` — authenticated checkpoint trust update when explicitly selected.

Third-party scanner binaries, ROMs, operating-system images, private keys and malware samples outside an explicitly selected M13 bundle are never replicated implicitly.

## Receipt schema

M15.1 should introduce `aaa-evidence-replica-receipt-v1` with deterministic JSON representation.

Required fields:

- `schema`
- `created_at` — metadata timestamp, not trusted time;
- `object_kind`
- `sha256`
- `size`
- `replica_name` — portable relative object name below the replica namespace

Optional fields may include a human operator note. Absolute source or destination host paths must not be serialized.

A receipt is evidence that AAA copied and re-verified bytes at a destination at an operator-observed time. It is not a remote attestation and is not proof that the replica still exists later.

## Proposed CLI

```text
aaa evidence replicate \
  --destination /mnt/aaa-archive \
  --kind evidence-bundle \
  case.aaa-evidence.zip

aaa evidence replica verify \
  --root /mnt/aaa-archive \
  receipt.json
```

Later M15 layers may add batch/session manifests and remote transports. M15.0 deliberately does not select SSH, rsync, S3, WebDAV, SMB, NFS, object storage, or cloud-specific APIs.

## Source and destination safety

Source files must be regular files and should use the established AAA opened-file `Stat` + path `Lstat` + `SameFile` identity pattern before hashing/copying. M15 does not claim Linux `O_NOFOLLOW` semantics.

The replica root and namespace must be real directories, not symlinks. Destination object creation must be exclusive. If the content-addressed object already exists, AAA must verify exact size and SHA-256 and treat only an exact match as idempotent success.

Temporary files, if used, must remain within the destination namespace and must not be followed through symlinks. A failed partial copy must not be published under the final content-addressed object name.

## Relationship to M13 and M14

M13 remains authoritative for bundle structure, offline evidence verification, evidence signatures and evidence-signing trust.

M14 remains authoritative for ledger-chain and checkpoint verification. M15 preserves exact bytes from those systems. A replicated checkpoint is useful for rollback detection only if the verifier also has the appropriate independently trusted checkpoint signer policy/root material.

M15 must not weaken M12's acquisition boundary: replication of an SCP and an ADF does not assert derivation between them.

## Security boundary

M15.0 does not provide:

- trusted timestamps;
- remote attestation;
- Byzantine consensus or blockchain semantics;
- automatic off-site networking;
- encryption at rest;
- private-key escrow;
- WORM guarantees supplied by hardware/storage;
- protection when the appliance and every replica are compromised by the same actor;
- proof of continued replica existence after the last verification.

A mounted directory on the same physical disk is technically supported but does not satisfy the intended independent-failure-domain deployment goal.

## Planned qualification

M15.1 implementation should prove in CI:

- deterministic content-addressed destination naming;
- exact byte preservation and SHA-256 binding;
- idempotent re-copy of identical objects;
- fail-closed conflict handling;
- source symlink rejection;
- replica-root/namespace symlink rejection;
- partial-copy cleanup;
- receipt strict decoding and deterministic serialization;
- no absolute host paths in receipts;
- offline replica verification detects missing/tampered objects;
- amd64 and arm64 builds.

No Orange Pi, Greaseweazle, Amiga emulator or historical scanner runtime is required for the M15.0 specification or M15.1 core implementation.
