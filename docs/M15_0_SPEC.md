# M15.0 — Off-appliance Evidence Replication

Status: FOUNDATION IMPLEMENTED — M15.1 and M15.2 CODE-QUALIFIED; M15 remains open for later layers.

## Purpose

M15 extends the M13 Portable Evidence Bundle and M14 Authenticated Evidence Ledger chain beyond the local AAA appliance. The objective is to retain independently verifiable evidence objects and ledger checkpoints on storage whose failure and compromise domain is separate from the appliance.

M15 is preservation and replication infrastructure. It does not change malware classification, signature qualification, M13 evidence verification, or M14 ledger semantics.

## Threat model

M14 can detect ledger rollback only relative to a trusted checkpoint that survives independently. If an attacker or storage failure destroys the appliance ledger and every copy of its checkpoints, the local hash chain cannot prove the removed suffix existed.

M15 therefore creates an explicit export/replication boundary so that selected evidence and checkpoint material can survive loss or compromise of the AAA appliance.

The first implementation targets a local mounted destination directory. The destination may in deployment be a separately mounted NAS, removable medium, read-mostly archive volume, or another host-mounted filesystem. Network protocols and cloud providers are not part of M15.0–M15.2.

## Principles

1. **Push only.** AAA exports selected immutable evidence to a destination; the replica never becomes scanner input automatically.
2. **No deletion propagation.** Missing local source objects never cause deletion from a replica.
3. **Content addressed.** Replicated objects are named and verified by SHA-256 rather than trusted source paths.
4. **Write once.** Existing destination objects are accepted only when their bytes match the expected SHA-256 exactly; conflicting bytes fail closed.
5. **No execution.** Replication and verification never execute evidence payloads.
6. **Portable metadata.** Host absolute paths are not serialized into replica metadata.
7. **Independent checkpoint retention.** M14 checkpoint documents are first-class replica objects.
8. **Verification before success.** A copy is successful only after destination bytes have been verified.
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

The `receipts/` namespace is reserved for a later replica-side catalogue/session layer. M15.1 receipts and M15.2 session documents are currently operator-held metadata and are not silently copied there.

## Initial object kinds

M15.1 supports:

- `evidence-bundle` — M13 deterministic evidence ZIP;
- `evidence-signature` — M13 detached evidence signature;
- `evidence-ledger` — exact M14 JSONL ledger snapshot;
- `ledger-checkpoint` — M14 detached checkpoint;
- `checkpoint-trust-store` — checkpoint signer policy when explicitly selected;
- `checkpoint-trust-update` — authenticated checkpoint trust update when explicitly selected.

Third-party scanner binaries, ROMs, operating-system images, private keys and malware samples outside an explicitly selected M13 bundle are never replicated implicitly.

## Implemented layers

### M15.1 — single-object immutable replication

M15.1 implements schema `aaa-evidence-replica-receipt-v1`, content-addressed write-once storage, idempotent exact-object handling, source/root/namespace checks, destination verification and strict portable receipts.

Public CLI:

```text
aaa evidence replicate \
  --destination /mnt/aaa-archive \
  --kind evidence-bundle \
  case.aaa-evidence.zip

aaa evidence replica verify \
  --root /mnt/aaa-archive \
  case.aaa-evidence.zip.replica.json
```

See `docs/M15_1_SPEC.md` and `docs/M15_1_QUALIFICATION.md`.

### M15.2 — deterministic replication sessions

M15.2 layers deterministic multi-object intent and terminal per-object outcomes over M15.1 without claiming transaction atomicity.

Public CLI:

```text
aaa evidence replicate-session \
  --destination /mnt/aaa-archive \
  --session session.json \
  --object evidence-bundle:case.aaa-evidence.zip \
  --object ledger-checkpoint:checkpoint.json

aaa evidence replica verify-session \
  --root /mnt/aaa-archive \
  session.json
```

See `docs/M15_2_SPEC.md` and `docs/M15_2_QUALIFICATION.md`.

## Source and destination safety

Source files use the established AAA opened-file `Stat` + path `Lstat` + `SameFile` identity pattern before hashing/copying. M15 does not claim Linux `O_NOFOLLOW`/`openat` semantics.

The replica root and existing namespace components must be real directories, not symlinks. Destination objects are content-addressed and write-once. If an object already exists, only exact size/SHA-256 identity is accepted as idempotent success.

Temporary copy files remain inside the destination namespace and are not published under the final content-addressed name until copying succeeds. Current M15.1 qualification explicitly proves successful-path cleanup; it does not overstate failure-injection cleanup coverage.

## Relationship to M13 and M14

M13 remains authoritative for bundle structure, offline evidence verification, evidence signatures and evidence-signing trust.

M14 remains authoritative for ledger-chain and checkpoint verification. M15 preserves exact bytes from those systems. A replicated checkpoint is useful for rollback detection only if the verifier also has the appropriate independently trusted checkpoint signer policy/root material.

M15 does not weaken M12's acquisition boundary: replication of an SCP and an ADF does not assert derivation between them.

## Security boundary

M15.0–M15.2 do not provide:

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

## Qualification status

M15.1 and M15.2 are code-qualified in the normal repository CI, including amd64/arm64 build coverage. M15.2 final public dispatcher integration passed CI #540, run `35162907869`, at commit `348cf540b6129bc863d0e078f3f5d1023e88d090`.

No Orange Pi, Greaseweazle, Amiga emulator or historical scanner runtime is required for these code qualifications. Real independent/off-appliance storage deployment remains an operational qualification concern.
