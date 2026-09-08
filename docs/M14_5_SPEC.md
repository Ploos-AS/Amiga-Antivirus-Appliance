# M14.5 — Checkpoint trust lifecycle

Status: IMPLEMENTED — code-qualified

## Purpose

M14.5 adds a dedicated trust lifecycle for M14.3 signed ledger checkpoints. A checkpoint can now be verified against an operator-controlled set of approved Ed25519 checkpoint signers instead of requiring exactly one manually supplied public key.

Checkpoint-signing authority is intentionally separated from M13 evidence-bundle signing authority. An `aaa-evidence-trust-store-v1` document is not accepted as checkpoint trust policy.

## Trust-store schema

Schema identifier:

`aaa-evidence-ledger-checkpoint-trust-store-v1`

Each key contains:

- `key_id` — SHA-256 of the raw 32-byte Ed25519 public key;
- `public_key` — the raw public key as lowercase hexadecimal;
- `status` — `active` or `revoked`;
- optional `label`;
- optional UTC `not_before`;
- optional UTC `not_after`;
- optional UTC `revoked_at` for revoked keys.

The trust store must contain at least one key. Duplicate IDs, key-ID/public-key mismatches, unsupported states, malformed timestamps and unknown/trailing JSON are rejected.

Deterministic serialization sorts keys by `key_id`.

## CLI

Validate a checkpoint trust store:

```text
aaa evidence ledger checkpoint trust validate checkpoint-trust.json
```

Verify a checkpoint using checkpoint trust policy:

```text
aaa evidence ledger checkpoint verify-trusted \
  --trust-store checkpoint-trust.json \
  [--ledger /data/aaa/state/evidence-ledger.jsonl] \
  [--checkpoint evidence-ledger.jsonl.checkpoint.json]
```

The existing single-key verifier remains available:

```text
aaa evidence ledger checkpoint verify --trusted-key checkpoint.public ...
```

## Verification semantics

`verify-trusted` performs the complete M14.3 checkpoint verification after resolving the checkpoint's `signer_key_id` through the checkpoint trust store.

The signer must:

1. be present in the checkpoint trust store;
2. be `active`;
3. be inside any configured validity window at verification time;
4. match the public-key-derived key ID;
5. produce a valid Ed25519 checkpoint signature;
6. bind the supplied ledger at the checkpoint sequence through both tail hashes.

Revoked keys fail current verification.

Because M14 checkpoints do not contain a trusted signing timestamp, M14.5 does not claim historical "valid at signing time" semantics. Revocation and validity windows are evaluated at verification time, matching the conservative M13.5 trust model.

## Role separation

M14.5 deliberately uses a different schema from M13.5.

This prevents accidental privilege expansion where a key authorized to sign malware evidence bundles also becomes authorized to attest ledger history. Operators may use the same physical key in both stores if they explicitly choose to, but authorization is represented separately.

## Security boundary

The checkpoint trust store is policy, not self-authenticating truth. Its authenticity and distribution remain the operator's responsibility at this milestone.

M14.5 does not yet provide:

- root-authenticated checkpoint trust-store updates;
- persistent anti-rollback state for checkpoint trust policy;
- trusted signing timestamps;
- automatic remote trust distribution;
- root-key rotation.

Those concerns must be implemented explicitly rather than inherited implicitly from M13 evidence trust.

## Qualification

CI qualification covers:

- active trusted signer verification;
- signer labels;
- revoked signer rejection;
- unknown signer rejection;
- not-yet-valid signer rejection;
- expired signer rejection;
- deterministic trust-store serialization;
- unknown/trailing JSON rejection;
- key-ID/public-key binding;
- unsupported status rejection;
- explicit rejection of the M13 evidence trust-store schema;
- symlink trust-store rejection at the CLI boundary;
- full existing M14.3 checkpoint/ledger verification;
- amd64 and arm64 builds.

Repository CI #504 passed the complete project gate after the M14.5 implementation and tests.

No physical appliance, Amiga, emulator, Greaseweazle or floppy hardware is required for M14.5 qualification.
