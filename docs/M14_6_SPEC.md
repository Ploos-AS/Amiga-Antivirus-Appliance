# M14.6 — Authenticated checkpoint trust-store updates

Status: CODE-QUALIFIED

M14.6 adds authenticated, monotonic updates for the M14.5 checkpoint trust-store role. This state is intentionally separate from the M13 evidence trust state and uses independent schemas, files and root trust.

## Schemas

- checkpoint trust store: `aaa-evidence-ledger-checkpoint-trust-store-v1`
- authenticated update: `aaa-evidence-ledger-checkpoint-trust-update-v1`
- persistent state: `aaa-evidence-ledger-checkpoint-trust-update-state-v1`

Updates use Ed25519. The authenticated statement binds the update schema, algorithm, monotonic sequence, SHA-256 of the exact serialized checkpoint trust store, and the independently pinned root key ID.

## CLI

```text
aaa evidence ledger checkpoint trust-update sign \
  --root-private-key ROOT.private \
  --sequence N \
  --output update.json \
  checkpoint-trust-store.json

aaa evidence ledger checkpoint trust-update verify \
  --root-public-key ROOT.public \
  [--current-sequence N] \
  checkpoint-trust-store.json update.json

aaa evidence ledger checkpoint trust-update install \
  --root-public-key ROOT.public \
  [--state-root /data/aaa/state/checkpoint-trust] \
  checkpoint-trust-store.json update.json

aaa evidence ledger checkpoint trust-update status \
  [--state-root /data/aaa/state/checkpoint-trust]
```

## Persistent state

The default state root is `/data/aaa/state/checkpoint-trust`.

Each accepted store is retained under an immutable sequence-derived filename:

```text
checkpoint-trust-store-00000000000000000001.json
checkpoint-trust-store-00000000000000000002.json
...
```

The mutable pointer is `checkpoint-trust-update-state.json`. Installation verifies the current state before accepting a new update, requires the new sequence to be strictly greater, verifies the pinned root key identity, exact trust-store SHA-256 and Ed25519 signature, fsyncs the immutable store, then atomically replaces and fsyncs the state pointer.

An already-present sequence file is accepted only when its bytes are identical, permitting recovery from a crash after the immutable store was persisted but before the state pointer was updated. Replay and rollback attempts are rejected.

## Security boundary

The pinned root public key remains an external trust anchor. Root rotation is not implemented. This mechanism does not protect against an attacker who can replace the entire checkpoint-trust state directory and the independently pinned root-key source together. It is filesystem-backed rollback detection, not TPM-backed monotonic storage.

Checkpoint trust remains role-separated from M13 evidence signer trust. Possession of an M13 evidence-signing key or trust-store entry does not grant ledger-checkpoint authority.

## Qualification

Code qualification requires strict decoding, deterministic update/state serialization, exact store hashing, wrong-root and tampering rejection, replay rejection, bootstrap install, persistent status, corrupted-installed-store rejection, amd64 build, arm64 build, `go vet`, full tests and the existing AmiGuard compatibility gate.

CI #511 passed all repository gates for the M14.6 implementation.
