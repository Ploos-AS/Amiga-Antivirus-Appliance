# M13.6 — Authenticated trust-store updates

Status: IMPLEMENTED — code qualification pending CI

## Purpose

M13.6 adds authenticated distribution and rollback protection for the M13.5 evidence trust store.

The trust store itself remains a policy document and is not self-authenticating. M13.6 introduces a separate pinned Ed25519 root key whose only role is to authenticate trust-store update documents. Evidence-bundle signing keys from M13.4/M13.5 do not become trust roots.

## Update schema

Schema identifier:

`aaa-evidence-trust-update-v1`

Algorithm:

`ed25519`

Fields:

- `schema` — exact schema identifier;
- `algorithm` — `ed25519`;
- `sequence` — monotonically increasing unsigned integer greater than zero;
- `trust_store_sha256` — SHA-256 of the exact serialized trust-store bytes;
- `root_key_id` — SHA-256 of the raw pinned 32-byte Ed25519 root public key;
- `signature` — 64 raw Ed25519 signature bytes encoded as lowercase hexadecimal.

Unknown fields and trailing JSON data are rejected. The detached update document is serialized deterministically with a trailing LF.

## Signed statement

The root key signs the following domain-separated statement:

```text
aaa-evidence-trust-update-v1
ed25519
<SEQUENCE>
<TRUST_STORE_SHA256>
<ROOT_KEY_ID>
```

Each line ends in LF, including the final line.

The signature therefore binds the root identity, sequence number and exact trust-store bytes without embedding a self-selected public key.

## Root trust

The root public key is supplied independently by the operator and is never taken from:

- the trust store being installed;
- an evidence-bundle signature;
- the trust-update document itself.

The trust-update document only carries `root_key_id`; verification recomputes that ID from the pinned root public key.

The root private key is used only by the publishing side. It is not stored in AAA policy files.

## Rollback and replay protection

Verification requires the candidate update sequence to be strictly greater than the last sequence already accepted by the operator:

`new_sequence > current_sequence`

Equal sequence values are replays and are rejected. Lower sequence values are rollbacks and are rejected.

AAA intentionally does not infer the current sequence from the candidate update. The verifier must supply the last accepted sequence from trusted local state or equivalent operator-controlled state. Persisting that state atomically across appliance upgrades is a separate installation concern; M13.6 defines and enforces the cryptographic rollback gate.

## CLI

Create a detached trust update:

```text
aaa trust-update sign \
  --root-private-key <root-private-key> \
  --sequence <n> \
  --output <update.json> \
  <trust-store.json>
```

Verify a candidate update:

```text
aaa trust-update verify \
  --root-public-key <pinned-root-public-key> \
  --current-sequence <last-accepted-sequence> \
  <trust-store.json> \
  <update.json>
```

`--current-sequence` defaults to zero for bootstrap verification only.

Detached update output is write-once and will not replace an existing file.

## Verification gate

Verification succeeds only when all of the following hold:

1. the candidate trust store passes strict M13.5 validation;
2. the update document passes strict schema validation;
3. the update sequence is strictly newer than the supplied current sequence;
4. the pinned root public key derives to `root_key_id`;
5. SHA-256 of the exact trust-store bytes equals `trust_store_sha256`;
6. the Ed25519 signature verifies over the domain-separated update statement.

Any failure rejects the update.

## Security boundaries

M13.6 provides authenticated trust-store distribution and a cryptographic monotonic-sequence gate. It does not provide:

- remote automatic download;
- transparency logging;
- trusted timestamps;
- recovery from loss or compromise of the pinned root private key;
- automatic root-key rotation;
- atomic persistence of the appliance's last accepted sequence.

Root-key rotation requires an explicitly designed higher-level policy and is not inferred from a trust store signed by the current root.

## Qualification

No physical hardware is required for M13.6 code qualification.

Automated qualification covers:

- valid sign/verify flow;
- deterministic update serialization;
- strict unknown/trailing JSON rejection;
- exact trust-store SHA-256 binding;
- pinned root-key-ID binding;
- wrong-root rejection;
- tampered trust-store rejection;
- tampered-signature rejection;
- replay rejection;
- rollback rejection;
- write-once update output;
- strict regular-file/key parsing inherited from existing evidence CLI helpers;
- amd64 and arm64 build qualification through the normal repository CI.
