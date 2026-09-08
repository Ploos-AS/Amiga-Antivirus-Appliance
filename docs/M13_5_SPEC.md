# M13.5 — Evidence trust store and key lifecycle

Status: IMPLEMENTED — code qualification pending CI

## Purpose

M13.5 adds an explicit operator-controlled trust store for the detached Ed25519 evidence-bundle signatures introduced in M13.4.

M13.4 can verify one independently supplied public key. M13.5 adds a stable policy document that can contain multiple trusted keys so operators can perform controlled key rotation and revoke compromised or retired keys without changing the signed evidence bundle or detached signature format.

The trust store is **not self-authenticating**. It must be obtained through an independent trusted channel. A bundle, detached signature, or embedded public key can never add itself to the trust store.

## Trust-store schema

Schema identifier:

`aaa-evidence-trust-store-v1`

Top-level fields:

- `schema` — exactly the schema identifier above;
- `keys` — one or more trust-key records.

Each key record contains:

- `key_id` — SHA-256 of the raw 32-byte Ed25519 public key, lowercase hexadecimal;
- `public_key` — exactly 32 raw Ed25519 public-key bytes encoded as 64 lowercase hexadecimal characters;
- `status` — `active` or `revoked`;
- `label` — optional operator label;
- `not_before` — optional UTC activation time;
- `not_after` — optional UTC exclusive expiry time;
- `revoked_at` — optional UTC administrative revocation time.

`key_id` is recomputed from `public_key` during validation. Duplicate key IDs are rejected. Unknown fields and trailing JSON data are rejected.

`MarshalDeterministic` sorts keys by key ID and emits stable indented JSON with a trailing LF.

## Trust semantics

Only a key with `status: active` can verify a bundle.

An active key is rejected before `not_before` and at or after `not_after` when those fields are present. A key with `status: revoked` is rejected immediately.

An active key must not carry `revoked_at`. A revoked key may carry `revoked_at` for administrative provenance.

M13.4 signatures do not contain a trusted signing timestamp. AAA therefore cannot safely prove that an old signature predates a later revocation. M13.5 intentionally uses fail-closed semantics: once a key is marked revoked in the operator's current trust store, signatures from that key are rejected regardless of when they may have been created.

## Rotation model

Key rotation is performed by trust-store policy rather than by changing evidence bundles:

1. add the replacement public key as `active`;
2. allow an overlap period if desired, with both old and new keys active;
3. begin signing new evidence bundles with the replacement private key;
4. mark the old key `revoked` when it must no longer be trusted.

The trust store may contain multiple simultaneously active keys. This supports planned overlap, multiple approved signing stations, or staged migration.

Private keys never appear in the trust store.

## CLI

Validate a trust store:

```text
aaa evidence trust validate <trust-store.json>
```

Verify an M13.4 signed evidence bundle using the trust store:

```text
aaa evidence verify-trusted \
  --trust-store <trust-store.json> \
  [--signature <bundle.sig>] \
  <bundle.zip>
```

When `--signature` is omitted, AAA reads `<bundle.zip>.sig`.

The verification command resolves `signer_key_id` only from the supplied trust store, applies status and validity-window policy at verification time, then executes the complete M13.4 signed-bundle verification gate.

The existing single-key command remains available:

```text
aaa evidence verify-signed --trusted-key <public-key-file> <bundle.zip>
```

This is useful for direct pinning. `verify-trusted` is the lifecycle-managed path.

## Verification gate

`verify-trusted` succeeds only when all of the following are true:

1. the trust store is structurally and semantically valid;
2. the signature's `signer_key_id` exists in the trust store;
3. the matching key is `active`;
4. the current verification time is inside any configured validity window;
5. the trust-store public key derives to the declared key ID;
6. the complete M13.4 archive, SHA-256 and Ed25519 signature verification succeeds.

A failure at any stage is a verification failure.

## Security boundaries

The trust store is policy, not a certificate authority. M13.5 does not provide:

- automatic key discovery;
- a public-key infrastructure or certificate chain;
- trusted signing timestamps;
- transparency logs;
- remote revocation feeds;
- automatic trust-store updates;
- proof that a label names the real holder of a key.

Operators are responsible for secure trust-store distribution and for deciding when a key becomes active or revoked.

Trust-store files and detached signature files must be ordinary regular files. Symbolic-link paths are rejected by the CLI reader.

## Qualification

No physical hardware is required for M13.5 code qualification.

Automated qualification covers:

- deterministic trust-store serialization;
- strict unknown/trailing JSON rejection;
- public-key/key-ID binding;
- duplicate key-ID rejection;
- multiple-key rotation policy;
- revoked-key rejection;
- `not_before` and `not_after` enforcement;
- active-key `revoked_at` rejection;
- CLI trust-store validation;
- successful active-key `verify-trusted` flow;
- revoked signer rejection through the CLI;
- symbolic-link trust-store rejection;
- complete M13.4 verification after trust resolution.

Hardware/runtime qualification may later use the same trust-store mechanism with physically acquired M12 evidence, but is not required to code-qualify M13.5.
