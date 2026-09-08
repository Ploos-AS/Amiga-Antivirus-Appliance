# M13.7 — Persistent trust-update state and crash-safe installation

Status: IMPLEMENTED — code qualification pending final CI

## Purpose

M13.7 closes the persistence gap left intentionally open by M13.6. The appliance can now install an authenticated trust-store update while durably recording the last accepted sequence, so replay and rollback protection survives process restarts and appliance reboots.

The installation model is designed so the active trust store and the rollback state never require an unsafe two-file in-place replacement.

## Persistent layout

Default state root:

`/data/aaa/state/evidence-trust`

Installed files:

- `trust-store-<20-digit-sequence>.json` — immutable authenticated M13.5 trust-store bytes;
- `trust-update-state.json` — the single mutable pointer/state record describing the active sequence and trust-store identity.

Example for sequence 42:

- `trust-store-00000000000000000042.json`
- `trust-update-state.json`

Prior immutable trust stores are retained. M13.7 does not automatically prune them.

## State schema

Schema identifier:

`aaa-evidence-trust-update-state-v1`

Fields:

- `schema` — exact schema identifier;
- `sequence` — last durably installed authenticated sequence, greater than zero;
- `trust_store_sha256` — SHA-256 of the exact active trust-store bytes;
- `trust_store_file` — canonical immutable basename derived from `sequence`;
- `root_key_id` — SHA-256 identifier of the independently pinned M13.6 root public key.

The state decoder rejects unknown fields, trailing JSON, malformed hashes, zero sequence, and a filename that does not exactly match the declared sequence.

## Installation command

```text
aaa trust-update install \
  --root-public-key <pinned-root-public-key> \
  [--state-root <dir>] \
  <trust-store.json> \
  <update.json>
```

The default state root is `/data/aaa/state/evidence-trust`.

Status inspection:

```text
aaa trust-update status [--state-root <dir>]
```

`status` validates the complete local state before reporting it. It does not merely print the stored sequence.

## Install gate

Before writing anything, `install`:

1. loads and validates the currently installed state when present;
2. validates that the state-referenced trust-store file still exists, is a regular file, matches the stored SHA-256, and passes strict M13.5 trust-store validation;
3. requires the supplied pinned root public key to match the previously installed `root_key_id` when state already exists;
4. strictly decodes the candidate M13.6 update document;
5. verifies the candidate trust store with the pinned root key;
6. requires `candidate_sequence > installed_sequence` through the existing M13.6 verification gate.

Only after every verification gate succeeds does installation begin.

## Crash-safe commit model

M13.7 deliberately does not replace an active trust-store file in place.

For sequence `N`, installation first writes the exact candidate bytes to the immutable path:

`trust-store-N.json`

The file is created with exclusive-create semantics and fsynced. The state directory is then fsynced.

If the immutable filename already exists, installation succeeds only when its bytes exactly match the verified candidate. This permits recovery from a prior interruption that occurred after the store file became durable but before the state pointer was committed. Different bytes at the same sequence are rejected.

After the immutable store is durable, AAA writes the new state document to a temporary file in the same directory, fsyncs it, atomically renames it to `trust-update-state.json`, and fsyncs the directory again.

Therefore:

- interruption before the state rename can leave only an unreferenced immutable store file; the previous installed state remains authoritative;
- retry with the same verified bytes can safely complete the commit;
- interruption after the state rename leaves a state record that points to a trust store that was already made durable;
- prior trust-store versions remain available as historical local evidence but are not automatically reactivated.

## Recovery and fail-closed behavior

The local state is treated as a compound integrity record. Loading it fails if:

- the state file is malformed;
- its referenced immutable store is missing;
- the referenced file is not a regular file;
- the trust-store SHA-256 differs from the state record;
- the trust store no longer passes strict M13.5 validation.

AAA will not silently reset the current sequence to zero when an installed state file exists but is invalid. Operator intervention is required.

A different pinned root key is also rejected after bootstrap. Root-key rotation remains outside M13.7 and requires an explicit future policy rather than an implicit local override.

## Security boundaries

M13.7 provides durable local rollback state and crash-safe trust-store activation on the appliance filesystem. It does not provide:

- remote trust-store discovery or download;
- root-key rotation;
- automatic deletion of historical trust-store versions;
- protection against an attacker who can arbitrarily rewrite both the entire state directory and the independently pinned root-key source;
- hardware-backed monotonic counters or TPM-backed rollback resistance.

The security claim assumes the appliance persistent state directory and pinned root-key source have the normal integrity protections expected for `/data/aaa` and appliance configuration.

## Qualification

No physical Amiga or Greaseweazle hardware is required for M13.7 code qualification.

Automated qualification covers:

- strict persistent-state schema validation;
- deterministic state serialization;
- sequence-to-filename binding;
- successful bootstrap installation;
- replay rejection using persisted sequence state;
- forward sequence advancement;
- retention of the prior immutable trust-store file;
- recovery from a matching orphan store file left before state commit;
- rejection of a conflicting immutable store at the same sequence;
- rejection of a tampered active trust store;
- normal repository format, vet, test, AmiGuard compatibility, amd64 and arm64 build gates.
