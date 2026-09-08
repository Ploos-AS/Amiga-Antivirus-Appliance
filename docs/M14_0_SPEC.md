# M14.0 — Authenticated Evidence Ledger specification

Status: SPECIFIED — implementation pending

## Purpose

M14 extends the portable M13 evidence chain with a local append-only ledger of evidence-bundle events. The goal is to make later deletion, replacement, reordering or silent rewriting of recorded evidence history detectable without requiring network services or physical acquisition hardware.

M13 authenticates individual portable evidence objects and trust policy. M14 records the sequence in which those objects entered an operator-controlled evidence history.

The ledger is not a malware classifier, blockchain, public transparency service or trusted timestamp authority.

## Scope

M14.0 defines a versioned hash-chained JSONL ledger. Later M14 steps will implement the model, CLI append/verify operations, persistent appliance integration and optional signed checkpoints.

Initial event types are:

- `bundle-created`;
- `bundle-imported`;
- `bundle-verified`;
- `bundle-signed`;
- `trust-store-installed`.

Every event references an already-existing cryptographic identity. The ledger never embeds malware bytes, private keys or arbitrary host paths.

## Ledger format

Schema identifier:

`aaa-evidence-ledger-v1`

The ledger is UTF-8 JSON Lines. Each line is one deterministic event record followed by LF.

Each record contains:

- `schema` — exactly `aaa-evidence-ledger-v1`;
- `sequence` — unsigned integer starting at 1 and increasing by exactly one;
- `recorded_at` — UTC event metadata timestamp;
- `event` — controlled event type;
- `object_sha256` — lowercase SHA-256 of the referenced portable evidence/trust object;
- `object_kind` — controlled object category;
- `previous_record_sha256` — lowercase SHA-256 of the exact previous record bytes, or 64 zeroes for sequence 1;
- `record_sha256` — SHA-256 of the deterministic record statement defined below;
- optional `note` — human operator metadata with no trust semantics.

Initial object kinds are:

- `evidence-manifest`;
- `evidence-bundle`;
- `evidence-signature`;
- `evidence-trust-store`;
- `evidence-trust-update`.

## Record identity

A record hash must not recursively include itself. AAA computes `record_sha256` over a deterministic domain-separated statement containing all record fields except `record_sha256` itself:

```text
aaa-evidence-ledger-v1
<SEQUENCE>
<RECORDED_AT>
<EVENT>
<OBJECT_KIND>
<OBJECT_SHA256>
<PREVIOUS_RECORD_SHA256>
<NOTE_SHA256>
```

Each line ends in LF, including the final line. `NOTE_SHA256` is SHA-256 of the exact UTF-8 note bytes; an absent note hashes the empty byte string.

The complete deterministic JSON line is then the byte object referenced by the next record's `previous_record_sha256`.

This separates the semantic record statement from JSON formatting while also chaining the exact serialized ledger representation.

## Append contract

Appending an event must:

1. open and validate the complete existing ledger before accepting a new event;
2. fail closed if any existing sequence, schema, controlled value, record hash or previous-record link is invalid;
3. derive the next sequence only from the validated tail;
4. hash the referenced object from an already-opened regular file when the CLI is asked to derive object identity from a file;
5. append exactly one complete deterministic JSON line;
6. fsync the ledger before reporting success;
7. never rewrite, truncate or reorder existing valid records during normal append operation.

The first record uses sequence 1 and a `previous_record_sha256` value of 64 zeroes.

## Verification contract

Offline ledger verification must read from the first byte to EOF and validate every record in order.

Verification fails on:

- unsupported schema;
- unknown JSON fields or trailing JSON data within a line;
- blank or malformed lines;
- sequence gaps, duplicates or reordering;
- malformed or unsupported event/object kinds;
- malformed SHA-256 values;
- incorrect record hashes;
- broken previous-record links;
- a nonzero previous hash on the first record;
- partial final records.

Verification does not execute or automatically open the referenced evidence objects. A later command may optionally cross-check ledger object hashes against explicitly supplied files.

## Timestamp boundary

`recorded_at` is operator/appliance metadata only. Hash chaining makes later modification detectable, but it does not prove that the event occurred at that wall-clock time.

M14 must not describe ledger timestamps as trusted timestamps unless a later milestone explicitly introduces an external timestamp authority.

## Relationship to M13

M13 remains the authority for evidence-manifest hashes, deterministic evidence ZIP identity, detached bundle signatures, signing-key trust policy and authenticated trust-store updates.

M14 records those identities and events. It does not replace M13 verification. A `bundle-verified` event means the operator recorded a verification event; independent consumers should still run the relevant M13 verifier when they need to establish current validity themselves.

A ledger event never promotes an unknown or submitted sample to verified malware.

## Security boundaries

M14.0 does not claim protection against an attacker who can delete the entire ledger and every independently retained checkpoint/reference to its former tail.

A plain local hash chain detects internal modification when a trusted tail or complete expected ledger is available, but it cannot by itself prove that the newest suffix has not been removed.

Later M14 work should therefore add explicit signed checkpoint/tail export using independently trusted keys rather than overstating the guarantees of the local chain.

M14.0 also does not provide:

- a blockchain or consensus protocol;
- public transparency logging;
- remote replication;
- trusted timestamps;
- automatic evidence upload;
- private-key storage;
- malware classification authority.

## Planned CLI

Later M14 steps should provide at least:

```text
aaa evidence ledger append --event <type> --object-kind <kind> --object <file> [--note <text>] [--ledger <path>]
aaa evidence ledger verify [--ledger <path>]
aaa evidence ledger status [--ledger <path>]
```

The appliance default ledger path should live under `/data/aaa/state` and be defined by the implementation milestone rather than inferred by callers.

## Qualification

M14.0 is specification-only and requires no physical hardware.

Implementation qualification must cover at least:

- deterministic record serialization;
- first-record zero-link behavior;
- exact monotonic sequence enforcement;
- valid multi-record chain verification;
- modified-record rejection;
- deleted/interior-record detection through chain/sequence failure;
- reordered-record rejection;
- malformed/partial-line rejection;
- unsupported schema/event/object-kind rejection;
- exact referenced-object SHA-256 derivation;
- regular-file/symlink safety for object hashing;
- append-only behavior and fsync-before-success;
- amd64 and arm64 builds.

No Orange Pi, Amiga, emulator, Greaseweazle or floppy hardware is required for the M14 model and CLI qualification.
