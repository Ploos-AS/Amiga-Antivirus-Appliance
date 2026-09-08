# M14.2 — Evidence ledger CLI and append-only persistence

Status: CODE-QUALIFIED — CI #488 passed; no physical hardware required

## Purpose

M14.2 exposes the M14.1 authenticated evidence-ledger model through the public `aaa evidence ledger` CLI and adds persistent append-only JSONL storage.

The implementation validates the complete existing chain before every append, derives the next sequence only from the validated tail, hashes the referenced evidence object from an opened regular file, appends exactly one deterministic record and fsyncs the ledger before reporting success.

## Default path

The appliance default ledger path is:

`/data/aaa/state/evidence-ledger.jsonl`

A different path can be supplied with `--ledger` for testing, export workflows or operator-controlled deployments.

The current ledger size limit is 64 MiB. Verification and append fail closed when the limit is exceeded.

## CLI

Append one event:

```text
aaa evidence ledger append \
  --event bundle-created \
  --object-kind evidence-bundle \
  --object case.aaa-evidence.zip \
  [--note "operator metadata"] \
  [--ledger /data/aaa/state/evidence-ledger.jsonl]
```

Verify the complete chain:

```text
aaa evidence ledger verify \
  [--ledger /data/aaa/state/evidence-ledger.jsonl]
```

Inspect the verified tail:

```text
aaa evidence ledger status \
  [--ledger /data/aaa/state/evidence-ledger.jsonl]
```

`status` reports record count, tail sequence, exact tail-line SHA-256 and the semantic tail record SHA-256. A missing ledger is reported explicitly rather than being silently created by `status`.

## Append gate

Before appending, AAA:

1. hashes the explicitly supplied object using the existing post-open regular-file/path identity checks;
2. creates the ledger parent directory when needed;
3. opens or creates the ledger as a regular file;
4. takes an advisory exclusive file lock;
5. binds the opened descriptor to the current path with `Stat`, `Lstat` and `SameFile`;
6. reads the complete ledger under the 64 MiB bound;
7. verifies the complete M14.1 chain from byte 0 to EOF;
8. derives the next sequence from the verified tail only;
9. passes the exact previous JSONL record bytes, including LF, to the M14.1 record builder;
10. rechecks ledger path identity and byte size before writing;
11. appends one deterministic LF-terminated record;
12. fsyncs the ledger and state directory before reporting success;
13. performs a complete post-append verification before the CLI reports the resulting tail.

An invalid existing ledger is never repaired, truncated or overwritten by append. Operator intervention is required.

## Concurrency boundary

M14.2 uses advisory `flock` locking around append and shared locking around verification/status. Cooperating AAA processes therefore serialize append operations and do not independently derive the same next sequence.

The lock is advisory. M14.2 does not claim protection against unrelated privileged software that deliberately ignores advisory locks and mutates the ledger behind AAA.

## Object identity

`--object` is not serialized as a host path. AAA records only its exact SHA-256 plus the selected controlled object kind.

Object hashing uses an already-opened descriptor and requires the opened file and current path to remain the same ordinary regular file through the hash operation. Symbolic-link object paths and path replacement are rejected by the shared evidence hashing helper.

The ledger records the object identity observed at append time. It does not retain or copy the object bytes.

## Verification and status

`verify` and `status`:

- require the ledger path to resolve to the same ordinary regular file that was opened;
- take a shared advisory lock;
- enforce the 64 MiB bound;
- require stable size and modification time while reading;
- execute the complete M14.1 chain verifier;
- never execute or automatically open referenced evidence objects.

An empty existing ledger is structurally valid and reports zero records. A missing ledger is an error for `verify` and an explicit "no evidence ledger" state for `status`.

## Security boundaries

M14.2 preserves the M14.0 boundary: the local hash chain detects modification, deletion/reordering inside the retained chain and malformed state, but by itself cannot prove that a newest suffix or the entire ledger was not deleted if no independent trusted tail/checkpoint exists.

M14.2 does not provide:

- trusted timestamps;
- public transparency logging;
- blockchain/consensus semantics;
- remote replication;
- automatic evidence-object re-verification;
- protection against deletion of both the ledger and every independent reference to its prior tail;
- signed tail/checkpoint authentication.

Signed portable checkpoints remain the intended next M14 layer.

## Qualification

CI #488 passed the normal repository gates with M14.2 present: formatting, policy checks, module metadata, `go vet`, complete Go tests, AmiGuard compatibility, amd64 build and arm64 build.

Automated M14.2 coverage includes:

- first append and second append through the public command implementation;
- exact evidence-object SHA-256 recording;
- prefix preservation proving normal append does not rewrite earlier bytes;
- complete verify and status flows;
- invalid/partial existing-ledger rejection without modification;
- symbolic-link object rejection;
- symbolic-link ledger rejection;
- missing-ledger status;
- invalid event rejection;
- existing M14.1 deterministic chain/tamper/reorder/sequence tests.

No Orange Pi, Amiga, emulator, Greaseweazle or floppy hardware is required for M14.2 code qualification.
