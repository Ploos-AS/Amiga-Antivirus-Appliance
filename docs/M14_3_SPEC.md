# M14.3 — Signed ledger checkpoints

Status: CODE-QUALIFIED — CI #494 PASS

## Purpose

M14.3 adds detached Ed25519 checkpoints for the append-only evidence ledger introduced by M14.1/M14.2.

The local hash chain already detects interior modification, deletion and reordering when the full expected ledger is available. A separately retained signed checkpoint additionally binds a known ledger prefix so later removal of the ledger suffix can be detected.

A checkpoint is not a trusted timestamp, blockchain consensus proof or malware-classification statement.

## Checkpoint schema

Schema identifier:

`aaa-evidence-ledger-checkpoint-v1`

Algorithm:

`ed25519`

Fields:

- `schema` — exact checkpoint schema;
- `algorithm` — `ed25519`;
- `sequence` — ledger sequence at checkpoint creation;
- `tail_line_sha256` — SHA-256 of the exact sequence-N JSONL record bytes including the trailing LF;
- `tail_record_sha256` — semantic M14.1 record-statement SHA-256 stored inside that record;
- `signer_key_id` — SHA-256 of the raw 32-byte Ed25519 public key;
- `signature` — 64 raw Ed25519 signature bytes encoded as lowercase hexadecimal.

The checkpoint is deterministic JSON with a trailing LF. Unknown fields and trailing JSON data are rejected.

## Signed statement

AAA signs the domain-separated statement:

```text
aaa-evidence-ledger-checkpoint-v1
ed25519
<SEQUENCE>
<TAIL_LINE_SHA256>
<TAIL_RECORD_SHA256>
<SIGNER_KEY_ID>
```

Every line ends with LF, including the final line.

The signature therefore binds the ledger prefix position, the exact serialized record identity, the semantic record identity and the signing key identity.

## CLI

Create a detached checkpoint for the current validated ledger tail:

```text
aaa evidence ledger checkpoint sign \
  --private-key <private-key-file> \
  [--ledger /data/aaa/state/evidence-ledger.jsonl] \
  [--output <checkpoint.json>]
```

When `--output` is omitted, AAA writes `<ledger>.checkpoint.json`.

Verify a checkpoint against a ledger:

```text
aaa evidence ledger checkpoint verify \
  --trusted-key <public-key-file> \
  [--ledger /data/aaa/state/evidence-ledger.jsonl] \
  [--checkpoint <checkpoint.json>]
```

When `--checkpoint` is omitted, AAA reads `<ledger>.checkpoint.json`.

Checkpoint creation is write-once and does not replace an existing output.

## Verification semantics

Checkpoint verification:

1. strictly decodes and validates the checkpoint document;
2. requires the independently supplied trusted public key to derive to `signer_key_id`;
3. verifies the Ed25519 signature over the checkpoint statement;
4. fully validates the current M14 ledger chain;
5. requires the current ledger to contain at least the checkpoint sequence;
6. recomputes the exact JSONL line SHA-256 at the checkpoint sequence;
7. recomputes/reads the semantic record SHA-256 at the same sequence;
8. requires both identities to match the signed checkpoint.

A ledger may legitimately extend beyond the signed checkpoint. Verification succeeds when the signed prefix remains intact and the complete later chain is also valid.

If the current ledger ends before the checkpoint sequence, verification fails. This is the key M14.3 suffix-removal detection property.

## File safety

Ledger reads use the existing M14.2 regular-file, `Lstat`/`SameFile`, shared-`flock`, size-limit and change-during-read checks.

Checkpoint private keys, trusted public keys and checkpoint documents use the existing bounded regular-file readers and reject symbolic-link paths.

Checkpoint output uses write-once creation and fsync before success.

## Trust boundary

The checkpoint signing key must be trusted independently. A checkpoint cannot make its own key trusted.

M14.3 does not prescribe whether the checkpoint key is the same as an M13 evidence signing key or a dedicated ledger-checkpoint key. Operational deployments should prefer an explicitly managed checkpoint key identity when checkpoints are intended as independent history anchors.

M14.3 does not protect against an attacker who can delete both the ledger suffix and every independently retained copy of the corresponding signed checkpoint.

The checkpoint `sequence` and ledger timestamps do not provide trusted wall-clock time.

## Qualification

CI #494 passed the complete repository gate with M14.3 present: formatting, shell/policy checks, module metadata validation, `go vet`, full Go tests, AmiGuard compatibility validation, amd64 build and arm64 build.

Automated tests cover:

- deterministic checkpoint serialization;
- valid sign/verify flow;
- signer key-ID binding;
- wrong-key rejection;
- tampered-signature rejection;
- unknown/trailing JSON rejection;
- empty-ledger checkpoint rejection;
- valid verification after the ledger grows beyond the checkpoint;
- suffix-removal rejection when the ledger is shorter than the checkpoint;
- CLI sign/verify flow;
- write-once checkpoint output.

No physical appliance, Amiga or Greaseweazle hardware is required for M14.3 code qualification.
