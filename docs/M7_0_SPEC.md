# M7.0 — Signature Factory foundation

## Goal

Build the local, provenance-first infrastructure that turns confirmed malware detections into reviewable AAA signature candidates without automatically publishing broad signatures or storing malware samples in Git.

The Signature Factory is mandatory infrastructure for later native signatures, ClamAV export, historical-engine correlation, corpus validation, and signature distribution.

## Status

**Code-qualified.** The schema, persistent store, automatic exact-candidate recording, and explicit lifecycle CLI are implemented and qualified in GitHub Actions for linux/amd64 and linux/arm64. See `docs/M7_0_QUALIFICATION.md`.

Reference-appliance runtime qualification remains pending as part of the broader appliance qualification and is not required to proceed to M7.1.

## Safety and trust model

- A detection may create a **candidate**; it does not automatically become a trusted/published signature.
- Exact SHA-256 candidates may be generated from confirmed infected evidence.
- Pattern signatures require separate validation against clean and malware corpora before promotion.
- Correlated frontends using the same underlying engine/database are not counted as independent corroboration.
- Candidate provenance is mandatory: source engine, engine/database version where known, detection name, sample hash, format and evidence must remain attributable.
- Malware binaries and disk images are never committed to the Git repository.
- Submitted historical material is never automatically deleted.
- Factory state is local under `/data/aaa/signatures` by default.
- Invalid, incomplete, conflicting or unsupported candidate records fail closed.

## Persistent layout

```text
/data/aaa/signatures/
├── candidates/
├── promoted/
├── generated/
│   ├── aaa/
│   └── clamav/
├── rejected/
└── state/
```

Candidate, promoted and rejected records are immutable evidence records in normal operation. State files may track indexes/build metadata but must not replace candidate provenance.

## Candidate schema

M7.0 uses schema version 1:

```json
{
  "schema": 1,
  "id": "AAA.Amiga.<family>.<id>",
  "status": "candidate",
  "kind": "file-sha256 | bootblock-sha256 | pattern",
  "malware_name": "...",
  "sample_sha256": "...",
  "bootblock_sha256": "...",
  "sample_size": 12345,
  "format": "adf | hunk | ...",
  "source_engine": "virusz | virusexecutor | clamav | aaa-native | ...",
  "source_version": "...",
  "os_profile": "os13 | os204 | os31 | os32",
  "signature_db_version": "...",
  "detection_name": "...",
  "confidence": "single-engine | corroborated | confirmed",
  "evidence": [],
  "created_at": "...",
  "created_by": "aaa-signature-factory"
}
```

Fields not applicable to a candidate kind may be omitted. SHA-256 values must be lowercase hexadecimal and exactly 64 characters. IDs, statuses and kinds are validated rather than accepted as arbitrary strings.

## Candidate lifecycle

The initial lifecycle is:

`detection → candidate → validate → promote | reject → build/export`

Promotion is explicit. M7.0 does not silently promote a candidate merely because a scanner reported malware.

A later corpus-validation milestone may automate confidence changes when independent evidence meets documented policy, but publication still remains attributable and reproducible.

## CLI

```text
aaa signatures candidates [--json]
aaa signatures validate
aaa signatures promote <id>
aaa signatures reject <id>
```

`aaa signatures build` and `aaa signatures export clamav` are intentionally deferred to M7.2, where generated signature formats and export semantics are qualified explicitly.

## Candidate generation policy

### File SHA-256

A confirmed infected file may produce an exact `file-sha256` candidate containing the original sample SHA-256, sample size, format and detection provenance. Exact hashes identify only that exact byte sequence and therefore do not imply family-wide coverage.

For infected archive members, AAA records the exact member hash rather than treating only the outer ZIP/LHA/LZX container hash as the malware identity.

### Bootblock SHA-256

A confirmed infected Amiga bootblock may produce an exact `bootblock-sha256` candidate. The bootblock hash is the hash of the exact bootblock bytes used by AAA's bootblock analysis. The containing disk/sample hash remains provenance evidence and is not confused with the bootblock hash.

### Pattern

Pattern candidates are intentionally stricter and remain disabled in M7.0. A detection alone is insufficient to publish a pattern. Pattern derivation, clean-corpus checks, malware-corpus coverage and false-positive controls belong to M7.3 and later qualification.

## Engine provenance

Every generated candidate identifies the source of the detection. Examples include `aaa-native`, `clamav`, `virusz`, `virusexecutor`, `viruschecker2`, `virusslayer2`, `mill`, and `vtschutz`.

When version/database identity is available it must be recorded. Raw engine evidence may be referenced or summarized, but a generated signature must remain reproducible from structured provenance rather than an unexplained final verdict.

M7.1 strengthens this model with normalized evidence records and explicit cross-engine correlation/independence rules.

## M7 sequence

- **M7.0 Signature Factory** — schema, local store, exact candidate creation/validation, automatic infected-result recording, and lifecycle primitives. **Code-qualified.**
- **M7.1 Evidence/provenance** — normalized evidence records and stronger cross-engine attribution.
- **M7.2 ClamAV export** — deterministic generation of supported ClamAV signature forms from promoted records.
- **M7.3 Corpus validation** — clean/malware corpus gates, false-positive checks and pattern qualification.
- **M7.4 Signature distribution** — signed/versioned generated databases and update workflow.

## M7.0 code qualification

M7.0 is code-qualified because:

- schema-v1 candidate structs and strict validation exist;
- the persistent directory model can be created safely;
- candidate filenames are derived from validated IDs rather than untrusted paths;
- exact file/bootblock SHA-256 candidates can be written deterministically and read back;
- duplicate candidate creation is idempotent or fails safely without overwriting conflicting evidence;
- malformed records and path traversal attempts fail closed;
- infected scan results can record exact candidates without auto-promotion;
- lifecycle listing, validation, promotion and rejection are explicit CLI operations;
- no malware payload is required in repository tests;
- tests use synthetic hashes/evidence only;
- gofmt, vet, tests, linux/amd64 build and linux/arm64 build pass.

Final qualification evidence is recorded in `docs/M7_0_QUALIFICATION.md`.

## Non-goals for M7.0

M7.0 does not automatically invent byte patterns, publish candidates, download malware, commit samples, claim scanner engines are independent when they share a database, or replace the existing curated bootblock signature database. ClamAV export, corpus qualification and public distribution are subsequent milestones.
