# AAA → AmiGuard signature research bridge

## Purpose

AAA can support AmiGuard signature development by turning qualified AAA signature-factory candidates and historical-scanner evidence into conservative AmiGuard research records.

The bridge is intentionally one-way and research-only. AAA may help discover, normalize and preserve evidence; AmiGuard remains responsible for deciding whether a candidate becomes a production signature.

## Existing AmiGuard contract

The current AmiGuard repository stores bootblock signatures as schema-v1 JSON records below `signatures/bootblocks/`. A concrete byte signature uses an explicit `offset`, `bytes` value and `mask`. AmiGuard also permits research records with `signature: null` while sample qualification is pending.

AAA therefore maps only information it can represent without invention.

## Mapping rules

- AAA fixed-offset `pattern` candidate → AmiGuard research record with the same offset and bytes and an all-`ff` mask.
- AAA any-offset `pattern` candidate → research record with `signature: null`; an AmiGuard fixed offset/mask must be independently derived.
- AAA `bootblock-sha256` candidate → research record with `signature: null`; the hash/evidence identifies the sample but does not invent signature bytes.
- AAA `file-sha256` candidate → research record with `signature: null`; this is not directly an AmiGuard bootblock byte signature.
- every export has `status: research` and `verifier: pending-sample-qualification`.
- the source AAA candidate ID, engine/version, OS profile, signature database version, detection name and confidence are preserved as research provenance.

## Trust and promotion boundary

AAA must never write `status: production` or otherwise claim that an exported record is ready for AmiGuard merely because an AAA candidate exists. Before AmiGuard promotion, the bytes, offset and mask must be independently checked against legally analyzable infected samples and a sufficiently broad clean corpus.

Historical-scanner agreement is useful evidence but is not enough by itself to prove a byte pattern has acceptable specificity.

## Why this helps

AAA already has machinery for candidate creation, evidence correlation, bootblock/file hashes, deterministic signature exports and historical scanner metadata. The bridge lets that work feed AmiGuard without coupling the two projects or requiring AmiGuard to ingest AAA's internal candidate schema directly.

A practical workflow is:

```text
sample/corpus
  -> AAA analysis + historical scanners
  -> AAA candidate/evidence
  -> AAA AmiGuard research export
  -> independent AmiGuard sample/pattern qualification
  -> AmiGuard signature review/test
  -> AmiGuard promotion
```

## Current implementation

`internal/signaturefactory/amiguard.go` provides:

- `ExportAmiGuardResearch(Candidate)`
- `MarshalAmiGuardResearch(Candidate)`

The output intentionally follows the current AmiGuard schema-v1 research shape observed in `Ploos-AS/AmiGuard`, including `source`, `provenance`, `sample_sha256`, `signature`, `verifier`, `cleaner` and a bridge-specific `research` section.

## Next useful extension

The next step is a CLI command that exports selected AAA candidates to an output directory suitable for review/copy into AmiGuard's `signatures/bootblocks/`, followed by a validation job that checks the generated JSON against AmiGuard's own parser/schema tests without automatically committing anything to the AmiGuard repository.
