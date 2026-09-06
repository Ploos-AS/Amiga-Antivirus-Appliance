# AAA → AmiGuard signature research bridge

## Purpose

AAA can support AmiGuard signature development by turning qualified AAA signature-factory candidates and historical-scanner evidence into conservative AmiGuard research records.

The bridge is intentionally one-way and research-only. AAA may help discover, normalize and preserve evidence; AmiGuard remains responsible for deciding whether a candidate becomes a verified native signature.

## AmiGuard compiler contract

The bridge is aligned to the actual schema-v1 validation implemented by `Ploos-AS/AmiGuard` `tools/compile_signatures.py` at AmiGuard commit:

```text
ebdd5833615adc1e8b327aac4a0cb7e1a8217d3f
```

For a record with `status: research`, AmiGuard requires:

```text
schema = 1
kind = bootblock
synthetic = false
sample_sha256 = null
signature = null
```

This is stricter than merely allowing an unverified signature object. Therefore AAA never places an unverified sample hash or byte signature in AmiGuard's production-bearing top-level fields.

## Mapping rules

- AAA fixed-offset `pattern` candidate → AmiGuard `research` record with top-level `signature: null`; the same offset/bytes and an all-`ff` mask are preserved only as `research.proposed_signature`.
- AAA any-offset `pattern` candidate → `research` record with no proposed fixed signature; an AmiGuard offset/mask must be independently derived.
- AAA `bootblock-sha256` candidate → `research` record with `sample_sha256: null` and `signature: null`; AAA's sample and bootblock hashes remain inside the `research` provenance object.
- AAA `file-sha256` candidate → research-only provenance; it is not directly representable as an AmiGuard bootblock byte signature.
- every export has `status: research`, `synthetic: false`, `verifier: pending-sample-qualification` and `cleaner: none`.
- AAA candidate ID, hashes, engine/version, OS profile, signature database version, detection name and confidence are preserved as research metadata rather than verification claims.

## Trust and promotion boundary

AAA must never write a verified AmiGuard record merely because an AAA candidate exists. Before AmiGuard promotion, sample identity plus any proposed bytes, offset and mask must be independently checked against legally analyzable infected samples and a sufficiently broad clean corpus.

Historical-scanner agreement is useful evidence but is not enough by itself to prove a byte pattern has acceptable specificity.

## Why this helps

AAA already has machinery for candidate creation, evidence correlation, bootblock/file hashes, deterministic signature exports and historical scanner metadata. The bridge lets that work feed AmiGuard without coupling the two projects or requiring AmiGuard to ingest AAA's internal candidate schema directly.

A practical workflow is:

```text
sample/corpus
  -> AAA analysis + historical scanners
  -> AAA candidate/evidence
  -> AAA AmiGuard research export
  -> AmiGuard compiler accepts research record
  -> independent AmiGuard sample/pattern qualification
  -> AmiGuard review/test
  -> AmiGuard verified signature
```

## Current implementation

`internal/signaturefactory/amiguard.go` provides:

- `ExportAmiGuardResearch(Candidate)`
- `MarshalAmiGuardResearch(Candidate)`

The CLI exposes a selected stored candidate as deterministic AmiGuard research JSON:

```text
aaa signatures export amiguard <AAA-candidate-id>
```

The JSON is written to stdout so it can be reviewed directly or redirected into a file before being copied to AmiGuard, for example:

```text
aaa signatures export amiguard AAA.Amiga.Example.0123456789abcdef > example-research.json
```

The CLI reads only an existing validated AAA candidate. It does not write to the AmiGuard repository and it cannot promote an AmiGuard record.

## Cross-repository qualification

AAA tests now encode the exact AmiGuard research-state invariants above. The important compatibility correction is that both top-level `sample_sha256` and `signature` remain null for research records. AAA-specific sample hashes and proposed fixed-offset patterns are retained under the open-ended `research` object, which AmiGuard currently permits.

This contract was derived from AmiGuard's own compiler rather than inferred only from existing JSON examples.

## Next useful extension

The next useful extension is a batch export directory plus a CI job that checks a generated AAA fixture by invoking a pinned copy/check-out of AmiGuard's own `tools/compile_signatures.py`, so compatibility drift becomes visible automatically when either repository changes.
