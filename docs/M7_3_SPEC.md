# M7.3 — Corpus validation and pattern qualification

## Goal

M7.3 defines the fail-closed validation gate that must exist before AAA may promote or publish broad byte-pattern signatures. Exact SHA-256 signatures remain governed by the already-qualified M7.0–M7.2 lifecycle; M7.3 does not weaken those rules.

The milestone separates three activities that must not be conflated:

1. deriving a candidate pattern from attributable malware evidence;
2. validating that pattern against explicitly identified clean and malware corpora;
3. deciding whether the validated result is eligible for explicit promotion/publication.

A scanner detection alone is never sufficient evidence for a pattern signature.

## Status

**Foundation / qualification in progress.**

M7.3 starts from the M7.2 code-qualified HEAD. Pattern candidates are deliberately still rejected by schema-v1 candidate validation until the M7.3 pattern record and corpus-result contract below are implemented and tested.

## Trust model

M7.3 is preservation-first and fail-closed:

- malware samples and clean corpus payloads are not committed to Git;
- corpus identities and validation results are metadata, not substitutes for the underlying local corpus;
- clean and malware corpora must be independently identified and reproducible by manifest identity;
- a pattern with any clean-corpus match is not eligible for promotion;
- malformed, incomplete, ambiguous, stale or mismatched corpus evidence fails qualification;
- validation results are bound to the exact candidate pattern and exact corpus manifests used;
- validation never silently rewrites a candidate pattern to make it pass;
- publication remains explicit; passing corpus gates does not itself publish a signature.

## Corpus classes

M7.3 uses two explicit corpus classes.

### Clean corpus

The clean corpus contains material that has been deliberately admitted as expected-benign Amiga software/data for false-positive testing. Admission provenance must be retained outside or alongside the local corpus manifest.

A pattern candidate must produce **zero matches** in the qualified clean corpus. Any match is a hard false-positive gate failure.

The absence of a match does not prove universal safety; the qualification record must state the corpus size and manifest identity rather than claiming zero false positives globally.

### Malware corpus

The malware corpus contains attributable malware samples or preservation images held outside Git. M7.3 uses it to measure exact pattern coverage, not to infer family identity from filenames or directory names.

Coverage is reported as counts and exact sample identities. A pattern may not claim coverage beyond the samples actually matched.

## Corpus manifest contract

Each corpus validation run must be bound to an immutable manifest containing at least:

- schema version;
- corpus class (`clean` or `malware`);
- stable corpus identifier;
- manifest creation timestamp;
- deterministic list of sample SHA-256 values;
- sample size for each entry;
- optional format/provenance metadata that does not alter sample identity.

The manifest identity is the SHA-256 of its canonical serialized bytes. Validation evidence records that manifest SHA-256 and sample count.

Paths are operational inputs only and are not corpus identity. Absolute host paths must not be embedded into generated/public signature records.

## Pattern candidate contract

Pattern candidates remain disabled until the schema can represent the exact bytes being qualified without ambiguity.

The initial M7.3 pattern form will be intentionally narrow:

- fixed byte sequence only;
- no regular expressions;
- no executable code;
- no shell expressions;
- no unbounded wildcard language;
- explicit byte offset semantics if an offset constraint is used;
- deterministic canonical encoding;
- minimum pattern length defined and tested before enablement.

The pattern candidate must retain the existing provenance fields and evidence model. Pattern identity must be derived from canonical pattern bytes/constraints, not from a malware filename.

More expressive wildcard/logical signatures are later work and require their own false-positive qualification.

## Validation result contract

A corpus validation result must be reproducible from:

- candidate ID;
- canonical pattern identity/hash;
- clean corpus manifest SHA-256;
- malware corpus manifest SHA-256;
- validation implementation/schema version;
- clean sample count and clean match count;
- malware sample count and malware match count;
- deterministic identities of every matched sample;
- validation timestamp.

A result is invalid if its candidate/pattern identity no longer matches the candidate being considered.

## Promotion gates

M7.3 pattern promotion requires all of the following:

1. the candidate and all evidence validate strictly;
2. the pattern representation is canonical and within qualified bounds;
3. clean corpus manifest identity is present and valid;
4. malware corpus manifest identity is present and valid;
5. every corpus entry has a valid lowercase SHA-256 and non-negative size;
6. the clean-corpus match count is exactly zero;
7. at least one malware-corpus sample matches;
8. reported counts agree with the deterministic match list;
9. the validation result is bound to the exact candidate/pattern and exact corpus manifests;
10. promotion remains an explicit lifecycle action rather than an automatic side effect of validation.

Independent-engine corroboration may strengthen confidence, but it does not replace the clean-corpus gate.

## Exact signatures

Exact `file-sha256` and `bootblock-sha256` candidates are not converted into patterns automatically. Their M7.0–M7.2 semantics remain unchanged.

M7.3 may later provide corpus reporting for exact signatures, but exact hashes do not require broad-pattern false-positive qualification because they identify one exact byte sequence.

## CI qualification strategy

Repository tests must not require real malware. CI qualification uses synthetic byte fixtures and synthetic manifests to prove the mechanics:

- deterministic manifest canonicalization and SHA-256 identity;
- strict manifest decoding/validation;
- deterministic pattern matching;
- zero-clean-match gate;
- at-least-one-malware-match gate;
- stale/mismatched validation evidence rejection;
- deterministic match ordering;
- no automatic promotion/publication;
- amd64 and arm64 builds remain green.

Real historical corpora are a separate data qualification activity. Their payloads remain outside Git.

## Planned implementation slices

### M7.3a — Corpus manifests and validation report

Implement strict clean/malware manifest structs, canonical identity, deterministic sample validation and a corpus-validation result model. No pattern candidates are enabled yet.

### M7.3b — Fixed-pattern candidate schema

Add the narrow canonical fixed-byte pattern representation and strict candidate validation. Existing exact-candidate behavior must remain unchanged.

### M7.3c — Deterministic corpus matcher

Run a fixed pattern against local corpus inputs whose bytes are verified against the manifest before matching. Report deterministic match identities and fail on missing/changed samples.

### M7.3d — Promotion gate and CLI

Add an explicit validation command/report flow and refuse pattern promotion without a current passing M7.3 validation result.

### M7.3e — Qualification

Qualify the complete mechanics in CI with synthetic corpora, then separately record the status of any real clean/malware corpus qualification without committing payloads.

## Non-goals

M7.3 does not:

- download malware automatically;
- commit malware or clean corpus payloads to Git;
- auto-promote or auto-publish patterns;
- claim universal zero false positives from a finite clean corpus;
- infer malware family from filenames;
- add heuristic/ML signatures;
- add unbounded wildcard or regex signature languages;
- sign or distribute databases — that is M7.4;
- complete historical Amiga engine runtime qualification — that is M8;
- complete Orange Pi appliance runtime qualification.

## Exit criteria

M7.3 can be called **code-qualified** only when the manifest, pattern, matcher and promotion-gate contracts are implemented, synthetic CI proves the fail-closed properties above, and a qualification record identifies the exact green HEAD.

Real-corpus qualification must be reported separately and precisely. Code qualification alone must never be described as proof that a finite production corpus has zero false positives or complete malware-family coverage.
