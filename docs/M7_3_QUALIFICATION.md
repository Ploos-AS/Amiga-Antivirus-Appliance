# M7.3 — Corpus validation and pattern qualification

## Status

**Code-qualified.**

The complete M7.3 implementation mechanics and this qualification record have passed the normal GitHub Actions CI gates. M7.3 is closed for code qualification; real historical corpus qualification remains a separate, explicitly pending data-qualification activity.

## Qualified scope

M7.3 adds a fail-closed path for broad fixed-byte pattern candidates without weakening the already-qualified exact SHA-256 lifecycle.

### Corpus manifests

The corpus contract provides explicit `clean` and `malware` classes with:

- schema version;
- stable corpus identifier;
- creation timestamp;
- sample SHA-256 and size;
- optional format/provenance metadata;
- deterministic canonical ordering;
- SHA-256 manifest identity;
- strict JSON decoding that rejects unknown fields and trailing values.

Manifest paths are operational only and are not part of corpus identity.

### Fixed-pattern candidates

M7.3 enables only the intentionally narrow initial pattern form:

- fixed byte sequence represented as lowercase hexadecimal;
- 8-byte minimum length;
- 4096-byte maximum length;
- optional non-negative exact byte offset;
- no regex;
- no wildcard language;
- no executable or shell expression;
- deterministic pattern identity derived from the bytes and offset semantics.

Pattern candidate IDs are bound to the pattern identity. Exact file and bootblock candidates reject pattern fields and retain their previous semantics.

### Deterministic corpus matcher

`MatchPatternCorpora` validates both manifests, requires the expected clean/malware classes, verifies each local sample as a regular file, verifies manifest size and SHA-256 before matching, and fails closed on missing or changed bytes.

Matching is deterministic for both any-offset and exact-offset patterns. Match identities are sorted before the validation report is produced.

The generated `CorpusValidationResult` is bound to:

- candidate ID;
- pattern identity;
- clean manifest SHA-256;
- malware manifest SHA-256;
- clean and malware sample counts;
- exact sorted match lists;
- validation timestamp.

### Promotion gate

Direct `Store.Promote` of a pattern candidate is rejected. Pattern promotion requires `Store.PromotePattern` and a structurally valid corpus-validation result.

Promotion fails unless:

- the stored candidate validates;
- the candidate is a pattern candidate;
- the result candidate ID equals the stored candidate ID;
- the result pattern identity equals the stored pattern identity;
- clean match count is exactly zero;
- malware match count is at least one;
- result counts agree with the exact sorted match lists.

Passing validation does not auto-promote or auto-publish. Promotion remains an explicit lifecycle action.

### CLI

The existing promotion command accepts a validation report for pattern candidates:

```text
aaa signatures promote --validation <result.json> <id>
```

Exact SHA-256 candidates continue to use ordinary explicit promotion without a corpus-validation report. Supplying a pattern-validation report for a non-pattern candidate is rejected.

## Synthetic CI qualification

Repository CI uses only synthetic bytes and manifests. The tests cover:

1. canonical corpus manifest identity independent of entry order;
2. strict manifest validation and strict JSON decoding;
3. fixed-pattern lower/upper bounds and canonical lowercase hexadecimal;
4. deterministic any-offset and fixed-offset matching;
5. verification of corpus sample size and SHA-256 before matching;
6. deterministic sorted match identities;
7. a clean-corpus match blocking the gate;
8. zero malware coverage blocking the gate;
9. candidate/pattern identity mismatch blocking promotion;
10. direct pattern promotion without qualification being rejected;
11. successful explicit promotion with a passing synthetic qualification;
12. strict validation-result decoding rejecting unknown fields and trailing JSON;
13. exact candidate behavior remaining separate from pattern behavior.

The strict-decoder test itself was corrected after CI exposed mutation of the original JSON fixture through slice-capacity reuse. The fix copies the encoded buffer before constructing invalid unknown-field and trailing-data variants.

## CI evidence

M7.3d and the strict-decoder fixture correction are green on GitHub Actions CI run **#201** at implementation HEAD:

```text
56f1120ee33eb3ff3544fa43cac118b8b663ba42
```

Run #201 completed successfully across the normal repository gates, including format check, module metadata, `go vet`, tests, linux/amd64 build and linux/arm64 build.

The qualification record itself was then committed at:

```text
8e643021b983a9a82a722d09b1585d08b183057d
```

GitHub Actions CI run **#202** completed successfully on that documentation HEAD, satisfying the final M7.3 exit requirement.

Earlier slice qualification was also green:

- M7.3a corpus manifests: CI #191;
- M7.3b fixed-pattern candidates: CI #193;
- M7.3c deterministic corpus matching: CI #195.

## Real-corpus status

**Not yet qualified with a production historical corpus.**

No real malware or clean-corpus payloads are committed to the repository. A future real-corpus qualification must record the exact clean and malware manifest identities, sample counts, pattern match counts and matched sample identities while keeping corpus payloads outside Git.

A finite real-corpus pass must not be described as universal zero false positives or complete malware-family coverage.

## Remaining work outside M7.3

M7.3 does not claim completion of:

- real historical clean/malware corpus qualification;
- signed or versioned signature distribution — M7.4;
- automatic pattern derivation from scanner detections;
- regex or wildcard signature languages;
- historical Amiga engine runtime qualification — M8;
- reference Orange Pi appliance runtime qualification.

## Exit decision

M7.3 satisfies its code-qualification criteria and is closed as **code-qualified**. Development may proceed to **M7.4 — signed/versioned signature distribution** without treating real-corpus qualification, historical-engine runtime qualification, or Orange Pi appliance qualification as complete.
