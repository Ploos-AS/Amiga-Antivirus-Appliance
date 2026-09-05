# M6 — Archive and compressed-image pipeline

## Goal

Safely unwrap common Amiga preservation containers and feed their contents into AAA's existing passive scanner pipeline without executing submitted material.

## Formats

M6 is delivered incrementally:

- M6.0: ADZ (gzip-wrapped ADF), bounded in-memory expansion, member hashing, and full scanner integration.
- M6.1: ZIP and LHA/LZH member enumeration/extraction.
- M6.2: DMS disk-image decoding.
- M6.3: LZX support and nested-container policy.

A format is not claimed as supported merely because M1 can identify it.

## Safety contract

Archive processing is passive. Expanded bytes are not executed. Expansion is bounded; M6.0 uses a 32 MiB hard limit for one ADZ stream. Original submissions are never modified or deleted. Invalid, truncated, encrypted, unsupported, or over-limit containers fail closed with an attributable error/warning rather than being silently treated as clean.

## M6.0 contract

`internal/archive.DecodeADZ` accepts gzip bytes, expands them in memory, applies the hard expansion limit, and returns the expanded bytes plus SHA-256 metadata.

The scanner then requires the expanded payload to satisfy a supported raw ADF geometry and AmigaDOS bootblock contract before applying the existing native scanner chain. A valid ADZ therefore flows through:

`ADZ → expanded ADF → bootblock analysis/signatures → OFS/FFS traversal → reconstructed file SHA-256 → Hunk analysis`

No temporary extracted ADF is written to disk. The JSON result retains the outer submission hash and format, adds archive/member metadata, and attaches the normal ADF/filesystem analysis for the expanded image.

Malformed gzip, expansion over 32 MiB, unsupported ADF geometry, or a non-AmigaDOS expanded payload causes the scan to fail closed rather than being treated as an unknown clean container.

## M6.0 qualification

M6.0 is code-qualified when CI passes:

- archive unit tests for valid and malformed ADZ data;
- scanner integration test proving a valid ADZ reaches ADF analysis;
- scanner test proving a gzip stream expanding to non-ADF data is rejected;
- gofmt and `go vet ./...`;
- all Go tests;
- linux/amd64 build;
- linux/arm64 build.

## Exit criteria for full M6

M6 is complete when ADZ, DMS, LHA/LZH, LZX and the supported ZIP subset have bounded extraction/decoding, tests, scanner integration, and explicit behavior for malformed and unsupported inputs.
