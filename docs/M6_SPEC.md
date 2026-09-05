# M6 — Archive and compressed-image pipeline

## Goal

Safely unwrap common Amiga preservation containers and feed their contents into AAA's existing passive scanner pipeline without executing submitted material.

## Formats

M6 is delivered incrementally:

- M6.0: ADZ (gzip-wrapped ADF), bounded in-memory expansion, member hashing, and full scanner integration.
- M6.1a: ZIP member enumeration/extraction, hashing, and member format classification.
- M6.1b: LHA/LZH member enumeration/extraction and ZIP/LHA member scan-result integration.
- M6.2: DMS disk-image decoding.
- M6.3: LZX support and nested-container policy.

A format is not claimed as supported merely because M1 can identify it.

## Safety contract

Archive processing is passive. Expanded bytes are not executed. Expansion is bounded. M6.0 and M6.1a use a 32 MiB hard aggregate expansion limit, and ZIP additionally permits at most 1024 entries. Original submissions are never modified or deleted. ZIP members are retained only in memory; member names are never used as host extraction paths. Invalid, truncated, encrypted, unsupported, or over-limit containers fail closed with an attributable error/warning rather than being silently treated as clean.

## M6.0 contract

`internal/archive.DecodeADZ` accepts gzip bytes, expands them in memory, applies the hard expansion limit, and returns the expanded bytes plus SHA-256 metadata.

The scanner then requires the expanded payload to satisfy a supported raw ADF geometry and AmigaDOS bootblock contract before applying the existing native scanner chain. A valid ADZ therefore flows through:

`ADZ → expanded ADF → bootblock analysis/signatures → OFS/FFS traversal → reconstructed file SHA-256 → Hunk analysis`

No temporary extracted ADF is written to disk. The JSON result retains the outer submission hash and format, adds archive/member metadata, and attaches the normal ADF/filesystem analysis for the expanded image.

Malformed gzip, expansion over 32 MiB, unsupported ADF geometry, or a non-AmigaDOS expanded payload causes the scan to fail closed rather than being treated as an unknown clean container.

## M6.1a ZIP contract

`internal/archive.DecodeZIP` uses Go's standard-library ZIP reader. It expands regular members into memory, ignores directory entries, rejects encrypted members, caps the archive at 1024 entries, and applies a 32 MiB aggregate expanded-size limit. Each regular member receives an exact SHA-256.

The scanner classifies each expanded member using AAA's existing content-aware format detector and records the member name, expanded size, SHA-256, and detected format in the archive result. M6.1a deliberately does not write members to host paths and does not yet recursively attach full per-member ADF/Hunk scan results; that is part of M6.1b/M6.3.

## Qualification

M6.0 is code-qualified when CI passes archive and scanner ADZ tests, gofmt, `go vet ./...`, all Go tests, and linux/amd64 plus linux/arm64 builds.

M6.1a is code-qualified when the same CI additionally passes ZIP unit tests and a scanner integration test proving member enumeration, SHA-256, and format classification.

## Exit criteria for full M6

M6 is complete when ADZ, DMS, LHA/LZH, LZX and the supported ZIP subset have bounded extraction/decoding, tests, scanner integration, and explicit behavior for malformed and unsupported inputs.
