# M6 — Archive and compressed-image pipeline

## Goal

Safely unwrap common Amiga preservation containers and feed their contents into AAA's existing passive scanner pipeline without executing submitted material.

## Formats

M6 is delivered incrementally:

- M6.0: ADZ (gzip-wrapped ADF), bounded in-memory expansion and member hashing.
- M6.1: ZIP and LHA/LZH member enumeration/extraction.
- M6.2: DMS disk-image decoding.
- M6.3: LZX support and nested-container policy.

A format is not claimed as supported merely because M1 can identify it.

## Safety contract

Archive processing is passive. Expanded bytes are not executed. Expansion is bounded; M6.0 uses a 32 MiB hard limit for one ADZ stream. Original submissions are never modified or deleted. Invalid, truncated, encrypted, unsupported, or over-limit containers fail closed with an attributable error/warning rather than being silently treated as clean.

## M6.0 contract

`internal/archive.DecodeADZ` accepts gzip bytes, expands them in memory, applies the hard expansion limit, and returns the expanded bytes plus SHA-256 metadata. The scanner integration must additionally require the expanded payload to have a supported raw ADF geometry before applying ADF-specific analysis.

## Exit criteria for full M6

M6 is complete when ADZ, DMS, LHA/LZH, LZX and the supported ZIP subset have bounded extraction/decoding, tests, scanner integration, and explicit behavior for malformed and unsupported inputs.
