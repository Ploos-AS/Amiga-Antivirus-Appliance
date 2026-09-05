# M3 Specification — Bootblock Signature Database

## Scope

M3 adds exact SHA-256 fingerprinting and a provenance-validated database for Amiga bootblocks.

AAA hashes the exact 1024-byte bootblock extracted by the M2 ADF parser and looks it up in the bundled database.

## Status values

Database entries may use only:

- `known-clean`
- `known-malicious`

Unknown hashes have no match object.

## Verdict policy

A `known-malicious` bootblock changes the overall scan verdict to `infected` and records a bootblock detection.

A `known-clean` bootblock does **not** change the overall disk verdict to `clean`. M3 does not yet inspect all files on the disk, so a clean bootblock cannot prove that the complete ADF is clean.

An unknown bootblock leaves the overall verdict `unknown`.

## Database schema

The bundled database is `internal/signatures/bootblocks.json`:

```json
{
  "schema": 1,
  "entries": [
    {
      "sha256": "64 lowercase hex characters",
      "status": "known-malicious",
      "name": "Human-readable name",
      "family": "optional family",
      "source": "required provenance",
      "notes": "optional notes"
    }
  ]
}
```

The loader rejects invalid hashes, unsupported status values, duplicate hashes, empty names, missing provenance, and unsupported schema versions.

## Corpus policy

M3 deliberately starts with an empty production corpus rather than inventing or importing unverified historical fingerprints. Real signatures must be added only after their provenance and classification have been checked.

Test-only signatures are generated inside unit tests and are never shipped as production detections.

## JSON output

ADF results include `bootblock_sha256`. A matching database entry appears as `bootblock_match`.

## Exit criteria

- exact 1024-byte bootblock SHA-256 is emitted;
- bundled database parses successfully;
- invalid and duplicate entries are rejected;
- known-malicious match => overall `infected`;
- known-clean match does not imply a clean disk;
- unknown bootblock remains `unknown`;
- CI passes formatting, vet, tests, amd64 build, and arm64 build.
