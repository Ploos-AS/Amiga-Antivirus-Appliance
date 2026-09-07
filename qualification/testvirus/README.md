# Amiga test-virus qualification corpus

This directory defines the qualification policy for synthetic antivirus test files used by AAA.

## Purpose

Synthetic test-virus samples are known-positive functional fixtures. They are useful for verifying that native AAA scanning, ClamAV integration, emulated Amiga antivirus engines, daemon job handling, scan history and later REST/Web UI layers preserve a positive detection end to end.

They are **not real malware** and must never be treated as malware provenance or promoted as ordinary malware signatures.

## Candidate sources

Two useful Amiga-oriented sources have been identified for qualification:

- EICAR AV-Testfile for Amiga.
- Zeeball AV-Testfile / testvirus package by Zbigniew Trzcionkowski (Zeeball), intended for Amiga antivirus testing.

No third-party binaries are committed here until redistribution rights and exact upstream artifacts have been verified.

## Manifest policy

A local or CI qualification manifest uses schema 1 and records, for every sample:

- stable sample ID;
- human-readable name;
- exact SHA-256;
- `synthetic: true`;
- source/provenance;
- optional expected detection labels.

`internal/testvirus` validates this contract and rejects non-synthetic entries, malformed SHA-256 values and duplicate IDs.

Example shape:

```json
{
  "schema": 1,
  "corpus": "amiga-testvirus",
  "samples": [
    {
      "id": "upstream-sample-id",
      "name": "Upstream sample name",
      "sha256": "<64 lowercase or uppercase hexadecimal characters>",
      "synthetic": true,
      "source": "verified upstream artifact",
      "expected_detections": ["test-virus"]
    }
  ]
}
```

Do not replace the SHA-256 placeholder above in documentation with an invented digest. Populate a real qualification manifest only after the exact upstream file has been obtained and hashed.

## Signature Factory boundary

Synthetic test-virus detections may be recorded as qualification evidence, but they must be excluded from automatic candidate promotion and from any corpus used to derive real malware signatures. Later integration must preserve the `synthetic` classification across scan history and API responses.

## Next qualification step

Obtain the exact EICAR Amiga and Zeeball artifacts from their authoritative distribution source, record source URLs/version metadata and SHA-256 values, then create the first real manifest. Only after that should expected per-engine detections be baselined.
