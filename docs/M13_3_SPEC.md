# M13.3 — Portable evidence ZIP

Status: IMPLEMENTED — CI qualification pending

## Purpose

M13.3 adds a single-file transport container for the M13 evidence manifest and the exact evidence bytes that it names. The transport is designed for archival, transfer and independent offline verification.

The ZIP is a transport container only. The `aaa-evidence-bundle-v1` manifest remains the semantic and provenance authority.

## CLI

```sh
aaa evidence pack \
  --manifest case.json \
  --root ./case-files \
  --output case.aaa-evidence.zip

aaa evidence verify-bundle case.aaa-evidence.zip
```

`--root` defaults to the directory containing the source manifest.

## Archive contract

A valid AAA portable evidence ZIP contains:

1. exactly one `manifest.json`;
2. exactly one regular-file member for every manifest entry;
3. no undeclared members;
4. no directories, symlinks or special files;
5. no unsafe, absolute or traversal member names;
6. only ZIP `Store` members — no compression/decompression ambiguity;
7. deterministic member order and fixed archive metadata;
8. canonical deterministic manifest bytes.

`manifest.json` is a reserved transport name and cannot also be used as an evidence entry name.

## Creation safety

Bundle creation is write-once (`O_EXCL`). Existing outputs are never overwritten.

Before and during archive creation, AAA requires each source to remain a regular file, verifies that the opened descriptor and current path refer to the same file, verifies size, and recomputes SHA-256 while the bytes are copied into the archive. A source that changes during packaging causes the operation to fail and the incomplete output to be removed.

## Offline verification

`aaa evidence verify-bundle` does not extract or execute archive content. It:

- requires the archive itself to be a regular file;
- rejects duplicate, unsafe, special, directory or compressed members;
- parses the embedded manifest with unknown-field rejection and the normal M13 schema validation;
- rejects undeclared or missing members;
- checks every member's declared size;
- streams every member through SHA-256 and compares the digest with the manifest.

The embedded manifest is limited to 4 MiB and the archive is limited to 4096 evidence entries plus `manifest.json`.

## Determinism

For the same canonical manifest and identical evidence bytes, AAA produces identical ZIP bytes. Members use a fixed 1980-01-01 timestamp, fixed regular-file mode and ZIP Store method. Entry order follows canonical manifest name order.

## Provenance boundary

Packaging does not alter verdicts, promote samples, infer relationships, or change the M12 acquisition relationship. In particular, carrying SCP and ADF evidence in the same ZIP does not assert SCP-to-ADF derivation.

The archive SHA-256 printed by the CLI identifies one exact transport object; the manifest entry hashes continue to identify the underlying evidence independently of the transport container.

## Qualification gates

M13.3 code qualification requires tests covering:

- create → verify round trip;
- deterministic archive bytes;
- write-once output;
- exact member ordering;
- hash/size tamper rejection;
- undeclared-member rejection;
- unsafe path rejection;
- duplicate-member rejection;
- compressed-member rejection;
- symlink source rejection;
- reserved `manifest.json` evidence-name rejection;
- amd64 and arm64 build gates.

No physical appliance or Greaseweazle hardware is required for M13.3 code qualification.
