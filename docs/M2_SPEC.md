# M2 Specification — ADF and Bootblock Analysis

## Status

M2 adds structural analysis for classic raw Amiga Disk File (ADF) images to the `aaa scan` pipeline.

M2 does **not** contain a malware-signature database and therefore does not name or classify viruses. The overall verdict remains `unknown` until later detection milestones have sufficient evidence.

## Supported geometry

M2 accepts classic sector-dump ADF images with these exact sizes:

- DD: 901120 bytes, 1760 × 512-byte blocks, expected root block 880
- HD: 1802240 bytes, 3520 × 512-byte blocks, expected root block 1760

Extended ADF, HDF, DMS and compressed images are outside M2 structural parsing.

## Bootblock

AAA reads the first 1024 bytes and exposes:

- AmigaDOS type byte (`DOS\\0` through `DOS\\7`)
- filesystem family label (OFS/FFS and known DOS-type variants)
- stored bootblock checksum
- independently calculated checksum
- checksum validity
- root-block pointer
- expected root-block pointer for the detected geometry
- root-block plausibility
- whether the boot-code area contains any non-zero data

`bootable` is deliberately conservative: it means the boot-code area contains data. It does not prove that the code is valid, safe, executable, or malicious.

## Checksum

AAA calculates the standard 1024-byte Amiga bootblock checksum over 256 big-endian 32-bit words using end-around carry, treating the checksum field at bytes 4..7 as zero, then complementing the accumulated sum.

The calculated value is compared with the checksum stored in the image.

## CLI

Human-readable output:

```text
aaa scan disk.adf
```

Machine-readable output:

```text
aaa scan --json disk.adf
```

ADF-specific details appear under the `adf` JSON object.

## Security and preservation

M2 performs passive parsing only. It does not execute boot code, repair the bootblock, change the image, or delete material.

A malformed checksum or implausible root pointer is structural evidence only. It must not by itself be labelled malware.

## Exit criteria

M2 is code-qualified when CI passes:

- `gofmt` verification
- `go vet ./...`
- `go test ./...`
- linux/amd64 build
- linux/arm64 build

Reference-hardware runtime qualification remains deferred until the Orange Pi Zero 3 is available.
