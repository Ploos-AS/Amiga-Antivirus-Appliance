# M12.2 — Multi-read acquisition repeatability

## Status

M12.2 extends the Greaseweazle acquisition workflow with repeated physical reads and an explicit repeatability classification.

The purpose is acquisition quality and preservation evidence. Repeatability is **not** malware evidence and does not change a scanner verdict.

## CLI

Single-read behavior remains unchanged:

```sh
aaa acquire disk.adf
```

Repeated acquisition is requested with:

```sh
aaa acquire --reads 2 disk.adf
```

For multiple reads the supplied output path is a base name. AAA derives deterministic artifacts:

```text
disk.read-01.adf
disk.read-01.adf.acquisition.json
disk.read-01.adf.gw.log

disk.read-02.adf
disk.read-02.adf.acquisition.json
disk.read-02.adf.gw.log

disk.repeatability.json
```

`--repeatability <path>` may override the manifest path. `--evidence` and `--log` remain single-read options because each repeated read requires its own independent sidecars.

## Classification

`internal/acquisition.CompareReads` classifies acquisition hashes as:

- `insufficient` — fewer than two reads;
- `reproducible` — two or more reads and every read has the same SHA-256;
- `divergent` — two or more reads produced more than one SHA-256.

The comparison records the read count, number of unique hashes, per-hash occurrence counts, and each read's ordinal/hash/size.

A `divergent` result is not a malware signal. It indicates that repeated physical acquisition did not produce byte-identical sector images and requires preservation/operator review.

## Scanner binding

Every read independently passes the M12.1 integrity gate:

```text
acquisition.output_sha256 == scan.sha256
```

A read whose scanner hash does not equal its acquisition hash fails closed and is not included as a successfully bound read.

Scanner verdicts remain per acquired image. The repeatability manifest does not merge or vote malware verdicts.

## Preservation semantics

AAA preserves all successfully completed repeated reads, including divergent reads. A difference between two physical reads may be caused by media degradation, marginal sectors, drive/read variability, copy protection or other acquisition effects; deleting the differing evidence would destroy information needed for diagnosis.

If a later read fails after earlier reads succeeded, already completed images and sidecars remain preserved. No repeatability manifest is written until all requested reads complete and the comparison succeeds.

## Write-once preflight

Before the first physical read starts, AAA checks every planned image, acquisition sidecar, Greaseweazle log and the repeatability manifest.

If any planned artifact already exists, the operation fails before touching the disk. This prevents a multi-read run from mixing new evidence with artifacts from an older run.

## Qualification

CI qualification covers:

- `insufficient`, `reproducible` and `divergent` classification;
- per-hash counts;
- invalid acquisition evidence rejection;
- deterministic multi-read artifact naming;
- write-once whole-series preflight;
- two identical reads producing `reproducible`;
- two different reads producing `divergent` while preserving both images;
- per-read acquisition/scan SHA-256 binding;
- normal repository format, vet, test and amd64/arm64 build gates.

Real repeatability claims remain hardware-runtime-pending until the workflow is executed with a physical Greaseweazle, drive and Amiga floppy.

## Reference hardware gate

A useful target qualification should perform at least two reads of the same known disk and retain:

- every ADF;
- every acquisition JSON sidecar;
- every raw Greaseweazle log;
- the repeatability manifest;
- Greaseweazle device/firmware information;
- AAA scan result for every exact acquisition hash.

A reproducible pair is useful evidence that the decoded ADF is stable across reads, but it does not prove that copy-protected/non-AmigaDOS information outside the ADF representation was preserved. Flux-level preservation remains a later M12 concern.
