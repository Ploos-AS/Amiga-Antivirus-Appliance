# AAA — Amiga AntiVirus Appliance

AAA is a preservation-oriented malware scanning appliance for Commodore Amiga software and disk images.

Reference target: Orange Pi Zero 3 running DietPi (ARM64). The core scanner is portable and is developed/tested independently of the appliance hardware. Raspberry Pi and other ARM64 Debian-family systems are portability targets; Orange Pi Zero 3 remains the reference appliance.

## Command name

The project, product, and public CLI are all named **AAA**:

```sh
aaa scan <file>
aaa scan --json <file>
aaa version
```

`amigascan` is not the public command name.

## Current status

- **M0** — appliance foundation: code complete; Orange Pi/DietPi runtime qualification pending hardware arrival.
- **M1** — `aaa` CLI, SHA-256 and format identification: code-qualified in CI for amd64 and arm64.
- **M2** — classic ADF geometry and bootblock analysis: code complete.
- **M3** — exact bootblock SHA-256 matching and provenance-validated known-clean / known-malicious database: implemented and CI-qualified.
- **M3.1** — historical bootblock source qualification and emulator architecture: implemented and CI-qualified.
- **M4** — OFS/FFS metadata traversal: implemented and CI-qualified.
- **M4.1** — OFS/FFS file payload reconstruction and per-file SHA-256: implemented and CI-qualified as part of the M5 qualification chain.
- **M5** — structural Amiga Hunk analysis for standalone files and reconstructed ADF files: implemented and CI-qualified.
- **M6.0** — bounded ADZ/gzip expansion plus scanner integration into the existing ADF → filesystem → file hash → Hunk pipeline: implemented and CI-qualified.
- **M6.1a** — bounded ZIP member extraction, SHA-256, and content-aware member format classification: implemented and CI-qualified.
- **M6.1b** — bounded LHA/LZH extraction plus full native per-member ADF/Hunk scanning for ZIP and LHA: implemented; CI qualification pending on the current HEAD.

M3 can declare an ADF `infected` when its bootblock exactly matches a known-malicious entry. A known-clean bootblock does not make the whole disk clean, because complete malware inspection of reconstructed files is not implemented yet.

The production bootblock corpus starts empty intentionally. Real historical fingerprints are added only after provenance and classification have been verified; AAA does not invent signatures.

## Hybrid scanner architecture

AAA is intended to combine three independent layers:

- the native Go AAA engine for deterministic Amiga-aware parsing and signatures;
- ClamAV for generic host-side malware coverage;
- an isolated 68k Amiga emulator running genuine native Amiga antivirus engines such as VirusZ and VirusExecutor, subject to licensing and automation qualification.

The emulated scanner environment will be disposable/resettable, network-disabled by default, and unable to modify submitted originals. Scanner results remain attributable to engine/version/database identity instead of being collapsed into an unexplained verdict.

See `docs/EMULATED_SCANNERS.md` for the architecture contract.

## Build and scan

```sh
go build -o aaa ./cmd/aaa
./aaa scan disk.adf
./aaa scan disk.adz
./aaa scan bundle.zip
./aaa scan archive.lha
./aaa scan --json archive.lha
```

For classic DD/HD ADF images, AAA reports geometry, DOS type/filesystem, boot-code presence, exact bootblock SHA-256, stored/calculated Amiga bootblock checksum, checksum validity, root-block pointer, database match status, OFS/FFS filesystem objects, per-file payload hashes, and Hunk metadata for recognized executables.

M6.0 adds ADZ handling. AAA expands the gzip stream only in memory, enforces a 32 MiB hard limit, records the expanded member hash, validates that the result is a supported raw ADF, and then applies the same ADF scanner pipeline. Invalid or non-ADF ADZ payloads fail closed.

M6.1 adds ZIP and LHA/LZH archive handling. ZIP/LHA archives are limited to 1024 members and 32 MiB aggregate expanded data. Member names are never used as host extraction paths. Each regular member receives SHA-256 and content-aware format classification. ADF members are passed through bootblock analysis, OFS/FFS traversal, reconstructed file hashing, and Hunk detection; standalone Hunk members receive structural Hunk analysis. An infected member propagates the infected verdict to the outer archive while retaining the member identity.

Nested archive expansion is deliberately deferred until M6.3 so explicit recursion and aggregate resource limits can be enforced first.

Example fields:

```text
Format:   lha
Archive:  lha expanded=901120 bytes
  member    disk.adf [901120 bytes, adf]
            SHA-256 ...
Member scan: disk.adf [adf] verdict=unknown
             ADF dd DOS\1 (FFS) boot-sha=...
             FS 12 files, 3 directories, 4 Hunk files
Verdict:  unknown
```

M4 enumerates file and directory names, paths, and header-block numbers. M4.1 reconstructs OFS/FFS file byte streams transiently and records exact SHA-256 without writing extracted files to the host filesystem. M5 recognizes `HUNK_HEADER` load files and summarizes CODE, DATA, BSS, relocation and structural records without loading or executing them.

M1 format identification also recognizes DMS where a content signature is available. Identification alone does not mean that format is fully decoded yet.

See `docs/M1_SPEC.md`, `docs/M2_SPEC.md`, `docs/M3_SPEC.md`, `docs/M3_1_SPEC.md`, `docs/M4_SPEC.md`, `docs/M4_1_SPEC.md`, `docs/M5_SPEC.md`, and `docs/M6_SPEC.md` for the exact contracts.

## Persistent appliance layout

```text
/data/aaa/
├── incoming/
├── clean/
├── quarantine/
├── unknown/
├── reports/
├── signatures/
└── state/
```

No submitted material is automatically deleted.

## M0 install on DietPi

When the reference hardware is available:

```sh
sudo sh scripts/install-m0.sh
sudo sh scripts/qualify-m0.sh
```

See `docs/M0_SPEC.md` and `SECURITY.md` before deployment.

## Development

AAA currently builds with Go 1.24 or later.

```sh
make test
make build
make build-arm64
```

The core is mostly standard-library Go. M6.1b adds the MIT-licensed `github.com/koron-go/lha` dependency for LHA/LZH decoding; dependency checksums are committed in `go.sum`.

## Roadmap

- M0 appliance foundation
- M1 `aaa` CLI, hashing, format identification
- M2 ADF and boot-block analysis
- M3 known-clean / known-malicious boot-block database
- M3.1 historical bootblock source qualification
- M4 OFS/FFS traversal
- M4.1 OFS/FFS file payload reconstruction and per-file hashing
- M5 Amiga Hunk analysis
- M6 ADZ/DMS/LHA/LZX/archive pipeline
- M7 Amiga malware signatures / historical scanner knowledge
- M8 isolated emulated Amiga scanner engines and consensus
- M9 daemon, REST API, scan history
- M10 Web UI
- M11 SMB drop-folder workflow
- M12 Greaseweazle integration

## License

AAA is licensed under the MIT License. See `LICENSE`.

Third-party components and historical scanner engines retain their own licenses. The MIT license for AAA does not relicense external GPL or proprietary components.
