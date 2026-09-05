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
- **M4** — OFS/FFS metadata traversal: implemented; CI qualification pending on the current HEAD.

M3 can declare an ADF `infected` when its bootblock exactly matches a known-malicious entry. A known-clean bootblock does not make the whole disk clean, because complete file-content scanning is not implemented yet.

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
./aaa scan --json disk.adf
```

For classic DD/HD ADF images, AAA reports geometry, DOS type/filesystem, boot-code presence, exact bootblock SHA-256, stored/calculated Amiga bootblock checksum, checksum validity, root-block pointer, database match status, and the filesystem objects reached through OFS/FFS directory metadata.

Example fields:

```text
Format:   adf
Disk:     dd (1760 blocks)
DOS type: DOS\1 (FFS)
Bootable: true
Boot SHA: ...
Boot CRC: stored=... calculated=... valid=true
Root:     880 expected=880 plausible=true
FS root:  880 valid=true
FS items: 12 files, 3 directories
Boot DB:  unknown
Verdict:  unknown
```

M4 enumerates file and directory names, paths, and header-block numbers. It deliberately does not extract file payloads yet; that is the next prerequisite for file-level hashing and Hunk scanning.

M1 format identification also recognizes DMS, ADZ/gzip, LHA/LZH, ZIP and Amiga Hunk executables where content signatures are available. Extension-only hints are reported as unrecognized rather than validated.

See `docs/M1_SPEC.md`, `docs/M2_SPEC.md`, `docs/M3_SPEC.md`, `docs/M3_1_SPEC.md`, and `docs/M4_SPEC.md` for the exact contracts.

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

```sh
make test
make build
make build-arm64
```

The current implementation uses only the Go standard library.

## Roadmap

- M0 appliance foundation
- M1 `aaa` CLI, hashing, format identification
- M2 ADF and boot-block analysis
- M3 known-clean / known-malicious boot-block database
- M3.1 historical bootblock source qualification
- M4 OFS/FFS traversal
- M4.1 OFS/FFS file payload extraction and per-file hashing
- M5 Amiga Hunk analysis
- M6 ADZ/DMS/LHA/LZX/archive pipeline
- M7 Amiga malware signatures / historical scanner knowledge
- M8 isolated emulated Amiga scanner engines and consensus
- M9 daemon, REST API, scan history
- M10 Web UI
- M11 SMB drop-folder workflow
- M12 Greaseweazle integration

## License

No project license has been selected yet. Third-party components retain their own licenses.
