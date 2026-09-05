# AAA — Amiga AntiVirus Appliance

AAA is a preservation-oriented malware scanning appliance for Commodore Amiga software and disk images.

Reference target: Orange Pi Zero 3 running DietPi (ARM64). The core scanner is portable and is developed/tested independently of the appliance hardware.

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
- **M2** — classic ADF geometry and bootblock analysis: implemented; CI qualification required on the current HEAD.

AAA does **not** yet claim malware detection. The verdict remains intentionally `unknown` until detection/signature milestones have sufficient evidence.

## Build and scan

```sh
go build -o aaa ./cmd/aaa
./aaa scan disk.adf
./aaa scan --json disk.adf
```

For classic DD/HD ADF images, M2 reports geometry, DOS type/filesystem, boot-code presence, stored and calculated Amiga bootblock checksum, checksum validity, root-block pointer, expected root block, and root-pointer plausibility.

Example fields:

```text
Format:   adf
Disk:     dd (1760 blocks)
DOS type: DOS\1 (FFS)
Bootable: true
Boot CRC: stored=... calculated=... valid=true
Root:     880 expected=880 plausible=true
Verdict:  unknown
```

M1 format identification also recognizes DMS, ADZ/gzip, LHA/LZH, ZIP and Amiga Hunk executables where content signatures are available. Extension-only hints are reported as unrecognized rather than validated.

See `docs/M1_SPEC.md` and `docs/M2_SPEC.md` for the exact contracts.

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
- M4 OFS/FFS traversal
- M5 Amiga Hunk analysis
- M6 ADZ/DMS/LHA/LZX/archive pipeline
- M7 Amiga malware signatures / historical scanner knowledge
- M8 daemon, REST API, scan history
- M9 Web UI
- M10 SMB drop-folder workflow
- M11 Greaseweazle integration

## License

No project license has been selected yet. Third-party components retain their own licenses.
