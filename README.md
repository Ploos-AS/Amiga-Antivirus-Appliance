# AAA — Amiga AntiVirus Appliance

AAA is a preservation-oriented malware scanning appliance for Commodore Amiga software and disk images.

Reference target: Orange Pi Zero 3 running DietPi (ARM64). The core scanner is portable and is developed/tested independently of the appliance hardware. Raspberry Pi and other ARM64 Debian-family systems are portability targets; Orange Pi Zero 3 remains the reference appliance.

## Website and malware samples

Project website: **https://ploos-as.github.io/Amiga-Antivirus-Appliance/**

AAA benefits from authentic historical Amiga malware samples so detections and signature candidates can be backed by real evidence rather than guessed fingerprints. The shared Ploos-AS sample-intake project is **AmiGuard**:

**https://ploos-as.github.io/AmiGuard/**

Please preserve suspected samples unchanged and follow the instructions on the AmiGuard page. **Do not attach malware to GitHub issues, pull requests, discussions, or repository commits.** A submitted artifact is research material until it has been independently analyzed and qualified; submission alone does not make it a verified malware sample.

## Command name

The project, product, and public CLI are all named **AAA**:

```sh
aaa scan <file>
aaa scan --json <file>
aaa daemon
aaa evidence create --output evidence.json --entry artifact:artifacts/disk.adf:./disk.adf
aaa evidence verify evidence.json
aaa evidence verify-bundle case.aaa-evidence.zip
aaa trust-update status
aaa signatures candidates
aaa signatures validate
aaa signatures promote <id>
aaa signatures reject <id>
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
- **M6.1b** — bounded LHA/LZH extraction plus full native per-member ADF/Hunk scanning for ZIP and LHA: implemented and CI-qualified.
- **M6.2** — DMS decoding through a bounded xDMS subprocess and full ADF pipeline integration: implemented and CI-qualified; reference-appliance runtime qualification pending.
- **M6.3** — Amiga LZX plus bounded nested ZIP/LHA/LZX/ADZ/DMS scanning under shared per-job budgets: implemented and CI-qualified; real-fixture/reference-appliance qualification pending.
- **M6.4a** — IPF preservation-image helper boundary plus scanner integration: implemented and CI-qualified with deterministic fake-helper coverage; real CAPS-compatible decoder/fixture and Orange Pi runtime qualification pending.
- **M6.4b** — FDI preservation-image helper boundary plus scanner integration: implemented and CI-qualified with deterministic fake-helper coverage; real FDI parser/helper/fixture and Orange Pi runtime qualification pending.
- **M7** — Signature Factory, normalized evidence/provenance, ClamAV export, corpus qualification and signed/versioned signature distribution: implemented and code-qualified; reference-appliance runtime qualification pending.
- **M8** — isolated historical Amiga scanner adapters, provenance, consensus/evidence aggregation and M8.7 support-component identity: implemented and code-qualified; real emulator/scanner appliance runtime qualification pending.
- **M9** — daemon, persistent scan history, REST API, upload pipeline, hardening and production systemd integration: implemented and code-qualified; REST result serialization uses an API-safe whitelist and does not expose the scanner's host input path; reference-appliance service/reboot qualification pending.
- **M10** — embedded Web UI, structured results, attributed engine cards, disagreement display and operational dashboard: implementation complete through M10.5; code qualification is tracked in `docs/M10_QUALIFICATION.md`, while Orange Pi runtime and visible browser qualification remain separate hardware gates.
- **M11** — secure SMB drop-folder workflow, stable-file ingest, immutable staging, daemon watcher, restart-safe ingest receipts and authenticated Samba appliance integration: implementation complete through M11.2 and code-qualified; staging binds the opened source to the observed path with post-open `Lstat`/`SameFile` validation to reject path replacement/symlink races; Orange Pi/DietPi authenticated runtime qualification remains pending. See `docs/M11_QUALIFICATION.md`.
- **M12.0–M12.6** — Greaseweazle acquisition foundation, hash-bound ADF acquisition, multi-read repeatability, raw SCP flux preservation, same-media acquisition sessions and qualification tooling: implemented and code-qualified with deterministic fake-`gw` coverage; physical Greaseweazle/drive/media qualification remains explicitly pending hardware. See `docs/M12_QUALIFICATION.md`.
- **M13.0–M13.7** — Portable Evidence Bundles: deterministic manifests and ZIP transport, offline verification, detached Ed25519 signatures, signing-key trust lifecycle, authenticated trust-store updates, replay/rollback protection and crash-safe persistent trust installation: implemented and code-qualified for amd64/arm64; no physical hardware required. See `docs/M13_QUALIFICATION.md`.

M3 can declare an ADF `infected` when its bootblock exactly matches a known-malicious entry. A known-clean bootblock does not make the whole disk clean, because other malware may be present elsewhere in the disk image.

The production bootblock corpus starts empty intentionally. Real historical fingerprints are added only after provenance and classification have been verified; AAA does not invent signatures.

## Hybrid scanner architecture

AAA combines three independent layers:

- the native Go AAA engine for deterministic Amiga-aware parsing and signatures;
- ClamAV for generic host-side malware coverage;
- isolated 68k Amiga emulator adapters for genuine native Amiga antivirus engines such as VirusZ and VirusExecutor, subject to licensing and runtime qualification.

The emulated scanner environment is designed to be disposable/resettable, network-disabled by default, and unable to modify submitted originals. Scanner results remain attributable to engine/version/database identity instead of being collapsed into an unexplained verdict.

See `docs/EMULATED_SCANNERS.md` for the architecture contract.

## Build and scan

```sh
go build -o aaa ./cmd/aaa
./aaa scan disk.adf
./aaa scan disk.adz
./aaa scan disk.dms
./aaa scan bundle.zip
./aaa scan archive.lha
./aaa scan archive.lzx
./aaa scan --json archive.lha
```

For classic DD/HD ADF images, AAA reports geometry, DOS type/filesystem when recognized, boot-code presence, exact bootblock SHA-256, stored/calculated Amiga bootblock checksum, checksum validity, root-block pointer, database match status, OFS/FFS filesystem objects when available, per-file payload hashes, and Hunk metadata for recognized executables.

M6.0 adds ADZ handling. AAA expands the gzip stream only in memory, enforces a 32 MiB hard limit, records the expanded member hash, validates that the result is a supported raw ADF, and then applies the same ADF scanner pipeline. Invalid or non-ADF ADZ payloads fail closed.

M6.1 adds ZIP and LHA/LZH archive handling. ZIP/LHA archives are limited to 1024 members and 32 MiB aggregate expanded data. Member names are never used as host extraction paths. Each regular member receives SHA-256 and content-aware format classification. ADF members are passed through bootblock analysis, OFS/FFS traversal, reconstructed file hashing, and Hunk detection; standalone Hunk members receive structural Hunk analysis. An infected member propagates the infected verdict to the outer archive while retaining the member identity.

M6.2 adds DMS support through the reference `xdms` utility. AAA sends the DMS stream to `xdms -q u stdin +stdout`, applies a bounded output budget and 15-second timeout, and feeds the resulting ADF bytes into the same native scanner chain. Nested DMS uses the remaining shared archive expansion budget before output is accepted. No temporary DMS or ADF path is created.

M6.3 adds Amiga LZX through Debian `unar`/`lsar` and enables bounded nested-container scanning. Nested ZIP, LHA, LZX, ADZ and DMS share the same 32 MiB expanded-data budget and 1024-member ceiling rather than receiving fresh budgets at each level.

M6.4 extends scanning to preservation formats IPF and FDI through bounded optional helper boundaries. The original preservation image remains the primary evidence object and retains its own SHA-256; any lossless ADF-compatible sector view is explicitly recorded as derived evidence with a separate SHA-256 before entering the native ADF scanner pipeline. Both helper boundaries and scanner integrations are code-qualified in CI. Real decoder/parser fixtures and reference-appliance runtime qualification remain pending. IPF uses an optional separately licensed CAPSImage-compatible decoder boundary rather than bundling CAPS/SPS code into AAA's MIT core. See `docs/M6_4_SPEC.md`.

M7 adds the local Signature Factory. Confirmed `infected` results can produce reviewable candidates under `/data/aaa/signatures` without automatic promotion or publication. Candidate writes are deterministic and conflict-safe, archive-member infections are attributed to the member rather than only the outer container, and malicious bootblock candidates retain both the containing sample hash and exact bootblock hash. Operators can validate, promote, reject, export and distribute explicitly qualified signatures.

M9 adds the long-running `aaa daemon`, append-only persistent scan history, localhost REST API, bounded HTTP upload ingestion and production systemd integration. M10 serves a same-origin Web UI from the same daemon process with no Node.js runtime, CDN or external frontend assets. M11 adds a dedicated authenticated SMB drop boundary whose stable files are staged into immutable controlled snapshots before entering the same daemon queue/history pipeline. See `docs/M9_5_SPEC.md`, `docs/M10_5_SPEC.md`, `docs/M10_QUALIFICATION.md`, `docs/M11_2_SPEC.md` and `docs/M11_QUALIFICATION.md`.

M13 makes selected evidence portable without changing its classification. Operators can create deterministic manifests, package exact evidence bytes into deterministic ZIPs, verify them offline, add detached Ed25519 signatures, manage trusted signing keys, authenticate trust-store updates with a separately pinned root key, and persist rollback-resistant trust-update state across restarts. See `docs/M13_QUALIFICATION.md`.

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

## Persistent appliance layout

```text
/data/aaa/
├── drop/
├── incoming/
├── clean/
├── quarantine/
├── unknown/
├── reports/
├── signatures/
└── state/
    └── evidence-trust/
```

No submitted material is automatically deleted.

## Reference appliance installation and qualification

When the reference hardware is available, M0 remains the foundation qualification. The production daemon is installed with the M9 installer; M10 adds its HTTP/UI runtime gate, M11 adds the authenticated SMB drop-folder gate, and M12 adds the physical Greaseweazle acquisition gate:

```sh
sudo sh scripts/qualify-m0.sh
sudo AAA_BINARY=./aaa-linux-arm64 sh scripts/install-m9.sh
sudo sh scripts/qualify-m9.sh
sudo sh scripts/qualify-m10.sh
sudo AAA_SMB_PASSWORD_FILE=/root/aaa-smb-password sh scripts/install-m11.sh
sudo AAA_SMB_PASSWORD_FILE=/root/aaa-smb-password sh scripts/qualify-m11.sh
sudo sh scripts/qualify-m12.sh
```

M10 is not fully appliance-qualified until the automated M10 runtime gate and the visible/manual browser checklist in `docs/M10_5_SPEC.md` have both passed on the Orange Pi Zero 3 / DietPi reference system. M11 is not appliance-qualified until its authenticated SMB3 end-to-end gate has passed on the same reference appliance. M12 is not physically qualified until `scripts/qualify-m12.sh` has passed with a real Greaseweazle, drive and diskette and the resulting acquisition evidence has been retained. M13 requires no additional physical hardware gate; a later real-media export/transfer/offline-verification exercise is optional integration evidence.

## Development

AAA currently builds with Go 1.24 or later.

```sh
make test
make build
make build-arm64
```

The core is mostly standard-library Go. M6.1b adds the MIT-licensed `github.com/koron-go/lha` dependency for LHA/LZH decoding; dependency checksums are committed in `go.sum`. M6.2 uses xDMS as a separate runtime decoder rather than linking its code into AAA. M6.3 uses Debian `unar`/`lsar` as separate runtime tools for Amiga LZX. M6.4 uses optional external helper boundaries for preservation formats; AAA does not bundle CAPS/SPS decoder code under its MIT license.

## Roadmap

- M0 appliance foundation — code complete; hardware qualification pending
- M1 `aaa` CLI, hashing, format identification
- M2 ADF and boot-block analysis
- M3 known-clean / known-malicious boot-block database
- M3.1 historical bootblock source qualification
- M4 OFS/FFS traversal
- M4.1 OFS/FFS file payload reconstruction and per-file hashing
- M5 Amiga Hunk analysis
- M6 ADZ/DMS/LHA/LZX/archive pipeline
- M6.4 IPF/FDI preservation-image support
- M7 Signature Factory and signature distribution
- M8 isolated emulated Amiga scanner engines and consensus — code-qualified; real runtime pending
- M9 daemon, REST API, scan history and appliance service integration — code-qualified and API path-redaction hardened; appliance runtime pending
- M10 Web UI — implementation complete; appliance runtime/visual qualification pending
- M11 SMB drop-folder workflow — code-qualified and path-replacement hardened; appliance runtime qualification pending
- M12 Greaseweazle integration — implemented through M12.6; physical acquisition qualification pending hardware
- M13 Portable Evidence Bundles — implemented and code-qualified through M13.7; no physical hardware gate required

Until the reference appliance and acquisition hardware are available, the remaining M0/M8/M9/M10/M11/M12 qualification gates are intentionally recorded as hardware/runtime pending rather than simulated as passes. M13 is independently code-qualified and closed.

## License

AAA is licensed under the MIT License. See `LICENSE`.

Third-party components and historical scanner engines retain their own licenses. The MIT license for AAA does not relicense external GPL, non-commercial, or proprietary components.
