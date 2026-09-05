# AAA — Amiga AntiVirus Appliance

AAA is a preservation-oriented malware scanning appliance for Commodore Amiga software and disk images.

Reference target: Orange Pi Zero 3 running DietPi (ARM64). The core scanner is intended to remain portable.

## M0 — appliance foundation

M0 establishes the DietPi/Debian ARM64 baseline, `/data/aaa` persistent layout, an unprivileged `aaa` service account, systemd hardening baseline, ClamAV integration boundary, and install/qualification workflow.

M0 does **not** claim Amiga-specific malware detection yet.

## Persistent layout

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

## Install on DietPi

```sh
sudo ./scripts/install-m0.sh
sudo ./scripts/qualify-m0.sh
```

See `docs/M0_SPEC.md` and `SECURITY.md` before deployment.

## Roadmap

- M0 appliance foundation
- M1 portable `amigascan` CLI, hashing, format identification
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

No project license has been selected in M0. Third-party components retain their own licenses.
