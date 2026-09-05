# M0 Specification — Appliance Foundation

## Reference platform

- Orange Pi Zero 3
- ARM64 / AArch64
- DietPi based on Debian
- systemd
- persistent local storage

AAA must not depend on Orange Pi-specific APIs.

## Principles

1. Preservation first: never automatically delete submitted material.
2. Least privilege: appliance services run as unprivileged `aaa`.
3. Hostile input: every image, archive and executable is untrusted.
4. Deterministic evidence: future scans preserve hashes and reports.
5. Explicit limits: future parsers/unpackers must bound recursion, expanded size, file count and execution time.
6. Local first: no cloud service or API key is required.
7. ClamAV is one engine, not the Amiga-specific architecture.

## Filesystem contract

Persistent root: `/data/aaa`.

- `incoming/`: submitted material
- `clean/`: material classified clean by configured policy
- `quarantine/`: known malicious material; originals retained
- `unknown/`: material not confidently classified
- `reports/`: machine/human readable reports
- `signatures/`: AAA-owned signature/hash data
- `state/`: databases and runtime state

M0 creates directories only and never moves scan material automatically.

## Service account

M0 creates locked system account `aaa`, with no interactive shell, owning `/data/aaa`.

## ClamAV boundary

The installer installs `clamav` and `clamav-daemon` on apt-based hosts unless `AAA_SKIP_PACKAGES=1` is set. Generic ClamAV coverage must never be represented as complete Amiga virus coverage.

## systemd boundary

`aaa.service` is a non-networked placeholder proving the service/security contract before a real daemon exists. It runs `/usr/local/libexec/aaa/aaa-m0-service` as `aaa` and has write access only beneath `/data/aaa`.

## Qualification contract

`scripts/qualify-m0.sh` checks the service account, directory tree and ownership, installed unit, systemd verification, enabled/active state, runtime user, and reports ClamAV command availability.

## Out of scope

ADF parsing, boot-block recognition, OFS/FFS traversal, Hunk parsing, archive extraction, signature corpus, Web/API/SMB and Greaseweazle integration.

## Exit criteria

On the reference appliance:

```sh
sudo ./scripts/install-m0.sh
sudo ./scripts/qualify-m0.sh
```

must complete successfully and `/data/aaa` must survive service restarts.
