# M9.5 appliance and systemd integration

## Goal

Turn the M9 daemon into the production service for the AAA appliance while keeping target-hardware runtime qualification separate from code qualification.

The primary target remains Orange Pi Zero 3 running DietPi/ARM64. Raspberry Pi and other Debian-family ARM64 systems remain portability targets.

## Service model

M9.5 adds `systemd/aaa-daemon.service` as the production daemon unit template. The original M0 unit is retained so the M0 foundation remains reproducible.

The M9.5 installer copies the production template to `/etc/systemd/system/aaa.service` and installs the AAA binary as `/usr/local/bin/aaa`.

The service:

- runs as the dedicated `aaa` user/group;
- launches `/usr/local/bin/aaa daemon`;
- uses `/etc/default/aaa` for `AAA_STATE_ROOT`, `AAA_INCOMING_ROOT`, and `AAA_LISTEN`;
- remains loopback-only by default at `127.0.0.1:8080`;
- restarts on failure;
- has a bounded stop timeout;
- preserves the existing systemd hardening controls;
- has write access only to `/data/aaa`.

Remote API exposure is deliberately not enabled by the defaults file because M9.4 requires the explicit `--allow-remote` opt-in. Operators who later choose remote exposure must make an explicit systemd ExecStart override and provide an appropriate trust/authentication boundary.

## Installation

Build or obtain the binary for the target architecture, then run:

```sh
sudo AAA_BINARY=./aaa-linux-arm64 ./scripts/install-m9.sh
```

For a native build named `aaa`, `AAA_BINARY` may be omitted.

The installer is intentionally idempotent for the system account, directory tree, binary, and unit. It preserves an existing `/etc/default/aaa` so local operator configuration is not silently overwritten.

## Persistent layout

The installer ensures the existing AAA layout exists and is owned by `aaa:aaa`:

- `/data/aaa/incoming`
- `/data/aaa/clean`
- `/data/aaa/quarantine`
- `/data/aaa/unknown`
- `/data/aaa/reports`
- `/data/aaa/signatures`
- `/data/aaa/state`

M9.1 scan history remains under `/data/aaa/state/scan-history.jsonl` by default.

## Qualification

`scripts/qualify-m9.sh` validates on a real system:

1. dedicated account and persistent directory layout;
2. installed production binary and systemd unit;
3. systemd verification, enablement, active state, service user and ExecStart;
4. `/healthz` and `/version` responses over loopback;
5. controlled service restart and API recovery;
6. continued availability of the scan-history path across restart when history exists.

## Code qualification gate

M9.5 is code-qualified when:

1. the production unit and installer/qualifier scripts are present;
2. shell scripts pass `sh -n` in CI;
3. the production unit passes `systemd-analyze verify` in CI where available;
4. existing Go format, module, vet, tests, amd64 build and arm64 build remain green.

## Target-appliance runtime gate

M9.5 is **not** target-appliance-qualified until an Orange Pi Zero 3 with DietPi is available and the qualification script is run there with captured evidence. That later run must additionally demonstrate reboot recovery and at least one persisted scan surviving a service/system reboot cycle.
