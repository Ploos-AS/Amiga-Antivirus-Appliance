# M10 Web UI qualification

## Status

**Code qualification: pending final M10.5 CI gate**  
**Reference-appliance runtime qualification: pending Orange Pi Zero 3 / DietPi hardware**  
**Manual browser / visual qualification: pending reference appliance**

This document is the roll-up qualification record for M10. The individual implementation contracts remain in `docs/M10_0_SPEC.md` through `docs/M10_5_SPEC.md`.

## Completed implementation chain

| Stage | Scope | Code status |
| --- | --- | --- |
| M10.0 | Embedded same-origin Web UI foundation | CI-qualified |
| M10.1 | Structured native scan result UI | CI-qualified |
| M10.2 | Common attributed engine-evidence model and history replay | CI-qualified |
| M10.3 | Per-engine cards, provenance and disagreement display | CI-qualified |
| M10.4 | Operational dashboard and observed engine-health view | CI-qualified |
| M10.5 | Completion gate, automated target qualifier and qualification roll-up | final CI pending |

Known green milestone heads before M10.5:

- M10.0: `cd64fdb08e9118417448da3c186a48006d1cb944` — CI #339 green.
- M10.1: `3b1cb056b9a67f11390e5d650db18544dab4c611` — CI #342 green.
- M10.2: `efa16d863c1a6ea7520bb16c1b0e89458b272ac2` — CI #354 green.
- M10.3: `98a558e929240a0b4cfd29ef14884055e7d44108` — CI #357 green.
- M10.4: `d082d089efae156f9a2ee37237ac59d953ca8edc` — CI #360 green.

## Final code qualification gate

The final M10.5 HEAD must pass the complete repository CI workflow:

- research manifest validation;
- `gofmt` cleanliness;
- appliance shell syntax, including `scripts/qualify-m10.sh`;
- M9.5 systemd unit verification;
- `go mod tidy -diff`;
- `go vet ./...`;
- `go test ./...` including all M10 Web UI regression tests;
- AmiGuard compatibility validation;
- linux/amd64 build;
- linux/arm64 build.

When this gate is green, update this document to record the exact M10.5 HEAD and CI run and mark M10 **code-qualified**.

## Reference-appliance runtime gate

On the installed Orange Pi Zero 3 / DietPi reference system:

```sh
sudo sh scripts/qualify-m9.sh
sudo sh scripts/qualify-m10.sh
```

The M9 qualifier establishes the installed daemon/systemd/persistence baseline. The M10 qualifier then verifies the Web UI, assets, same-origin API integration and route-specific security headers against the running production daemon.

Record at minimum:

- `uname -a`;
- DietPi/Debian release information;
- exact AAA binary version and Git commit;
- `systemctl status aaa --no-pager`;
- complete output from `scripts/qualify-m9.sh`;
- complete output from `scripts/qualify-m10.sh`.

A runtime pass without the manual browser/visual pass is **appliance-runtime-qualified**, not fully appliance-qualified.

## Manual browser / visual gate

Use a visible browser session. Headless-only evidence is insufficient for the final M10 visual gate.

Verify the checklist in `docs/M10_5_SPEC.md`, including dashboard rendering, responsive/narrow layout, benign upload/queue flow, terminal-state refresh, structured result view, engine cards, controlled disagreement rendering, long provenance/hash wrapping, raw JSON fallback and absence of frontend console errors.

Retain at least:

1. one dashboard screenshot;
2. one completed scan-result screenshot with attributed engine evidence when available;
3. the exact browser/version used for the visible qualification.

## Qualification claim boundaries

M10 code qualification does **not** prove:

- Orange Pi browser rendering;
- production daemon latency under real appliance load;
- historical Amiga-engine runtime availability;
- ClamAV installation/runtime health;
- correct rendering of every possible third-party engine result;
- remote deployment safety or authentication.

The daemon remains loopback-only by default. `--allow-remote` remains an explicit exposure opt-in rather than an authentication mechanism.

## Current decision

M10 completion does not block M11 development while hardware is unavailable. The valid interim state is:

> M10 code-qualified; reference-appliance runtime and manual visual qualification pending.
