# M10.5 — Web UI completion and appliance qualification gate

## Goal

M10.5 closes the Web UI development milestone by separating code qualification from reference-appliance runtime and visual qualification.

M10 is code-qualified when the complete repository CI gate is green with the M10.0–M10.4 UI implementation, M10.5 runtime qualifier, and amd64/arm64 builds. M10 is not appliance-qualified until the reference Orange Pi Zero 3 / DietPi system has passed the automated runtime qualifier and a manual browser/visual pass.

## Scope completed before M10.5

- M10.0: same-process, same-origin dependency-free Web UI.
- M10.1: structured native AAA result presentation with raw JSON fallback.
- M10.2: common attributed `engine_results` model for AAA native, ClamAV and historical Amiga engines, including persisted history replay.
- M10.3: per-engine cards, version/database/support-component provenance and explicit engine-disagreement display.
- M10.4: operational dashboard for job state, aggregate verdict counts and observed engine health.

The UI remains embedded in the `aaa daemon` process. No Node.js runtime, CDN, remote JavaScript, separate frontend service or external web asset is required.

## Automated reference-appliance qualifier

`scripts/qualify-m10.sh` is the M10 target-runtime gate.

Default target:

```sh
sudo sh scripts/qualify-m10.sh
```

The script uses `http://127.0.0.1:8080` unless `AAA_BASE_URL` is supplied.

It verifies:

1. `/healthz` reports healthy.
2. `/version` reports API v1.
3. the Web UI index is served.
4. the operational dashboard and engine-health sections are present.
5. `/ui/app.js` contains scan-API and engine-evidence integration.
6. `/ui/style.css` contains dashboard and engine-card styling.
7. UI responses retain `no-store`, `nosniff`, frame denial, no-referrer and same-origin CSP restrictions.
8. API responses retain the stricter `default-src 'none'` CSP.
9. `/api/v1/scans` remains reachable on the same origin.

The qualifier deliberately does not upload a malware sample and does not claim visual correctness.

## Manual browser / visual gate

After the automated qualifier passes on the reference appliance, perform a visible browser session against the appliance UI and record evidence for all of the following:

- dashboard renders without broken layout at desktop width;
- dashboard remains usable at a narrow/mobile-sized viewport;
- daemon health/version are visible;
- upload control accepts a benign test file and queues a scan;
- pending/running state becomes terminal without manual refresh;
- completed scan appears in history with an aggregate verdict;
- opening the scan displays structured native analysis;
- attributed engine cards render when engine evidence is present;
- engine error state is visually distinct from an infected verdict;
- disagreement warning is visible for a controlled fixture where completed engines disagree;
- long hashes and provenance fields wrap without overflowing the page;
- raw JSON fallback is accessible;
- browser developer console contains no frontend errors for the exercised path.

A screenshot or equivalent visual evidence should be retained for the dashboard and one completed scan result. Runtime evidence should record the exact AAA commit/binary version and target platform.

## Qualification states

### Code-qualified

Allowed when CI is green on the M10.5 HEAD. This establishes that:

- Go tests and vet pass;
- UI regression tests pass;
- shell syntax for the M10 qualifier passes;
- the project builds for linux/amd64 and linux/arm64;
- existing AmiGuard compatibility and M9.5 appliance gates remain green.

### Appliance-runtime-qualified

Allowed only after `scripts/qualify-m10.sh` passes against the installed production daemon on the reference appliance.

### Appliance-qualified

Allowed only after both the automated runtime gate and manual browser/visual gate pass on the reference Orange Pi Zero 3 / DietPi system.

## Non-goals

M10.5 does not add authentication, expose the daemon remotely by default, create a new aggregation engine, add a JavaScript framework, or relax the M9.4 loopback/security policy.

## Exit criterion

M10 development is complete when code qualification is green. Hardware availability may leave M10 in the explicit state `code-qualified; appliance-runtime/visual qualification pending` without blocking work on M11.
