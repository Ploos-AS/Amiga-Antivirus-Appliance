# M10.4 — Operational dashboard UX

## Goal

M10.4 turns the embedded M10 web UI into a useful local appliance dashboard without adding a second backend or a frontend build toolchain.

The dashboard remains same-origin, dependency-free and served by the existing `aaa daemon` process.

## Dashboard metrics

The landing page derives operational counters from the existing `/api/v1/scans` history response:

- total recorded jobs;
- active jobs (`pending` + `running`);
- completed `infected` verdicts;
- completed `clean` verdicts;
- completed `unknown` verdicts;
- observed engine execution errors in stored engine evidence.

These are presentation-layer summaries of persisted history. They do not introduce a new authoritative state store.

## Engine health

The UI summarizes attributed `engine_results` observed in up to the 25 most recent successful scans. Per engine it shows:

- engine name and kind;
- latest observed verdict;
- observed run count;
- observed execution-error count;
- latest recorded engine version;
- latest recorded database version when available.

`Engine health` means observed evidence in recent completed scans. It is not a daemon liveness probe for an engine that has never been invoked, and it must not claim runtime qualification for historical scanners.

## Scan history

The scan-history table now exposes the stored aggregate verdict beside lifecycle state. Pending/running/failed/canceled jobs remain distinguishable from completed verdicts.

## Security and architecture

M10.4 does not change the M9 network/security contract:

- loopback-only bind remains the default;
- `--allow-remote` remains an explicit exposure opt-in, not authentication;
- no CDN, npm, Node or external JavaScript is introduced;
- all dashboard data is fetched from existing same-origin AAA API endpoints;
- Content Security Policy and existing UI security headers remain in place.

## Qualification

Code qualification requires:

1. existing repository CI gates remain green;
2. UI asset tests confirm the operational metric elements are served;
3. UI asset tests confirm dashboard and engine-health logic is present;
4. M10.3 engine cards and API delegation tests remain green;
5. linux/amd64 and linux/arm64 builds remain green.

Orange Pi Zero 3/DietPi runtime qualification remains pending and is not implied by this milestone.
