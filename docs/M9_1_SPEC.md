# M9.1 — Persistent scan history

## Status

Implemented for code qualification. REST exposure of history remains M9.2.

## Goal

Persist daemon scan-job lifecycle and results under `/data/aaa/state/` so scan history survives daemon and appliance restarts without introducing a second scanner pipeline.

## Storage model

M9.1 uses an append-only JSON Lines journal:

```text
/data/aaa/state/scan-history.jsonl
```

The root can be overridden with `AAA_STATE_ROOT` or `aaa daemon --state-root` for qualification and non-appliance deployments.

Each lifecycle transition is written as a complete `daemon.Job` snapshot. The journal is fsynced before `Record` returns. Replay selects the last snapshot for each job ID and orders jobs by submission time, newest first.

The append-only format is intentional for M9.1:

- no CGO dependency is introduced;
- `linux/arm64` cross-build remains straightforward;
- writes are auditable as lifecycle events;
- later REST code can consume a reconstructed latest-state view;
- migration to an indexed store remains possible if query volume later justifies it.

## Lifecycle persistence

The daemon records:

1. `pending` after submission is accepted into daemon state;
2. `running` immediately before invoking the existing scanner;
3. `succeeded` or `failed` with terminal result/error;
4. `canceled` for pending work not executed during shutdown.

A journal write failure is a daemon error. The daemon must not silently claim durable history when persistence has failed.

## Replay and corruption

Daemon startup replays the journal before workers start. Malformed non-empty records are fatal startup errors rather than silently skipped history.

M9.1 does not yet resume interrupted `running` jobs. A later recovery increment may define explicit interrupted/retry semantics. The existing journal preserves the evidence needed to do that safely.

## Data content

The terminal job snapshot retains the full native `scanner.Result`, including SHA-256, format, verdict and existing scanner evidence fields. Later M9 increments may extend the shared result model for ClamAV and emulated-engine attribution; M9.1 does not discard those future requirements.

## Qualification gate

M9.1 is code-qualified when:

1. `go test ./...` passes;
2. `go vet ./...` passes;
3. `go build ./cmd/aaa` passes;
4. `GOOS=linux GOARCH=arm64 go build ./cmd/aaa` passes;
5. journal append/replay tests pass;
6. replay returns only the latest state per job;
7. replay ordering is deterministic, newest submission first;
8. corrupt journal input is rejected;
9. daemon startup validates replay before accepting work;
10. journal failures are surfaced as daemon failures.

Reference Orange Pi Zero 3/DietPi power-loss and reboot qualification remains a hardware gate and is not claimed by M9.1 code qualification.
