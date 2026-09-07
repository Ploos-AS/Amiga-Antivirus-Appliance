# M9.0 — Daemon foundation

## Status

Implemented for code qualification. Persistent scan history, REST endpoints, network submission, authentication and appliance service installation are deliberately deferred to later M9 increments.

## Goal

Introduce a long-lived AAA process without creating a second scanning implementation. The daemon must orchestrate the existing native scanner through a narrow function boundary and provide a bounded, testable job lifecycle that M9.1 persistence and later REST endpoints can reuse.

## CLI contract

```text
aaa daemon [--workers N] [--queue-depth N]
```

Defaults:

- workers: 1
- queue depth: 32

The command accepts no positional arguments. SIGINT and SIGTERM request graceful shutdown.

## Job lifecycle

M9.0 defines these states:

```text
pending -> running -> succeeded
                   -> failed
pending -> canceled   (shutdown before execution)
```

Each job has a cryptographically random opaque ID, submitted timestamp, path, state and terminal result/error. Start and finish timestamps are recorded as the job advances.

M9.0 state is intentionally in memory. M9.1 will replace/augment this with persistent scan history under `/data/aaa/state/` without changing the public lifecycle vocabulary unnecessarily.

## Resource bounds

The worker count and queue depth are explicit positive integers. Submission fails when the queue is full rather than growing memory without bound. This is a foundation requirement for the later network-facing API.

## Scanner boundary

The production daemon calls the existing `scanner.ScanFile` implementation. Tests inject a deterministic scan function. M9 does not fork or duplicate the M1–M8 scanner pipeline.

## Security boundary

M9.0 opens no listening socket and exposes no upload path. Network binding, request-size limits, controlled ingest paths and API authentication policy belong to later M9 increments and must be qualified before remote access is enabled.

## Qualification gate

M9.0 is code-qualified when:

1. `go test ./...` passes.
2. `go vet ./...` passes.
3. `go build ./cmd/aaa` passes.
4. `go build` for `GOOS=linux GOARCH=arm64` passes.
5. daemon tests demonstrate successful and failed terminal states.
6. daemon tests demonstrate bounded queue behavior.
7. invalid worker/queue configuration is rejected.
8. the CLI exposes `aaa daemon` and graceful SIGINT/SIGTERM handling.

Reference Orange Pi Zero 3/DietPi runtime qualification remains a hardware gate and is not claimed by M9.0 code qualification.
