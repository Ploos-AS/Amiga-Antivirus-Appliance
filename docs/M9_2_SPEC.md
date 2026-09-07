# M9.2 — Read-only REST API

## Goal

Expose daemon health, version and persistent scan history through a small versioned HTTP API without adding scan submission or remote file access yet.

M9.2 is deliberately read-only. Scan creation remains outside the HTTP surface until M9.3.

## Default listener

The daemon listens on:

```text
127.0.0.1:8080
```

by default. This keeps the unauthenticated M9.2 API local to the appliance/development host.

The address can be changed explicitly with:

```text
--listen <address>
AAA_LISTEN=<address>
```

Binding to a non-loopback address is therefore an explicit operator choice.

## Endpoints

### `GET /healthz`

Returns daemon HTTP health:

```json
{"status":"ok"}
```

### `GET /version`

Returns the AAA binary version and API contract version:

```json
{
  "version": "0.6.0-dev",
  "api_version": "v1"
}
```

### `GET /api/v1/scans`

Returns the latest persistent snapshot for each scan, ordered by M9.1 history order (newest submission first).

The list response intentionally omits the daemon's host-side input path. It contains lifecycle identity/state/timestamps and any terminal error.

### `GET /api/v1/scans/{id}`

Returns the lifecycle metadata for one scan. Unknown IDs return `404`.

### `GET /api/v1/scans/{id}/results`

Returns the existing `scanner.Result` for a completed scan. If the scan exists but no result is available, the API returns `409 Conflict` rather than inventing an empty/clean result.

## Error semantics

JSON errors use:

```json
{"error":"..."}
```

M9.2 uses:

- `404` for unknown routes/scans;
- `405` for non-GET methods, with `Allow: GET`;
- `409` when a known scan has no result yet;
- `500` when persistent history cannot be replayed/read.

History errors are not normalized into an empty successful list.

## History consistency

The API reads the same M9.1 append-only JSONL journal used by the daemon recorder. It does not maintain a second database or alternate scan model.

Two M9.1 edge cases are closed before exposing history:

1. a scan rejected because the bounded queue is full receives a persisted terminal `canceled` snapshot with `scan queue is full` rather than leaving an orphaned `pending` record;
2. `pending` or `running` jobs discovered after daemon restart are appended as terminal `canceled` records with an explicit restart reason.

This prevents the REST API from presenting scans that can never make further progress as permanently active.

## HTTP behavior

Responses use `application/json` and `Cache-Control: no-store`.

The daemon configures bounded HTTP server timeouts for request headers, reads, writes and idle connections and performs graceful HTTP shutdown together with the scan manager.

## Non-goals

M9.2 does not provide:

- `POST` scan submission;
- file upload;
- arbitrary host-file retrieval;
- authentication/authorization;
- TLS termination;
- public/LAN binding by default;
- pagination/filtering;
- Web UI.

Those concerns are handled in later M9/M10 slices.

## Code qualification

M9.2 is code-qualified when CI proves:

1. health/version endpoints return the versioned JSON contract;
2. scan list/detail are backed by persistent M9.1 history;
3. scan result retrieval preserves the existing scanner result object;
4. missing result, missing scan and history failure have explicit non-200 semantics;
5. non-GET methods are rejected;
6. scan list/detail do not expose the daemon host input path;
7. queue-full rejection is persisted terminally;
8. interrupted jobs are terminally reconciled after restart;
9. formatting, vet, unit tests and amd64/arm64 builds remain green.

Target Orange Pi Zero 3 + DietPi appliance qualification remains pending until hardware is available and is not required to call this code slice code-qualified.
