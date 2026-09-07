# M9.3 — Scan submission API

## Goal

Add controlled HTTP scan submission to the M9 daemon without allowing clients to name arbitrary host filesystem paths.

M9.3 extends the M9.2 read-only API with:

- `POST /api/v1/scans`
- streaming upload into the appliance-controlled incoming directory
- SHA-256 calculation during ingest
- bounded request size
- storage deduplication by SHA-256
- explicit re-scan semantics
- hand-off to the existing bounded daemon scan queue

The existing read-only endpoints remain unchanged.

## Request contract

`POST /api/v1/scans` accepts the file bytes as the HTTP request body.

The optional `X-AAA-Filename` header supplies a display/storage suffix. It is not a path. Values containing `/`, `\\`, `.`/`..` path semantics, or an overlong basename are rejected.

If the header is omitted, `upload.bin` is used.

Clients cannot submit a host path, URL, device name, or other filesystem locator.

## Ingest boundary

The daemon controls the incoming root. The default is:

`/data/aaa/incoming`

It can be changed locally with:

- `--incoming-root`
- `AAA_INCOMING_ROOT`

The default maximum upload size is 256 MiB and can be changed with `--max-upload-bytes`.

Uploads are streamed to a temporary file in the incoming root while SHA-256 is calculated. The implementation does not need to buffer the full payload in memory.

Empty uploads are rejected.

## Storage identity and duplicate policy

The persisted payload name is derived from the computed SHA-256 and the validated basename. A client never chooses the full path.

If an identical SHA-256/basename payload already exists, AAA reuses the existing stored payload rather than storing a second copy.

Every accepted POST still creates a new daemon scan job. This is the M9.3 re-scan policy: storage is deduplicated, scan history is not.

The response reports whether the stored payload was already present.

## Response

Successful submission returns HTTP `202 Accepted` with a JSON object containing:

- `id` — daemon scan job ID
- `state` — normally `pending`
- `sha256` — SHA-256 calculated during ingest
- `size` — accepted payload size in bytes
- `duplicate` — whether an identical stored payload was reused

Clients use the M9.2 GET endpoints to poll job state and retrieve results.

## Failure behavior

- unsafe filename: `400 Bad Request`
- empty upload: `400 Bad Request`
- upload larger than the configured bound: `413 Request Entity Too Large`
- unavailable/full scan queue: `503 Service Unavailable`
- unavailable incoming storage: `500 Internal Server Error`

Internal filesystem paths are not returned in the API response.

## Network exposure

M9.3 does not change the M9.2 network default. The daemon still binds to `127.0.0.1:8080` unless the operator explicitly changes `--listen` or `AAA_LISTEN`.

Authentication, additional request hardening, and broader exposure policy remain M9.4 work.

## Code qualification

M9.3 is code-qualified when CI proves:

1. valid uploads are streamed into the configured incoming root;
2. SHA-256 and accepted size are returned;
3. traversal-style filenames are rejected;
4. configured upload limits are enforced;
5. rejected uploads never reach the scan queue;
6. identical stored payloads are deduplicated while each POST still submits a scan job;
7. queue failures surface as service-unavailable responses;
8. M9.2 read-only behavior remains intact when submission is not configured;
9. `go test ./...`, `go vet ./...`, amd64 build, and linux/arm64 build remain green.

## Runtime qualification

Target-appliance runtime qualification is deferred until the Orange Pi Zero 3 / DietPi appliance is available. Host and CI qualification do not substitute for that hardware gate.
