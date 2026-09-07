# M9.4 API hardening

## Goal

Harden the M9 daemon HTTP API before appliance exposure or later authentication work.

## Network exposure

The daemon remains loopback-only by default at `127.0.0.1:8080`.

A non-loopback bind such as `0.0.0.0:8080`, `:8080`, a LAN address, or `[::]:8080` is rejected unless the operator explicitly supplies `--allow-remote`.

This is an exposure opt-in, not an authentication mechanism. M9.4 does not claim that an unauthenticated remotely exposed API is suitable for untrusted networks.

## HTTP limits and timeouts

The server uses bounded header parsing and explicit timeouts:

- `ReadHeaderTimeout`: 5 seconds
- `ReadTimeout`: 5 minutes, allowing bounded scan uploads
- `WriteTimeout`: 30 seconds
- `IdleTimeout`: 60 seconds
- `MaxHeaderBytes`: 32 KiB
- upload payload limit: 256 MiB by default, configurable by `--max-upload-bytes`

The upload endpoint also enforces the payload limit while streaming, so a missing or dishonest `Content-Length` cannot bypass the bound.

## Upload surface

`POST /api/v1/scans` accepts raw file bytes. An absent content type is accepted for simple clients; an explicit content type must be `application/octet-stream`.

The optional `X-AAA-Filename` value is treated only as a basename. Directory separators, `.` and `..`, and oversized names are rejected. Clients cannot request an arbitrary host path.

Uploaded content is written to the configured incoming root using a temporary file, SHA-256 is calculated during ingest, and final storage is content-addressed by SHA-256 plus the sanitized basename.

## Response hardening

All API responses set:

- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`

## Qualification gate

M9.4 is code-qualified when:

1. loopback addresses are accepted by default;
2. wildcard/LAN binds are rejected unless `--allow-remote` is explicit;
3. malformed listen addresses are rejected;
4. API security headers are covered by tests;
5. unsupported explicit upload content types are rejected;
6. octet-stream uploads remain accepted;
7. format, module metadata, vet, tests, native build, and linux/arm64 build pass in CI.

Target-appliance exposure and authentication policy remain separate later qualification concerns.
