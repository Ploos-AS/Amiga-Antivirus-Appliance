# M10.1 Structured scan result UI

## Goal

Replace the M10.0 raw-JSON-first result view with a structured, preservation-oriented presentation of the scan result currently exposed by the M9 API.

## Current result contract

The current `scanner.Result` contract exposes native AAA analysis fields including:

- aggregate verdict and optional detection;
- name, size, SHA-256, and detected format;
- bootblock database match;
- ADF and filesystem analysis;
- Amiga Hunk analysis;
- archive and preservation-image analysis;
- recursive archive member results.

M10.1 must render those fields without inventing engine results that are not present in the current API contract.

ClamAV and historical/emulated M8 engine attribution remain planned integration data. If later API revisions add fields outside the current native result schema, M10.1 preserves visibility through an `Additional attributed evidence` section until dedicated typed UI panels are qualified.

## Presentation

The result view provides:

1. aggregate verdict badge;
2. format, size, and SHA-256 identity;
3. prominent detection message when present;
4. native AAA analysis panels for bootblock, ADF/filesystem, and Hunk evidence;
5. archive and preservation-image panels;
6. recursive archive-member presentation with per-member verdict, hashes, detections, errors, and nested children;
7. an expandable raw API result for audit/debug use;
8. an expandable additional-evidence area for forward-compatible API fields.

The raw API result remains available, but is no longer the primary presentation.

## Security

All dynamic values are HTML-escaped before insertion into generated markup. The existing restrictive M10.0 CSP and same-origin model remain unchanged. No external frontend dependencies are introduced.

## Qualification gate

M10.1 is code-qualified when:

1. the result view is a structured container rather than a raw-only `<pre>` element;
2. the client contains explicit presentation handling for `bootblock_match`, `member_results`, `filesystem`, `hunk`, and `preservation_image`;
3. recursive archive-member results remain visible;
4. unknown future result fields remain inspectable as additional attributed evidence;
5. the complete raw API result remains available for audit/debugging;
6. existing M9/M10 security and routing tests remain green;
7. `gofmt`, module metadata, `go vet`, `go test ./...`, linux/amd64 build, and linux/arm64 build pass in CI.

Browser visual qualification and target Orange Pi Zero 3 appliance qualification remain separate runtime gates.
