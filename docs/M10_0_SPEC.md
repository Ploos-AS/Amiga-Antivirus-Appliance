# M10.0 Web UI foundation

## Goal

Provide the first appliance-local browser UI for AAA without introducing a separate frontend runtime or duplicating scan logic.

## Architecture

The Web UI is embedded in the existing Go `aaa` binary and served by the same HTTP server as the M9 API.

- `/` and `/ui/` serve the dashboard.
- `/ui/app.js` and `/ui/style.css` are embedded assets.
- all non-UI routes delegate to the existing M9 API handler.
- the UI consumes `/healthz`, `/version`, and `/api/v1/scans` over the same origin.
- no Node.js, npm, CDN, external fonts, analytics, or third-party browser dependencies are required.

The M9 API remains the authoritative application interface. M10 must not create a second scan/history model.

## Initial UI capabilities

M10.0 provides:

1. appliance health display;
2. daemon/API version display;
3. scan-history table with periodic refresh;
4. raw file upload using `POST /api/v1/scans`;
5. individual scan-result display using `/api/v1/scans/{id}/results`;
6. responsive layout suitable for desktop and small appliance-management screens.

## Security boundary

The daemon remains bound to `127.0.0.1:8080` by default. M10 does not weaken the M9.4 remote-exposure gate.

UI responses set `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive Content Security Policy. JavaScript and CSS are served as separate same-origin resources; inline scripts and remote resources are not required.

M10.0 does not add authentication. Remote binding remains an explicit operator opt-in and is not considered safe for untrusted networks merely because a UI exists.

## Qualification gate

M10.0 is code-qualified when:

1. the root dashboard and embedded JS/CSS assets are served successfully;
2. UI routes do not shadow M9 API routes;
3. same-origin API delegation is covered by tests;
4. UI write methods are rejected;
5. UI security headers and CSP are covered by tests;
6. scan upload, history refresh, and result retrieval are represented by the embedded client;
7. `gofmt`, module metadata, `go vet`, `go test ./...`, linux/amd64 build, and linux/arm64 build pass in CI.

Visual/browser qualification and target Orange Pi Zero 3 appliance qualification remain separate runtime gates.
