#!/bin/sh
set -eu

BASE_URL=${AAA_BASE_URL:-http://127.0.0.1:8080}

pass=0
fail=0
warn=0

ok() {
    printf 'PASS: %s\n' "$1"
    pass=$((pass + 1))
}

bad() {
    printf 'FAIL: %s\n' "$1" >&2
    fail=$((fail + 1))
}

note() {
    printf 'WARN: %s\n' "$1" >&2
    warn=$((warn + 1))
}

need_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        ok "$1 available"
    else
        bad "$1 is required"
    fi
}

fetch_body() {
    curl -fsS "$1"
}

fetch_headers() {
    curl -fsSI "$1"
}

printf 'AAA M10 Web UI qualification\n'
printf 'Base URL: %s\n\n' "$BASE_URL"

need_cmd curl
if [ "$fail" -ne 0 ]; then
    exit 1
fi

if health=$(fetch_body "$BASE_URL/healthz" 2>/dev/null) && printf '%s' "$health" | grep -q '"status":"ok"'; then
    ok 'daemon health endpoint reports ok'
else
    bad 'daemon health endpoint is unavailable or unhealthy'
fi

if version=$(fetch_body "$BASE_URL/version" 2>/dev/null) && printf '%s' "$version" | grep -q '"api_version":"v1"'; then
    ok 'version endpoint reports API v1'
else
    bad 'version endpoint did not report API v1'
fi

if index=$(fetch_body "$BASE_URL/" 2>/dev/null) && printf '%s' "$index" | grep -q 'Amiga AntiVirus Appliance'; then
    ok 'Web UI index is served'
else
    bad 'Web UI index is unavailable or unexpected'
fi

if printf '%s' "$index" | grep -q 'Operational dashboard' && printf '%s' "$index" | grep -q 'Engine health'; then
    ok 'M10.4 dashboard sections are present'
else
    bad 'operational dashboard sections are missing'
fi

if app=$(fetch_body "$BASE_URL/ui/app.js" 2>/dev/null) && printf '%s' "$app" | grep -q 'engine_results' && printf '%s' "$app" | grep -q '/api/v1/scans'; then
    ok 'Web UI JavaScript includes engine evidence and scan API integration'
else
    bad 'Web UI JavaScript is unavailable or missing expected integration'
fi

if css=$(fetch_body "$BASE_URL/ui/style.css" 2>/dev/null) && printf '%s' "$css" | grep -q '.engine-card' && printf '%s' "$css" | grep -q '.metric'; then
    ok 'Web UI stylesheet includes engine cards and dashboard metrics'
else
    bad 'Web UI stylesheet is unavailable or incomplete'
fi

headers=$(fetch_headers "$BASE_URL/" 2>/dev/null || true)
for header in \
    'cache-control: no-store' \
    'x-content-type-options: nosniff' \
    'x-frame-options: DENY' \
    'referrer-policy: no-referrer'; do
    if printf '%s\n' "$headers" | tr -d '\r' | grep -i -q "^$header$"; then
        ok "UI header $header"
    else
        bad "UI missing header $header"
    fi
done

if printf '%s\n' "$headers" | tr -d '\r' | grep -i '^content-security-policy:' | grep -q "script-src 'self'"; then
    ok 'UI CSP permits only same-origin scripts'
else
    bad 'UI CSP is missing same-origin script restriction'
fi

api_headers=$(fetch_headers "$BASE_URL/healthz" 2>/dev/null || true)
if printf '%s\n' "$api_headers" | tr -d '\r' | grep -i '^content-security-policy:' | grep -q "default-src 'none'"; then
    ok 'API retains strict non-UI CSP'
else
    bad 'API strict CSP was not observed'
fi

if scans=$(fetch_body "$BASE_URL/api/v1/scans" 2>/dev/null); then
    case "$scans" in
        \[*\]) ok 'scan history endpoint is reachable from UI origin' ;;
        *) bad 'scan history endpoint returned unexpected payload' ;;
    esac
else
    bad 'scan history endpoint is unavailable'
fi

note 'manual browser/visual qualification is still required before appliance-qualified status'
printf '\nQualification summary: PASS=%d FAIL=%d WARN=%d\n' "$pass" "$fail" "$warn"

if [ "$fail" -ne 0 ]; then
    exit 1
fi

printf 'M10 automated runtime checks passed.\n'
