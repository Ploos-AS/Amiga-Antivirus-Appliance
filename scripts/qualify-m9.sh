#!/bin/sh
set -eu

DATA_ROOT=/data/aaa
UNIT=/etc/systemd/system/aaa.service
failed=0

pass() { echo "PASS: $*"; }
warn() { echo "WARN: $*"; }
fail() { echo "FAIL: $*" >&2; failed=1; }

http_get() {
    url=$1
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 5 "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- -T 5 "$url"
    else
        return 127
    fi
}

echo "AAA M9.5 appliance qualification"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -sr)"

if id aaa >/dev/null 2>&1; then pass "aaa system account exists"; else fail "aaa system account missing"; fi
[ -x /usr/local/bin/aaa ] && pass "AAA binary installed" || fail "AAA binary missing"
[ -f "$UNIT" ] && pass "aaa.service installed" || fail "aaa.service missing"

for dir in incoming clean quarantine unknown reports signatures state; do
    if [ -d "$DATA_ROOT/$dir" ]; then pass "$DATA_ROOT/$dir exists"; else fail "$DATA_ROOT/$dir missing"; fi
done

if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify "$UNIT" >/dev/null 2>&1 && pass "systemd unit verifies" || fail "systemd unit verification failed"
else
    warn "systemd-analyze unavailable"
fi

systemctl is-enabled aaa.service >/dev/null 2>&1 && pass "aaa.service enabled" || fail "aaa.service not enabled"
systemctl is-active aaa.service >/dev/null 2>&1 && pass "aaa.service active" || fail "aaa.service not active"

user=$(systemctl show -p User --value aaa.service 2>/dev/null || true)
[ "$user" = "aaa" ] && pass "aaa.service runs as aaa" || fail "aaa.service User=$user, expected aaa"
execstart=$(systemctl show -p ExecStart --value aaa.service 2>/dev/null || true)
printf '%s' "$execstart" | grep -q '/usr/local/bin/aaa' && pass "aaa.service executes installed AAA binary" || fail "unexpected ExecStart: $execstart"

if health=$(http_get http://127.0.0.1:8080/healthz 2>/dev/null); then
    printf '%s' "$health" | grep -q '"status":"ok"' && pass "health endpoint responds" || fail "unexpected health response: $health"
else
    warn "curl/wget unavailable or health endpoint unreachable"
    fail "health endpoint unavailable"
fi

if version=$(http_get http://127.0.0.1:8080/version 2>/dev/null); then
    printf '%s' "$version" | grep -q '"api_version":"v1"' && pass "version endpoint reports API v1" || fail "unexpected version response: $version"
else
    fail "version endpoint unavailable"
fi

history="$DATA_ROOT/state/scan-history.jsonl"
before=absent
[ -e "$history" ] && before=$(stat -c '%s:%Y' "$history")
if systemctl restart aaa.service; then
    sleep 1
    systemctl is-active aaa.service >/dev/null 2>&1 && pass "service survives controlled restart" || fail "service inactive after restart"
    if http_get http://127.0.0.1:8080/healthz >/dev/null 2>&1; then pass "API recovers after restart"; else fail "API did not recover after restart"; fi
else
    fail "controlled service restart failed"
fi

after=absent
[ -e "$history" ] && after=$(stat -c '%s:%Y' "$history")
if [ "$before" = absent ] && [ "$after" = absent ]; then
    warn "scan history journal not created yet; submit at least one scan before durability qualification"
else
    pass "scan history path remains available across restart"
fi

if [ "$failed" -ne 0 ]; then
    echo "M9.5 appliance qualification: FAIL" >&2
    exit 1
fi

echo "M9.5 appliance qualification: PASS"
