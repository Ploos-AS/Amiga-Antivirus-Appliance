#!/bin/sh
set -eu

DATA_ROOT=/data/aaa
failed=0

pass() { echo "PASS: $*"; }
warn() { echo "WARN: $*"; }
fail() { echo "FAIL: $*" >&2; failed=1; }

echo "AAA M0 qualification"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -sr)"

if id aaa >/dev/null 2>&1; then pass "aaa system account exists"; else fail "aaa system account missing"; fi

for dir in incoming clean quarantine unknown reports signatures state; do
    if [ -d "$DATA_ROOT/$dir" ]; then pass "$DATA_ROOT/$dir exists"; else fail "$DATA_ROOT/$dir missing"; fi
done

if [ -d "$DATA_ROOT" ]; then
    owner=$(stat -c '%U:%G' "$DATA_ROOT")
    if [ "$owner" = "aaa:aaa" ]; then pass "$DATA_ROOT ownership is aaa:aaa"; else fail "$DATA_ROOT ownership is $owner, expected aaa:aaa"; fi
else
    fail "$DATA_ROOT missing"
fi

[ -f /etc/systemd/system/aaa.service ] && pass "aaa.service unit installed" || fail "aaa.service unit missing"

if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify /etc/systemd/system/aaa.service >/dev/null 2>&1 && pass "systemd unit verifies" || fail "systemd unit verification failed"
else
    warn "systemd-analyze unavailable"
fi

systemctl is-enabled aaa.service >/dev/null 2>&1 && pass "aaa.service enabled" || fail "aaa.service not enabled"
systemctl is-active aaa.service >/dev/null 2>&1 && pass "aaa.service active" || fail "aaa.service not active"

user=$(systemctl show -p User --value aaa.service 2>/dev/null || true)
[ "$user" = "aaa" ] && pass "aaa.service runs as aaa" || fail "aaa.service User=$user, expected aaa"

if command -v clamscan >/dev/null 2>&1; then pass "clamscan available: $(clamscan --version | head -n 1)"; else warn "clamscan not available"; fi
if command -v clamdscan >/dev/null 2>&1; then pass "clamdscan available"; else warn "clamdscan not available"; fi

if [ "$failed" -ne 0 ]; then echo "M0 qualification: FAIL" >&2; exit 1; fi

echo "M0 qualification: PASS"
