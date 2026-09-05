#!/bin/sh
set -eu

PROJECT=aaa
DATA_ROOT=/data/aaa
LIBEXEC=/usr/local/libexec/aaa
UNIT=/etc/systemd/system/aaa.service

fail() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl is required"

if [ "${AAA_SKIP_PACKAGES:-0}" != "1" ]; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y clamav clamav-daemon ca-certificates
    else
        echo "WARNING: apt-get not found; skipping ClamAV package installation" >&2
    fi
fi

if ! id "$PROJECT" >/dev/null 2>&1; then
    adduser --system --group --no-create-home --home "$DATA_ROOT" --shell /usr/sbin/nologin "$PROJECT"
fi

install -d -o aaa -g aaa -m 0750 "$DATA_ROOT"
for dir in incoming clean quarantine unknown reports signatures state; do
    install -d -o aaa -g aaa -m 0750 "$DATA_ROOT/$dir"
done

install -d -o root -g root -m 0755 "$LIBEXEC"
install -o root -g root -m 0755 scripts/aaa-m0-service "$LIBEXEC/aaa-m0-service"
install -o root -g root -m 0644 systemd/aaa.service "$UNIT"

systemctl daemon-reload
systemctl enable --now aaa.service

echo "AAA M0 installed."
echo "Run: sudo ./scripts/qualify-m0.sh"
