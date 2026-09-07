#!/bin/sh
set -eu

PROJECT=aaa
DATA_ROOT=/data/aaa
BINARY_DST=/usr/local/bin/aaa
UNIT_DST=/etc/systemd/system/aaa.service
DEFAULTS=/etc/default/aaa

fail() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl is required"

BINARY_SRC=${AAA_BINARY:-./aaa}
[ -f "$BINARY_SRC" ] || fail "AAA binary not found: $BINARY_SRC (set AAA_BINARY to the built binary)"
[ -x "$BINARY_SRC" ] || fail "AAA binary is not executable: $BINARY_SRC"

if ! id "$PROJECT" >/dev/null 2>&1; then
    adduser --system --group --no-create-home --home "$DATA_ROOT" --shell /usr/sbin/nologin "$PROJECT"
fi

install -d -o aaa -g aaa -m 0750 "$DATA_ROOT"
for dir in incoming clean quarantine unknown reports signatures state; do
    install -d -o aaa -g aaa -m 0750 "$DATA_ROOT/$dir"
done

install -o root -g root -m 0755 "$BINARY_SRC" "$BINARY_DST"
install -o root -g root -m 0644 systemd/aaa-daemon.service "$UNIT_DST"

if [ ! -e "$DEFAULTS" ]; then
    cat >"$DEFAULTS" <<'EOF'
# AAA appliance daemon defaults.
# The API stays loopback-only unless the systemd ExecStart is explicitly
# overridden to add --allow-remote.
AAA_STATE_ROOT=/data/aaa/state
AAA_INCOMING_ROOT=/data/aaa/incoming
AAA_LISTEN=127.0.0.1:8080
EOF
    chmod 0640 "$DEFAULTS"
    chown root:aaa "$DEFAULTS"
fi

systemctl daemon-reload
systemctl enable --now aaa.service

echo "AAA M9.5 daemon installed."
echo "API: http://127.0.0.1:8080"
echo "Run: sudo ./scripts/qualify-m9.sh"
