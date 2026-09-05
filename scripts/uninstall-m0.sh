#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }

systemctl disable --now aaa.service 2>/dev/null || true
rm -f /etc/systemd/system/aaa.service
rm -f /usr/local/libexec/aaa/aaa-m0-service
rmdir /usr/local/libexec/aaa 2>/dev/null || true
systemctl daemon-reload

cat <<'EOF'
AAA M0 service files removed.

Preserved intentionally:
  /data/aaa
  aaa system account
  ClamAV packages and signatures
EOF
