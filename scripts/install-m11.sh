#!/bin/sh
set -eu

DROP_ROOT=${AAA_DROP_ROOT:-/data/aaa/drop}
SMB_USER=aaa-drop
SMB_GROUP=aaa-drop
SMB_CONF=/etc/samba/aaa-drop.conf
SMB_MAIN=/etc/samba/smb.conf

fail() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root"
command -v apt-get >/dev/null 2>&1 || fail "apt-get is required on the reference appliance"
id aaa >/dev/null 2>&1 || fail "AAA daemon user is missing; install M9.5 first"

if ! command -v smbd >/dev/null 2>&1 || ! command -v testparm >/dev/null 2>&1 || ! command -v smbpasswd >/dev/null 2>&1 || ! command -v smbclient >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y samba smbclient
fi

if ! getent group "$SMB_GROUP" >/dev/null 2>&1; then
    addgroup --system "$SMB_GROUP"
fi
if ! id "$SMB_USER" >/dev/null 2>&1; then
    adduser --system --ingroup "$SMB_GROUP" --no-create-home --home /nonexistent --shell /usr/sbin/nologin "$SMB_USER"
fi

usermod -a -G "$SMB_GROUP" aaa
install -d -o "$SMB_USER" -g "$SMB_GROUP" -m 0770 "$DROP_ROOT"
install -o root -g root -m 0644 samba/aaa-drop.conf "$SMB_CONF"

[ -f "$SMB_MAIN" ] || fail "missing $SMB_MAIN"
if ! grep -Fqx 'include = /etc/samba/aaa-drop.conf' "$SMB_MAIN"; then
    printf '\n# AAA M11 SMB drop-folder integration\ninclude = /etc/samba/aaa-drop.conf\n' >>"$SMB_MAIN"
fi

testparm -s "$SMB_MAIN" >/dev/null

if [ -n "${AAA_SMB_PASSWORD_FILE:-}" ]; then
    [ -r "$AAA_SMB_PASSWORD_FILE" ] || fail "AAA_SMB_PASSWORD_FILE is not readable"
    password=$(cat "$AAA_SMB_PASSWORD_FILE")
    [ -n "$password" ] || fail "AAA_SMB_PASSWORD_FILE is empty"
    printf '%s\n%s\n' "$password" "$password" | smbpasswd -s -a "$SMB_USER"
    unset password
    echo "Configured Samba credentials for $SMB_USER from password file."
else
    echo "No SMB password was configured automatically."
    echo "Run: sudo smbpasswd -a $SMB_USER"
fi

if [ -f /etc/default/aaa ] && ! grep -q '^AAA_DROP_ROOT=' /etc/default/aaa; then
    printf 'AAA_DROP_ROOT=%s\n' "$DROP_ROOT" >>/etc/default/aaa
fi

systemctl enable --now smbd.service
systemctl restart smbd.service
systemctl restart aaa.service

echo "AAA M11.2 Samba drop-folder integration installed."
echo "Share: \\\\$(hostname)\\aaa-drop"
echo "Path:  $DROP_ROOT"
echo "User:  $SMB_USER"
echo "Run: sudo ./scripts/qualify-m11.sh"
