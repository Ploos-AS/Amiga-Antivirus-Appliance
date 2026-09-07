#!/bin/sh
set -eu

DROP_ROOT=${AAA_DROP_ROOT:-/data/aaa/drop}
STATE_ROOT=${AAA_STATE_ROOT:-/data/aaa/state}
INCOMING_ROOT=${AAA_INCOMING_ROOT:-/data/aaa/incoming}
SMB_USER=aaa-drop
SMB_GROUP=aaa-drop
SMB_MAIN=/etc/samba/smb.conf
SMB_CONF=/etc/samba/aaa-drop.conf

pass=0
fail=0
warn=0

ok() { printf 'PASS: %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=$((fail + 1)); }
note() { printf 'WARN: %s\n' "$1" >&2; warn=$((warn + 1)); }

printf 'AAA M11 SMB drop-folder qualification\n\n'

[ "$(id -u)" -eq 0 ] && ok 'running as root' || bad 'run as root'
for cmd in testparm smbd smbclient pdbedit systemctl curl; do
    command -v "$cmd" >/dev/null 2>&1 && ok "$cmd available" || bad "$cmd missing"
done

id "$SMB_USER" >/dev/null 2>&1 && ok 'dedicated aaa-drop Unix user exists' || bad 'aaa-drop Unix user missing'
getent group "$SMB_GROUP" >/dev/null 2>&1 && ok 'dedicated aaa-drop group exists' || bad 'aaa-drop group missing'
id -nG aaa 2>/dev/null | tr ' ' '\n' | grep -Fxq "$SMB_GROUP" && ok 'AAA daemon user can read drop group files' || bad 'AAA daemon user is not in aaa-drop group'

if [ -d "$DROP_ROOT" ]; then
    owner=$(stat -c '%U:%G' "$DROP_ROOT")
    mode=$(stat -c '%a' "$DROP_ROOT")
    [ "$owner" = "$SMB_USER:$SMB_GROUP" ] && ok 'drop directory ownership is dedicated' || bad "drop directory owner is $owner"
    [ "$mode" = '770' ] && ok 'drop directory mode is 0770' || bad "drop directory mode is $mode"
else
    bad 'drop directory is missing'
fi

[ -f "$SMB_CONF" ] && ok 'AAA Samba fragment installed' || bad 'AAA Samba fragment missing'
grep -Fqx 'include = /etc/samba/aaa-drop.conf' "$SMB_MAIN" 2>/dev/null && ok 'main Samba config includes AAA fragment' || bad 'main Samba config does not include AAA fragment'

parsed=$(mktemp)
trap 'rm -f "$parsed" "${auth_file:-}" "${payload:-}"' EXIT HUP INT TERM
if testparm -s "$SMB_MAIN" >"$parsed" 2>/dev/null; then
    ok 'testparm accepts Samba configuration'
else
    bad 'testparm rejects Samba configuration'
fi

grep -Eq '^[[:space:]]*server min protocol = SMB2_10$' "$parsed" && ok 'SMB1 disabled by minimum protocol' || bad 'server min protocol is not SMB2_10'
grep -Eq '^[[:space:]]*server max protocol = SMB3$' "$parsed" && ok 'maximum protocol is SMB3' || bad 'server max protocol is not SMB3'
grep -Eq '^[[:space:]]*map to guest = Never$' "$parsed" && ok 'guest mapping disabled' || bad 'guest mapping is not Never'
grep -Eq '^\[aaa-drop\]$' "$parsed" && ok 'aaa-drop share exists' || bad 'aaa-drop share missing'
grep -Eq '^[[:space:]]*path = /data/aaa/drop$' "$parsed" && ok 'share path is isolated drop directory' || bad 'share path is unexpected'
grep -Eq '^[[:space:]]*guest ok = No$' "$parsed" && ok 'guest access disabled' || bad 'guest access is not disabled'
grep -Eq '^[[:space:]]*read only = No$' "$parsed" && ok 'drop share accepts authenticated writes' || bad 'drop share is not writable'
grep -Eq '^[[:space:]]*valid users = aaa-drop$' "$parsed" && ok 'share restricted to aaa-drop user' || bad 'valid users is not restricted to aaa-drop'
grep -Eq '^[[:space:]]*follow symlinks = No$' "$parsed" && ok 'share does not follow symlinks' || bad 'follow symlinks is not disabled'

systemctl is-enabled --quiet smbd.service && ok 'smbd enabled' || bad 'smbd not enabled'
systemctl is-active --quiet smbd.service && ok 'smbd active' || bad 'smbd not active'
systemctl is-active --quiet aaa.service && ok 'AAA daemon active' || bad 'AAA daemon not active'
curl -fsS http://127.0.0.1:8080/healthz 2>/dev/null | grep -q '"status":"ok"' && ok 'AAA health endpoint is healthy' || bad 'AAA health endpoint unavailable'

if pdbedit -L -u "$SMB_USER" >/dev/null 2>&1; then
    ok 'aaa-drop Samba credential exists'
else
    bad 'aaa-drop Samba credential is not configured'
fi

if [ -n "${AAA_SMB_PASSWORD_FILE:-}" ]; then
    if [ ! -r "$AAA_SMB_PASSWORD_FILE" ]; then
        bad 'AAA_SMB_PASSWORD_FILE is not readable'
    else
        auth_file=$(mktemp)
        chmod 0600 "$auth_file"
        {
            printf 'username = %s\n' "$SMB_USER"
            printf 'password = %s\n' "$(cat "$AAA_SMB_PASSWORD_FILE")"
        } >"$auth_file"
        payload=$(mktemp)
        remote="aaa-m11-qualification-$$.bin"
        printf 'AAA M11 qualification payload %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$payload"

        if smbclient //127.0.0.1/aaa-drop -A "$auth_file" -m SMB3 -c "put $payload $remote" >/dev/null 2>&1; then
            ok 'authenticated SMB3 write succeeded'
            found=0
            i=0
            while [ "$i" -lt 30 ]; do
                if grep -Fq "\"name\": \"$remote\"" "$STATE_ROOT/drop-ingest.json" 2>/dev/null; then
                    found=1
                    break
                fi
                sleep 1
                i=$((i + 1))
            done
            [ "$found" -eq 1 ] && ok 'drop watcher persisted successful ingest receipt' || bad 'drop watcher receipt not observed within 30 seconds'

            if find "$INCOMING_ROOT" -maxdepth 1 -type f -name "*-$remote" -print -quit 2>/dev/null | grep -q .; then
                ok 'SMB payload was snapshotted into controlled incoming storage'
            else
                bad 'controlled incoming snapshot was not found'
            fi
            grep -Fq "$remote" "$STATE_ROOT/scan-history.jsonl" 2>/dev/null && ok 'SMB ingest reached persistent scan history' || bad 'SMB ingest did not reach scan history'
            smbclient //127.0.0.1/aaa-drop -A "$auth_file" -m SMB3 -c "del $remote" >/dev/null 2>&1 || note 'could not remove qualification source from SMB drop folder'
        else
            bad 'authenticated SMB3 write failed'
        fi
    fi
else
    note 'AAA_SMB_PASSWORD_FILE not set; authenticated end-to-end SMB write was not exercised'
fi

printf '\nQualification summary: PASS=%d FAIL=%d WARN=%d\n' "$pass" "$fail" "$warn"
[ "$fail" -eq 0 ] || exit 1

if [ -z "${AAA_SMB_PASSWORD_FILE:-}" ]; then
    note 'full M11 appliance qualification still requires an authenticated SMB client write'
else
    printf 'M11 authenticated SMB drop-folder checks passed.\n'
fi
