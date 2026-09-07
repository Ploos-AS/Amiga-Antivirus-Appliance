#!/bin/sh
set -eu

AAA_BIN=${AAA_BIN:-./aaa}
GW_BIN=${AAA_GW:-gw}
OUTPUT_ROOT=${AAA_M12_OUTPUT_ROOT:-./qualification/m12-runtime}
SESSION_NAME=${AAA_M12_SESSION_NAME:-reference-floppy}
READS=${AAA_M12_READS:-3}
DEVICE=${AAA_M12_DEVICE:-}
NOTE=${AAA_M12_NOTE:-M12 reference hardware qualification}

pass=0
fail=0

ok() { printf 'PASS: %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=$((fail + 1)); }

printf 'AAA M12 Greaseweazle qualification\n\n'

[ -x "$AAA_BIN" ] && ok 'AAA binary is executable' || bad "AAA binary not executable: $AAA_BIN"
command -v "$GW_BIN" >/dev/null 2>&1 && ok 'Greaseweazle host tool is available' || bad "Greaseweazle tool missing: $GW_BIN"

case "$READS" in
    ''|*[!0-9]*) bad 'AAA_M12_READS must be an integer' ;;
    *) [ "$READS" -ge 2 ] && ok 'ADF repeatability read count is at least 2' || bad 'AAA_M12_READS must be at least 2' ;;
esac

if [ "$fail" -ne 0 ]; then
    printf '\nQualification summary: PASS=%d FAIL=%d\n' "$pass" "$fail"
    exit 1
fi

"$AAA_BIN" version
"$GW_BIN" --version

if [ -n "$DEVICE" ]; then
    if "$GW_BIN" info --device "$DEVICE"; then
        ok 'Greaseweazle device/firmware probe succeeded'
    else
        bad "Greaseweazle device probe failed for $DEVICE"
    fi
else
    if "$GW_BIN" info; then
        ok 'Greaseweazle device/firmware probe succeeded'
    else
        bad 'Greaseweazle device probe failed'
    fi
fi

if [ "$fail" -ne 0 ]; then
    printf '\nQualification summary: PASS=%d FAIL=%d\n' "$pass" "$fail"
    exit 1
fi

mkdir -p "$OUTPUT_ROOT"
prefix="$OUTPUT_ROOT/$SESSION_NAME"

set -- acquire-session --reads "$READS" --gw "$GW_BIN" --note "$NOTE"
if [ -n "$DEVICE" ]; then
    set -- "$@" --device "$DEVICE"
fi
set -- "$@" "$prefix"

printf '\nInsert the reference Amiga floppy in the connected drive.\n'
printf 'Starting physical acquisition session: %s\n\n' "$prefix"

if "$AAA_BIN" "$@"; then
    ok 'AAA acquisition session completed'
else
    bad 'AAA acquisition session failed'
fi

session="$prefix.session.json"
scp="$prefix.scp"
repeatability="$prefix.repeatability.json"

[ -s "$session" ] && ok 'session manifest retained' || bad 'session manifest missing or empty'
[ -s "$scp" ] && ok 'raw SCP flux retained' || bad 'raw SCP flux missing or empty'
[ -s "$repeatability" ] && ok 'ADF repeatability manifest retained' || bad 'repeatability manifest missing or empty'

if [ -s "$session" ]; then
    grep -Fq '"schema": "aaa-acquisition-session-v1"' "$session" && ok 'session schema is M12.4 v1' || bad 'unexpected session schema'
    grep -Fq 'same-operator-session; no SCP-to-ADF derivation asserted' "$session" && ok 'session preserves conservative provenance relationship' || bad 'session relationship statement missing'
    grep -Fq '"format": "scp-raw-flux"' "$session" && ok 'session contains raw SCP evidence' || bad 'raw SCP evidence missing from session'
    grep -Fq '"format": "adf"' "$session" && ok 'session contains ADF evidence' || bad 'ADF evidence missing from session'
fi

printf '\nQualification summary: PASS=%d FAIL=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
printf 'M12 physical Greaseweazle acquisition checks passed.\n'
