#!/usr/bin/env bash
#
# qemu_pid_ylang_window.sh - enable/disable the ylang %rip window (ylang_lo/hi)
# at RUNTIME over the unix socket, observed through run-y -p.
#
# Attaches to a running qemu when a PID + socket are given ($1 $2, or
# QMON_QPID/QMON_SOCK); otherwise boots the appliance (ylang OFF by default).
#
#   1. window = [marker,marker], ylang on -> every dump is at marker()
#   2. REQ_YLANG_WINDOW off (wide open)    -> the probe fires at other %rip too
#
# Needs the OpenResty XRay CLI (run-y); SKIPs cleanly if absent.  Step 2 briefly
# fires the probe on every block (an intentional uprobe flood): we only need one
# non-marker dump to prove the window is off, then we tear down.  Self-boot mode
# needs root; attach mode does not.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/common.sh"

command -v run-y >/dev/null 2>&1 || { echo "SKIP: run-y not found (OpenResty XRay CLI)"; exit 0; }

qmon_pid_begin "$@"

# Enable ylang with the window pinned to marker().
qmon_cli ylang-window "$MARKER" "$MARKER"
qmon_cli ylang-enable on

YDIR="$(mktemp -d)"; YSCRIPT="$YDIR/reg_dump.y"; YOUT="$YDIR/run-y.out"
qmon_ylang_reg_probe "$YSCRIPT"

echo "== fork run-y on qemu pid $QPID (window pinned to marker) =="
qmon_runy_start "$YSCRIPT" "$YOUT"
trap 'qmon_runy_stop; rm -rf "${YDIR:-}"; qmon_teardown' EXIT

qmon_wait "$YOUT" "YLANG_REGDUMP" 300 \
    || { echo "FAIL: no dumps with window at marker"; tail -n 20 "$YOUT"; exit 1; }

fails=0

# 1. window active: EVERY dump must be at marker().
sleep 4
if grep "YLANG_REGDUMP" "$YOUT" | grep -qv "rip=$MARKER "; then
    echo "[FAIL] window on: saw a dump with rip != marker():"
    grep "YLANG_REGDUMP" "$YOUT" | grep -v "rip=$MARKER " | head -2
    fails=$((fails + 1))
else
    n="$(qmon_dump_count "$YOUT")"
    echo "[PASS] window on: all $n dump(s) at marker() ($MARKER)"
fi

# 2. disable the window (wide open) -> the probe now fires at other %rip too.
qmon_cli ylang-window off
found_other=""
for _ in $(seq 1 30); do
    if grep "YLANG_REGDUMP" "$YOUT" | grep -qv "rip=$MARKER "; then found_other=1; break; fi
    qmon_runy_failed "$YOUT" && break
    kill -0 "${RUNY_PID:-0}" 2>/dev/null || break
    sleep 1
done
if [ -n "$found_other" ]; then
    other="$(grep "YLANG_REGDUMP" "$YOUT" | grep -v "rip=$MARKER " | tail -n1 \
             | sed -n 's/.*\(rip=0x[0-9a-fA-F]*\).*/\1/p')"
    echo "[PASS] window off: probe fired outside marker() ($other)"
else
    echo "[FAIL] window off: still only marker() dumps"; fails=$((fails + 1))
fi

echo
[ "$fails" -eq 0 ] && echo "PASS: ylang runtime window on/off" || echo "$fails CHECK(S) FAILED"
exit "$fails"
