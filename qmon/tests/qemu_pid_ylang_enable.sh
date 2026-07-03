#!/usr/bin/env bash
#
# qemu_pid_ylang_enable.sh - toggle the ylang bridge ON/OFF at RUNTIME over the
# unix socket, observed through run-y -p on the qemu process.
#
# Attaches to a running qemu when a PID + socket are given ($1 $2, or
# QMON_QPID/QMON_SOCK); otherwise boots the appliance (ylang OFF by default).
# The %rip window is pinned to marker() so that, once enabled, the probe fires
# cheaply at a single instruction.
#
#   1. run-y attached, ylang OFF   -> no register dumps
#   2. REQ_YLANG_ENABLE on          -> dumps appear at marker()
#   3. REQ_YLANG_ENABLE off         -> dumps stop
#
# Needs the OpenResty XRay CLI (run-y); SKIPs cleanly if absent.  Self-boot mode
# needs root (loop-mounts the appliance); attach mode does not.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/common.sh"

command -v run-y >/dev/null 2>&1 || { echo "SKIP: run-y not found (OpenResty XRay CLI)"; exit 0; }

qmon_pid_begin "$@"

# Start from a known state (robust when attaching to a reused guest): ylang OFF,
# window pinned to marker()'s entry so enabling later doesn't flood the uprobe.
qmon_cli ylang-enable off
qmon_cli ylang-window "$MARKER" "$MARKER"

YDIR="$(mktemp -d)"; YSCRIPT="$YDIR/reg_dump.y"; YOUT="$YDIR/run-y.out"
qmon_ylang_reg_probe "$YSCRIPT"

echo "== fork run-y on qemu pid $QPID (ylang currently OFF) =="
qmon_runy_start "$YSCRIPT" "$YOUT"
trap 'qmon_runy_stop; rm -rf "${YDIR:-}"; qmon_teardown' EXIT

qmon_wait "$YOUT" "Start tracing" 300 \
    || { echo "FAIL: run-y never started tracing"; tail -n 20 "$YOUT"; exit 1; }

fails=0

# 1. ylang OFF: the plugin never calls the probe target, so no dumps.
sleep 5
base="$(qmon_dump_count "$YOUT")"
if [ "$base" -eq 0 ]; then
    echo "[PASS] ylang off: no dumps (count=0)"
else
    echo "[FAIL] ylang off but $base dump(s) seen"; fails=$((fails + 1))
fi

# 2. enable at runtime -> dumps appear at marker().
qmon_cli ylang-enable on
if qmon_wait "$YOUT" "YLANG_REGDUMP" 60; then
    rip="$(qmon_last_rip "$YOUT")"
    if [ "$rip" = "$MARKER" ]; then
        echo "[PASS] runtime enable: dumps appeared at marker() rip=$rip"
    else
        echo "[FAIL] enable: dump rip=$rip != marker $MARKER"; fails=$((fails + 1))
    fi
else
    echo "[FAIL] runtime enable: no dumps after 'ylang-enable on'"; tail -n 15 "$YOUT"
    fails=$((fails + 1))
fi

# 3. disable at runtime -> dumps stop (let any in-flight dump settle first).
qmon_cli ylang-enable off
sleep 4; c1="$(qmon_dump_count "$YOUT")"
sleep 6; c2="$(qmon_dump_count "$YOUT")"
if [ "$c2" -eq "$c1" ]; then
    echo "[PASS] runtime disable: dumps stopped (steady at $c2)"
else
    echo "[FAIL] disable: dumps kept growing $c1 -> $c2"; fails=$((fails + 1))
fi

echo
[ "$fails" -eq 0 ] && echo "PASS: ylang runtime enable/disable" || echo "$fails CHECK(S) FAILED"
exit "$fails"
