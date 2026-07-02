#!/usr/bin/env bash
#
# test_ylang_cpu_reg_dump.sh - end-to-end test of the ylang CPU register-dump probe.
#
# The plugin exports a no-op probe target qemu_ylang_cpu_reg_dump(struct
# qemu_cpu_state *cpu) and, when ylang=on, calls it from the per-TB pump with the
# guest registers snapshotted in.  An external ylang script (run via run-y)
# places a uprobe on that symbol in the running qemu process and dumps the regs.
#
# We boot the appliance with ylang=on and a %rip pre-filter pinned to the guest
# workload's marker() (so the nop only fires there, keeping the uprobe cheap),
# fork run-y, and check the captured output is a register snapshot at marker().
#
# run-y (OpenResty XRay CLI) compiles the probe on a cloud build-box and loads it
# via a local agent, so this is slow (~30-60s) and needs network + that CLI; it
# SKIPs cleanly if run-y is unavailable.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -xuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/common.sh"

command -v run-y >/dev/null 2>&1 || { echo "SKIP: run-y not found (OpenResty XRay CLI)"; exit 0; }

# Build + discover the workload's fixed VAs, then boot with the ylang bridge
# gated to marker()'s translation block so the probe target fires only there.
qmon_build
qmon_symbols
# Pin the probe to marker()'s entry exactly: marker() is noinline and reached via
# a call, so its first instruction is a translation-block entry the pump sees.
export QMON_PLUGIN_ARGS=",ylang=on,ylang_lo=$MARKER,ylang_hi=$MARKER"
qmon_repack
qmon_boot            # sets QPID + the teardown trap, injects the workload

# Build the ylang script.  Reuse the SHARED qemu_cpu_state layout by extracting
# it straight from ylang/qmon_ylang.y (so the test can't drift from the plugin),
# then uprobe the plugin's probe target and print the registers.
YDIR="$(mktemp -d)"; YSCRIPT="$YDIR/reg_dump.y"; YOUT="$YDIR/run-y.out"
{
    awk '/^struct qemu_cpu_state \{/,/^\};/' "$QMON_DIR/ylang/qmon_ylang.y"
    cat <<'EOF'

_probe qemu_ylang_cpu_reg_dump(struct qemu_cpu_state *cpu) {
    printf("YLANG_REGDUMP cpu=%u rip=%#lx rax=%#lx rsp=%#lx rbp=%#lx cs=%#lx cr3=%#lx\n",
           cpu->cpu_index, cpu->rip, cpu->rax, cpu->rsp, cpu->rbp, cpu->cs, cpu->cr3);
}
EOF
} > "$YSCRIPT"

echo "== fork run-y on qemu pid $QPID (uprobe qemu_ylang_cpu_reg_dump) =="
timeout 300 run-y -p "$QPID" "$YSCRIPT" >"$YOUT" 2>&1 &
RPID=$!
ycleanup() { kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null; rm -rf "$YDIR"; }
trap 'ycleanup; qmon_teardown' EXIT

# First run uploads qemu's (large) debuginfo to the build-box then compiles the
# probe; once tracing starts, marker() fires every ~100ms of guest time.  Only
# treat a terminal run-y failure as an error (benign "cannot find this debug
# file" warnings for stripped system libs are expected and non-fatal).
hit=""
for _ in $(seq 1 280); do
    if grep -q "YLANG_REGDUMP" "$YOUT" 2>/dev/null; then hit=1; break; fi
    if grep -qE "status: errored|failed to compile the ylang script" "$YOUT" 2>/dev/null; then
        echo "run-y reported a terminal error:"
        grep -E "failed to compile the ylang script|status: errored" "$YOUT" | head -2
        break
    fi
    kill -0 "$RPID" 2>/dev/null || break
    sleep 1
done

echo "== probe output =="
grep "YLANG_REGDUMP" "$YOUT" | head -3 || true
[ -n "$hit" ] || { echo "FAIL: no register dump captured"; echo "---- run-y log tail ----"; tail -n 20 "$YOUT"; exit 1; }

# The dumped rip must equal marker()'s address - proof it is a genuine guest
# register snapshot taken at that exact instruction, not noise.
line="$(grep -m1 "YLANG_REGDUMP" "$YOUT")"
rip="$(printf '%s\n' "$line" | sed -n 's/.*rip=\(0x[0-9a-fA-F]*\).*/\1/p')"
if [ -z "$rip" ] || [ "$(( rip != MARKER ))" -ne 0 ]; then
    echo "FAIL: dumped rip '$rip' is not marker() ($MARKER)"
    exit 1
fi

echo "PASS: ylang cpu_reg_dump captured guest regs at marker() (rip=$rip)"
exit 0
