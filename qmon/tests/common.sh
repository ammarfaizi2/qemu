# common.sh - shared helpers for qmon tests (source this; do not run directly).
#
# A test script does:
#     source "$(dirname "$0")/common.sh"
#     qmon_begin            # build + (reuse|boot) a guest + ensure target running
#     run_check <name> [args]
#
# qmon_begin reuses a shared guest when QMON_SOCK is exported (set by run_all.sh);
# otherwise it boots its own guest and arranges teardown on exit.  Must run as
# root (the appliance image is loop-mounted to inject the guest workload).

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QMON_DIR="$(cd "$TESTS_DIR/.." && pwd)"
RUN="$(cd "$QMON_DIR/.." && pwd)/000_run"
APP="$RUN/appliance.d"
QEMU="${QEMU:-/root/qemu/build/qemu-system-x86_64}"
CLIENT="$QMON_DIR/client.py"
PLUGIN="$QMON_DIR/qmon.so"
TARGET="$RUN/root/qmon_target"
KSYMS="${KSYMS:-/boot/System.map-$(uname -r)}"
BTF="${BTF:-/sys/kernel/btf/vmlinux}"

QMON_OWNED=0          # 1 if this process booted the guest (=> we tear it down)

qmon_build() {
    make -C "$QMON_DIR" all guest >/dev/null || { echo "FAIL: build"; exit 1; }
}

# Fixed VAs of the freestanding guest workload -> MARKER / COUNTER.  Normalised
# to the minimal 0x form (printf %#lx, no leading zeros) so they compare equal to
# the addresses the ylang probe prints.
qmon_symbols() {
    local m c
    m="$(nm "$TARGET" | awk '$3=="marker"{print $1}')"
    c="$(nm "$TARGET" | awk '$3=="g_counter"{print $1}')"
    [ -n "$m" ] && [ -n "$c" ] || { echo "FAIL: no symbols"; exit 1; }
    MARKER="$(printf '0x%x' "0x$m")"
    COUNTER="$(printf '0x%x' "0x$c")"
}

# Inject the (freshly built) workload into the appliance image.
qmon_repack() {
    local mnt; mnt="$(mktemp -d)"
    mount -o loop "$APP/root" "$mnt" || { echo "FAIL: mount (need root + loop)"; exit 1; }
    rm -rf "$mnt/root/root"
    cp -a "$RUN/root" "$mnt/root/root"
    sync; umount "$mnt"; rmdir "$mnt"
}

# Boot a fresh guest with the plugin; sets SOCK/LOG/QPID/FIFODIR; launches target.
qmon_boot() {
    SOCK="${SOCK:-/tmp/qmon_test.$$.sock}"
    LOG="${LOG:-/tmp/qmon_test.$$.log}"
    FIFODIR="$(mktemp -d)"; FIFO="$FIFODIR/cons"; mkfifo "$FIFO"
    rm -f "$SOCK" "$LOG"

    # Boot under real KASLR (no nokaslr): the plugin auto-detects the text slide.
    # Set APPEND="... nokaslr" to override, or pass slide= in QMON_PLUGIN_ARGS.
    "$QEMU" -accel tcg -cpu max -smp 1 -m 1024 \
        -kernel "$APP/kernel" -initrd "$APP/initrd" \
        -drive file="$APP/root",format=raw,if=virtio,cache=unsafe \
        -append "console=ttyS0 root=/dev/vda panic=-1 quiet ${APPEND:-}" \
        -nographic -no-reboot \
        -plugin "$PLUGIN,sock=$SOCK,bp=on,wp=on,ksyms=$KSYMS,btf=$BTF${QMON_PLUGIN_ARGS:-}" \
        <"$FIFO" >"$LOG" 2>&1 &
    QPID=$!
    exec 3>"$FIFO"      # hold console write end open so PID-1 bash doesn't exit
    QMON_OWNED=1
    trap qmon_teardown EXIT   # set now, so a boot failure below still cleans up

    local i
    for i in $(seq 1 60); do [ -S "$SOCK" ] && break; sleep 1; done
    [ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -n 20 "$LOG"; exit 1; }
    for i in $(seq 1 420); do
        grep -q "no job control" "$LOG" && break
        kill -0 "$QPID" 2>/dev/null || { echo "FAIL: qemu died"; tail -n 20 "$LOG"; exit 1; }
        sleep 1
    done
    sleep 3
    printf '/root/root/qmon_target &\n' >&3   # start the deterministic workload
    sleep 5
}

qmon_teardown() {
    [ "$QMON_OWNED" = 1 ] || return 0
    kill -9 "$QPID" 2>/dev/null
    wait "$QPID" 2>/dev/null   # reap so the disk image lock is released before we return
    exec 3>&- 2>/dev/null
    rm -rf "${FIFODIR:-}" "$SOCK" "$LOG" 2>/dev/null
}

# Entry point for a test: build, then reuse a shared guest or boot our own.
qmon_begin() {
    qmon_build
    qmon_symbols
    if [ -n "${QMON_SOCK:-}" ] && [ -S "${QMON_SOCK:-}" ]; then
        SOCK="$QMON_SOCK"          # shared guest provided by run_all.sh
        QMON_OWNED=0
    else
        qmon_repack
        qmon_boot          # sets the teardown trap itself (handles boot failure)
    fi
}

# Run one named check via the python client (one connection per invocation).
run_check() {
    python3 "$CLIENT" "$SOCK" test "$@"
}

# --- ylang / run-y helpers (used by the qemu_pid_ylang_* tests) --------------

# Entry point for the pid-style ylang tests: attach to a running qemu when a PID
# and socket are supplied ($1/$2 or QMON_QPID/QMON_SOCK), else boot our own guest.
# Always builds the workload so MARKER/COUNTER are available.  Sets QPID + SOCK.
qmon_pid_begin() {
    qmon_build
    qmon_symbols
    local pid="${1:-${QMON_QPID:-}}" sock="${2:-${QMON_SOCK:-}}"
    if [ -n "$pid" ] && [ -n "$sock" ]; then
        QPID="$pid"; SOCK="$sock"; QMON_OWNED=0
        kill -0 "$QPID" 2>/dev/null || { echo "FAIL: pid $QPID not running"; exit 1; }
        [ -S "$SOCK" ] || { echo "FAIL: $SOCK is not a socket"; exit 1; }
        echo "== attaching to running qemu pid=$QPID sock=$SOCK =="
    else
        qmon_repack
        qmon_boot          # boots with ylang OFF (no ylang in QMON_PLUGIN_ARGS)
    fi
}

# Send a qmon command over the control socket, e.g. qmon_cli ylang-enable on.
qmon_cli() { python3 "$CLIENT" "$SOCK" "$@"; }

# Write the shared cpu_reg_dump probe to $1, reusing the qemu_cpu_state layout
# from ylang/qmon_ylang.y so the probe can never drift from the plugin.
qmon_ylang_reg_probe() {
    {
        awk '/^struct qemu_cpu_state \{/,/^\};/' "$QMON_DIR/ylang/qmon_ylang.y"
        cat <<'EOF'

_probe qemu_ylang_cpu_reg_dump(struct qemu_cpu_state *cpu) {
    printf("YLANG_REGDUMP cpu=%u rip=%#lx rax=%#lx rsp=%#lx rbp=%#lx cs=%#lx cr3=%#lx\n",
           cpu->cpu_index, cpu->rip, cpu->rax, cpu->rsp, cpu->rbp, cpu->cs, cpu->cr3);
}
EOF
    } > "$1"
}

# Fork run-y on the qemu pid, tracing script $1, output to $2.  Sets RUNY_PID.
qmon_runy_start() {
    timeout "${RUNY_TIMEOUT:-320}" run-y -p "$QPID" "$1" >"$2" 2>&1 &
    RUNY_PID=$!
}
qmon_runy_stop() { kill "${RUNY_PID:-0}" 2>/dev/null; wait "${RUNY_PID:-0}" 2>/dev/null; }

# True if run-y hit a terminal error (benign "cannot find this debug file"
# warnings for stripped system libs are NOT terminal).
qmon_runy_failed() {
    grep -qE "status: errored|failed to compile the ylang script" "$1" 2>/dev/null
}

# Poll file $1 for ERE pattern $2 for up to $3 seconds; abort early on a run-y
# terminal error or exit.  Returns 0 if matched, 1 otherwise.
qmon_wait() {
    local f="$1" pat="$2" n="$3" i=0
    while [ "$i" -lt "$n" ]; do
        grep -qE "$pat" "$f" 2>/dev/null && return 0
        qmon_runy_failed "$f" && return 1
        kill -0 "${RUNY_PID:-0}" 2>/dev/null || return 1
        sleep 1; i=$((i + 1))
    done
    return 1
}

qmon_dump_count() { local c; c=$(grep -c "YLANG_REGDUMP" "$1" 2>/dev/null) || true; echo "${c:-0}"; }
# The %rip of the most recent dump line (hex).
qmon_last_rip() { grep "YLANG_REGDUMP" "$1" | tail -n1 | sed -n 's/.*rip=\(0x[0-9a-fA-F]*\).*/\1/p'; }
