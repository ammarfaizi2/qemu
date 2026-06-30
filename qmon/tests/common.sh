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

# Fixed VAs of the freestanding guest workload -> MARKER / COUNTER.
qmon_symbols() {
    MARKER="0x$(nm "$TARGET" | awk '$3=="marker"{print $1}')"
    COUNTER="0x$(nm "$TARGET" | awk '$3=="g_counter"{print $1}')"
    [ "$MARKER" != "0x" ] && [ "$COUNTER" != "0x" ] || { echo "FAIL: no symbols"; exit 1; }
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

    "$QEMU" -accel tcg -cpu max -smp 1 -m 1024 \
        -kernel "$APP/kernel" -initrd "$APP/initrd" \
        -drive file="$APP/root",format=raw,if=virtio,cache=unsafe \
        -append "console=ttyS0 root=/dev/vda panic=-1 quiet nokaslr" \
        -nographic -no-reboot \
        -plugin "$PLUGIN,sock=$SOCK,bp=on,wp=on,ksyms=$KSYMS,btf=$BTF" \
        <"$FIFO" >"$LOG" 2>&1 &
    QPID=$!
    exec 3>"$FIFO"      # hold console write end open so PID-1 bash doesn't exit
    QMON_OWNED=1

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
        qmon_boot
        trap qmon_teardown EXIT
    fi
}

# Run one named check via the python client (one connection per invocation).
run_check() {
    python3 "$CLIENT" "$SOCK" test "$@"
}
