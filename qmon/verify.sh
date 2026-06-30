#!/usr/bin/env bash
#
# verify.sh - end-to-end test of qmon.so against the 000_run TCG appliance.
#
# Builds the plugin and a deterministic guest workload, injects the workload
# into the appliance image, boots it under TCG with the plugin, launches the
# workload via the serial console, then drives client.py through all five
# objectives and prints PASS/FAIL.  Must run as root (loop-mounts the image).
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
RUN="$(cd "$HERE/.." && pwd)/000_run"
APP="$RUN/appliance.d"
QEMU="${QEMU:-/root/qemu/build/qemu-system-x86_64}"
SOCK="${SOCK:-/tmp/qmon_verify.sock}"
LOG="${LOG:-$RUN/qemu.log}"
PLUGIN="$HERE/qmon.so"
TARGET="$RUN/root/qmon_target"

echo "== build plugin + guest target =="
make all guest || exit 1

echo "== resolve guest symbol VAs =="
MARKER="0x$(nm "$TARGET" | awk '$3=="marker"{print $1}')"
COUNTER="0x$(nm "$TARGET" | awk '$3=="g_counter"{print $1}')"
echo "   marker=$MARKER  g_counter=$COUNTER"
[ "$MARKER" != "0x" ] && [ "$COUNTER" != "0x" ] || { echo "FAIL: no symbols"; exit 1; }

echo "== inject target into appliance image (loop mount) =="
MNT="$(mktemp -d)"
mount -o loop "$APP/root" "$MNT" || { echo "FAIL: mount (need root + loop)"; exit 1; }
rm -rf "$MNT/root/root"
cp -a "$RUN/root" "$MNT/root/root"
sync; umount "$MNT"; rmdir "$MNT"

echo "== boot guest (TCG + plugin, bp=on,wp=on, kernel symbols) =="
# nokaslr makes guest kernel text match System.map exactly (text slide 0).
KSYMS="/boot/System.map-$(uname -r)"
BTF="/sys/kernel/btf/vmlinux"
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
exec 3>"$FIFO"      # hold the console write end open so PID-1 bash doesn't exit
cleanup(){ kill -9 "$QPID" 2>/dev/null; exec 3>&- 2>/dev/null; rm -rf "$FIFODIR"; }
trap cleanup EXIT

for _ in $(seq 1 60); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -n 20 "$LOG"; exit 1; }
grep -m1 -i "qmon: listening" "$LOG" 2>/dev/null || true

echo "== wait for guest shell, then launch target =="
for _ in $(seq 1 420); do
    grep -q "no job control" "$LOG" && break
    kill -0 "$QPID" 2>/dev/null || { echo "FAIL: qemu died"; tail -n 20 "$LOG"; exit 1; }
    sleep 1
done
sleep 3
printf '/root/root/qmon_target &\n' >&3
sleep 5

echo "== selftest =="
python3 client.py "$SOCK" selftest "$MARKER" "$COUNTER"
RC=$?

printf 'echo o > /proc/sysrq-trigger\n' >&3 2>/dev/null || true
sleep 1
exit $RC
