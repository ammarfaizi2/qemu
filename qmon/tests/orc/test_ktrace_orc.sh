#!/usr/bin/env bash
#
# test_ktrace_orc.sh - verify qmon's ORC unwinder on a frame-pointer-less kernel.
#
# Boots the ORC kernel (from build-orc-kernel.sh) with a minimal initramfs whose
# PID 1 is the qmon workload, then checks slide / breakpoint / watchpoint and the
# kernel call-trace.  The trace MUST reach do_syscall_64 -- which only works via
# ORC here, since this kernel has no frame pointers.  Skips if the kernel
# artifacts are absent.
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
QMON_DIR="$(cd "$HERE/../.." && pwd)"
ORC_DIR="${ORC_DIR:-/root/orc}"
BZ="${ORC_BZIMAGE:-$ORC_DIR/linux-7.2-rc1/arch/x86/boot/bzImage}"
SYSMAP="${ORC_SYSMAP:-$ORC_DIR/linux-7.2-rc1/System.map}"
BTF="${ORC_BTF:-$ORC_DIR/vmlinux.btf}"
QEMU="${QEMU:-/root/qemu/build/qemu-system-x86_64}"
SOCK="${SOCK:-/tmp/qmon_orc.sock}"; LOG="${LOG:-/tmp/qmon_orc.log}"
CLIENT="$QMON_DIR/client.py"; PLUGIN="$QMON_DIR/qmon.so"

for f in "$BZ" "$SYSMAP" "$BTF"; do
    [ -f "$f" ] || { echo "SKIP: missing $f -- run tests/orc/build-orc-kernel.sh first"; exit 0; }
done

echo "== build plugin + workload =="
make -C "$QMON_DIR" >/dev/null || exit 1

# Minimal initramfs: PID 1 is the workload, named qmon_target so comm matches.
WD="$(mktemp -d)"
gcc -static -no-pie -nostartfiles -O2 -fno-stack-protector -o "$WD/qmon_target" "$HERE/orc_init.c"
MARKER="0x$(nm "$WD/qmon_target" | awk '$3=="marker"{print $1}')"
COUNTER="0x$(nm "$WD/qmon_target" | awk '$3=="g_counter"{print $1}')"
mkdir -p "$WD/ir/dev"
cp "$WD/qmon_target" "$WD/ir/qmon_target"
mknod "$WD/ir/dev/console" c 5 1
( cd "$WD/ir" && find . | cpio -o -H newc 2>/dev/null | gzip ) > "$WD/initramfs.cpio.gz"

echo "== boot ORC kernel (no frame pointers) =="
rm -f "$SOCK" "$LOG"
"$QEMU" -accel tcg -cpu max -m 512 \
    -kernel "$BZ" -initrd "$WD/initramfs.cpio.gz" \
    -append "console=ttyS0 rdinit=/qmon_target" -nographic -no-reboot \
    -plugin "$PLUGIN,sock=$SOCK,bp=on,wp=on,ksyms=$SYSMAP,btf=$BTF" \
    </dev/null >"$LOG" 2>&1 &
QPID=$!
cleanup(){ kill -9 "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null; rm -rf "$WD"; }
trap cleanup EXIT

for _ in $(seq 1 60); do [ -S "$SOCK" ] && break; sleep 1; done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared"; tail -n 20 "$LOG"; exit 1; }
for _ in $(seq 1 120); do grep -q "QMON-ORC-INIT" "$LOG" && break; sleep 1; done
sleep 5

echo "== $(grep -m1 -o 'Linux version [^ ]*' "$LOG") (ORC, no frame pointers) =="
fails=0
python3 "$CLIENT" "$SOCK" test slide            || fails=$((fails + 1))
python3 "$CLIENT" "$SOCK" test break "$MARKER"   || fails=$((fails + 1))
python3 "$CLIENT" "$SOCK" test watch "$COUNTER"  || fails=$((fails + 1))
python3 "$CLIENT" "$SOCK" test ktrace            || fails=$((fails + 1))

echo
[ "$fails" -eq 0 ] && echo "ORC TESTS PASSED" || echo "$fails ORC TEST(S) FAILED"
exit "$fails"
