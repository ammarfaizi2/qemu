#!/usr/bin/env bash
#
# build-orc-kernel.sh - build a small ORC-unwinder kernel to test qmon against.
#
# Produces a kernel with CONFIG_UNWINDER_ORC=y and frame pointers OFF (the case
# qmon's ORC unwinder handles), plus KASLR, virtio, serial console and a
# detached BTF (for task_struct offsets).  One-time; ~2 min on many cores.
#
# Writes:
#   $ORC_DIR/linux-$VER/arch/x86/boot/bzImage   (the kernel)
#   $ORC_DIR/linux-$VER/System.map              (symbols incl. ORC tables)
#   $ORC_DIR/vmlinux.btf                         (detached BTF, for qmon btf=)
#
# Deps (Debian/Ubuntu):
#   apt-get install -y build-essential flex bison bc libelf-dev libssl-dev \
#                      dwarves cpio
#
set -euo pipefail

ORC_DIR="${ORC_DIR:-/root/orc}"
VER="${VER:-7.2-rc1}"
URL="https://github.com/torvalds/linux/archive/refs/tags/v${VER}.tar.gz"

mkdir -p "$ORC_DIR"; cd "$ORC_DIR"
[ -f linux-src.tar.gz ] || curl -fL --retry 3 -o linux-src.tar.gz "$URL"
[ -d "linux-$VER" ]     || tar -xzf linux-src.tar.gz
cd "linux-$VER"

make defconfig
./scripts/config \
    --enable  UNWINDER_ORC \
    --disable UNWINDER_FRAME_POINTER --disable FRAME_POINTER \
    --enable  RANDOMIZE_BASE \
    --enable  DEBUG_INFO \
    --enable  VIRTIO_PCI --enable VIRTIO_BLK \
    --enable  EXT4_FS --enable EXT2_FS \
    --enable  SERIAL_8250 --enable SERIAL_8250_CONSOLE \
    --enable  BLK_DEV_INITRD --enable BINFMT_ELF \
    --enable  DEVTMPFS --enable DEVTMPFS_MOUNT --enable TMPFS
make olddefconfig

echo "== unwinder config =="
grep -E "CONFIG_UNWINDER_ORC|CONFIG_UNWINDER_FRAME_POINTER|CONFIG_OBJTOOL" .config

make -j"$(nproc)" bzImage
pahole --btf_encode_detached="$ORC_DIR/vmlinux.btf" vmlinux

echo
echo "built:"
echo "  bzImage    : $PWD/arch/x86/boot/bzImage"
echo "  System.map : $PWD/System.map"
echo "  BTF        : $ORC_DIR/vmlinux.btf"
echo "run: tests/orc/test_ktrace_orc.sh"
