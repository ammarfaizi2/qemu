# Debugging a Kernel with QEMU TCG and GDB

This guide walks through debugging a Linux kernel using QEMU's TCG
(Tiny Code Generator) accelerator and GDB. TCG is QEMU's software CPU
emulator — it JIT-compiles guest x86 instructions into host machine
code, giving QEMU total control over every instruction the guest
executes. This makes it ideal for kernel debugging: unlimited
breakpoints, deterministic single-stepping, full memory inspection
through the emulated MMU, and no dependency on host hardware
virtualization support.

The tradeoff is speed (TCG is ~10-100x slower than KVM), but for
debugging, the control it provides is exactly what you want.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build the Kernel with Debug Symbols](#2-build-the-kernel-with-debug-symbols)
3. [Launch QEMU with TCG and GDB Support](#3-launch-qemu-with-tcg-and-gdb-support)
4. [Connect GDB](#4-connect-gdb)
5. [Debugging Operations](#5-debugging-operations)
6. [TCG Debug Logging](#6-tcg-debug-logging)
7. [Advanced Techniques](#7-advanced-techniques)

---

## 1. Prerequisites

- **QEMU** built with TCG support (enabled by default).
- **GDB** installed on the host (e.g., `gdb` or `gdb-multiarch`).
- **A Linux kernel source tree** to build a debug kernel.
- **A root filesystem** — either an initramfs/initrd image, or a disk
  image with a root filesystem.

## 2. Build the Kernel with Debug Symbols

In your kernel source tree, enable these config options:

```
CONFIG_DEBUG_INFO=y            # Include DWARF debug info in vmlinux
CONFIG_DEBUG_INFO_DWARF5=y     # Use DWARF5 format (or DWARF4)
CONFIG_GDB_SCRIPTS=y           # Enable kernel GDB helper scripts (optional)
CONFIG_FRAME_POINTER=y         # Reliable stack traces in GDB
CONFIG_RANDOMIZE_BASE=n        # Disable KASLR so addresses are stable
CONFIG_DEBUG_INFO_REDUCED=n    # Don't strip debug info
```

Then build:

```bash
make -j$(nproc)
```

You need two artifacts:
- `vmlinux` — the uncompressed kernel ELF with debug symbols (used by
  GDB).
- `arch/x86/boot/bzImage` — the compressed kernel image (used by
  QEMU's `-kernel` flag).

## 3. Launch QEMU with TCG and GDB Support

```bash
qemu-system-x86_64 \
    -accel tcg \
    -s -S \
    -kernel path/to/bzImage \
    -initrd path/to/initramfs.img \
    -append "root=/dev/sda console=ttyS0 nokaslr" \
    -nographic \
    -m 1G
```

### Flag Reference

| Flag | Description |
|------|-------------|
| `-accel tcg` | Use the TCG software CPU emulator (not KVM). |
| `-s` | Shorthand for `-gdb tcp::1234`. Starts a GDB server on port 1234. |
| `-S` | Freeze the CPU at startup. Execution begins only when GDB sends `continue`. |
| `-kernel` | Boot a kernel image directly, bypassing any bootloader. |
| `-initrd` | Provide an initial ramdisk / initramfs. |
| `-append` | Kernel command-line arguments. `nokaslr` disables address randomization. |
| `-nographic` | Redirect serial output to the terminal (no GUI window). |
| `-m 1G` | Allocate 1 GB of guest RAM. |

If you want to use a custom GDB port or a Unix socket instead:

```bash
# Custom TCP port
qemu-system-x86_64 -gdb tcp::3117 -S ...

# Unix socket
qemu-system-x86_64 -gdb unix:/tmp/qemu-gdb.sock -S ...
```

At this point QEMU is running but the CPU is frozen, waiting for GDB.

## 4. Connect GDB

In a separate terminal:

```bash
gdb vmlinux
```

Then inside GDB:

```gdb
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
0x000000000000fff0 in ?? ()

(gdb) break start_kernel
Breakpoint 1 at 0xffffffff81000000: file init/main.c, line 123.

(gdb) continue
Continuing.

Breakpoint 1, start_kernel () at init/main.c:123
123     {
```

The kernel is now paused at the entry to `start_kernel()` and you have
full debugging control.

## 5. Debugging Operations

### 5.1 Inspect CPU Registers

```gdb
(gdb) info registers
rax            0x0                 0
rbx            0xffffffff82a00000  -2102132736
rcx            0x0                 0
rdx            0x0                 0
rsi            0xffffffff82800000  -2104328192
rdi            0x0                 0
rbp            0x0                 0x0
rsp            0xffffffff82803ff0  0xffffffff82803ff0
rip            0xffffffff81000000  0xffffffff81000000 <start_kernel>
eflags         0x46                [ PF ZF ]
cs             0x10                16
ss             0x18                24
...

(gdb) info registers eflags         # Single register
(gdb) print/x $rip                  # Print a register value
(gdb) print/x $cr3                  # Page table base (available in TCG)
```

### 5.2 Examine Memory

```gdb
# Disassemble 20 instructions at the current PC
(gdb) x/20i $rip

# Examine 16 quad-words on the stack
(gdb) x/16gx $rsp

# Examine a kernel symbol
(gdb) x/s linux_banner

# Examine a specific virtual address
(gdb) x/10x 0xffffffff81000000

# Dump raw bytes
(gdb) x/64bx $rip
```

### 5.3 Set Breakpoints

```gdb
# Break at a function
(gdb) break do_page_fault

# Break at an address
(gdb) break *0xffffffff81234567

# Break at a source file:line
(gdb) break kernel/sched/core.c:4321

# Conditional breakpoint
(gdb) break schedule if current_task->pid == 1

# List breakpoints
(gdb) info breakpoints

# Delete a breakpoint
(gdb) delete 2
```

In TCG mode, QEMU provides unlimited software breakpoints. There is no
hardware debug register limit.

### 5.4 Watchpoints

```gdb
# Break when a memory location is written
(gdb) watch *(int *)0xffffffff82a00100

# Break on read or write
(gdb) awatch some_global_variable

# Break on read only
(gdb) rwatch some_global_variable
```

### 5.5 Step Through Code

```gdb
# Step one source line (steps into function calls)
(gdb) step

# Step one source line (steps over function calls)
(gdb) next

# Step one machine instruction
(gdb) stepi

# Step over one machine instruction
(gdb) nexti

# Continue until the current function returns
(gdb) finish

# Continue execution
(gdb) continue
```

### 5.6 Stack Traces and Variables

```gdb
# Full backtrace
(gdb) backtrace

# Backtrace with local variables
(gdb) backtrace full

# Print a kernel variable
(gdb) print current_task
(gdb) print init_task.comm
(gdb) print *(struct task_struct *)0xffff888000123000

# Print with type information
(gdb) ptype struct task_struct

# List source code around current position
(gdb) list
```

## 6. TCG Debug Logging

QEMU can dump detailed execution traces without GDB. This is useful for
understanding what the CPU is actually executing at the machine level.

### 6.1 Log Flags

Use `-d` to enable logging categories and `-D` to redirect output to a
file:

```bash
qemu-system-x86_64 -accel tcg \
    -d in_asm,cpu \
    -D /tmp/qemu-debug.log \
    -kernel bzImage ...
```

| Flag | Description |
|------|-------------|
| `in_asm` | Guest x86 assembly being translated. |
| `out_asm` | Host machine code produced by TCG JIT. |
| `op` | TCG intermediate representation (IR). |
| `op_opt` | TCG IR after optimization passes. |
| `cpu` | Full CPU register dump before each translation block. |
| `exec` | Trace each translation block execution (very verbose). |
| `int` | Interrupts and exceptions. |
| `mmu` | MMU/TLB activity and page faults. |
| `pcall` | x86-specific: protected mode far calls/returns/exceptions. |
| `nochain` | Disable TB chaining for complete per-instruction traces. |
| `cpu_reset` | CPU state at reset. |
| `guest_errors` | Log invalid guest operations. |
| `unimp` | Log unimplemented functionality. |
| `fpu` | Include FPU/SSE registers in `cpu` dumps. |
| `vpu` | Include AVX/vector registers in `cpu` dumps. |

### 6.2 Address Filtering

Use `-dfilter` to restrict logging to specific address ranges:

```bash
# Log only instructions in the kernel text range
qemu-system-x86_64 -accel tcg \
    -d in_asm,cpu \
    -dfilter 0xffffffff81000000..0xffffffff82000000 \
    -D /tmp/kernel-trace.log \
    -kernel bzImage ...
```

Filter format: `start..end`, `start+size`, or `start-size`. Multiple
ranges can be comma-separated.

### 6.3 Practical Examples

```bash
# Trace guest assembly + CPU state (comprehensive but verbose)
qemu-system-x86_64 -accel tcg \
    -d in_asm,cpu,exec -D /tmp/full-trace.log \
    -kernel bzImage -initrd initramfs.img \
    -append "nokaslr" -nographic

# Trace interrupts only (lightweight)
qemu-system-x86_64 -accel tcg \
    -d int -D /tmp/interrupts.log \
    -kernel bzImage -nographic

# See what TCG JIT produces (for TCG development/analysis)
qemu-system-x86_64 -accel tcg \
    -d in_asm,op,out_asm -D /tmp/jit.log \
    -kernel bzImage -nographic

# Disable TB chaining for instruction-level trace
qemu-system-x86_64 -accel tcg \
    -d in_asm,nochain -D /tmp/nochain.log \
    -kernel bzImage -nographic
```

You can also combine `-d` logging with GDB debugging (`-s -S`) — they
work independently.

## 7. Advanced Techniques

### 7.1 Physical Memory Mode

By default, GDB memory commands use virtual addresses (going through the
guest's page tables). To access physical memory directly:

```gdb
(gdb) maintenance packet Qqemu.PhyMemMode:1
# Now all memory reads/writes use physical addresses

(gdb) x/10x 0x1000    # This is now a physical address

# Switch back to virtual addressing
(gdb) maintenance packet Qqemu.PhyMemMode:0
```

### 7.2 Control Single-Step Behavior

By default, single-stepping may pause on interrupts. To suppress IRQs
and timer ticks during stepping:

```gdb
# Query current single-step flags
(gdb) maintenance packet qqemu.sstep

# Set flags: bit 0 = enable, bit 1 = no IRQ, bit 2 = no timer
# Value 0x7 = enable + suppress IRQ + suppress timer
(gdb) maintenance packet Qqemu.sstepbits=0x7
```

This is essential when stepping through code in interrupt-heavy
sections — without it, `stepi` may land inside an interrupt handler
instead of the next instruction.

### 7.3 Multicore Debugging

```bash
qemu-system-x86_64 -accel tcg -smp 4 -s -S -kernel bzImage ...
```

Each vCPU appears as a GDB thread:

```gdb
(gdb) info threads
  Id   Target Id         Frame
* 1    Thread 1 (CPU#0)  start_kernel () at init/main.c:123
  2    Thread 2 (CPU#1)  0xffffffff810001a0 in secondary_startup_64 ()
  3    Thread 3 (CPU#2)  0xffffffff810001a0 in secondary_startup_64 ()
  4    Thread 4 (CPU#3)  0xffffffff810001a0 in secondary_startup_64 ()

(gdb) thread 2         # Switch to CPU#1
(gdb) info registers   # See CPU#1's registers
(gdb) bt               # CPU#1's backtrace
```

### 7.4 Debugging Early Boot (16-bit Real Mode)

The x86 CPU starts in 16-bit real mode. To debug the BIOS or early
bootloader:

```gdb
(gdb) set architecture i8086
(gdb) target remote localhost:1234

# The CPU starts at 0xFFF0 (reset vector)
(gdb) x/10i $eip
(gdb) stepi
```

Switch back to 64-bit mode once the kernel enters long mode:

```gdb
(gdb) set architecture i386:x86-64
```

### 7.5 Using QEMU Monitor Alongside GDB

If you need the QEMU monitor (for VM snapshots, device control, etc.)
while GDB is connected, add a monitor channel:

```bash
qemu-system-x86_64 -accel tcg -s -S \
    -monitor telnet:localhost:4444,server,nowait \
    -kernel bzImage -nographic
```

Then connect in another terminal:

```bash
telnet localhost 4444
```

Useful monitor commands:

```
(qemu) info registers    # CPU register dump
(qemu) info mem          # Page table info
(qemu) info mtree        # Memory region tree
(qemu) xp /16x 0x1000   # Examine physical memory
(qemu) gdbserver         # Control GDB server at runtime
```

---

## Quick Reference

```bash
# Launch QEMU (frozen, waiting for GDB on port 1234)
qemu-system-x86_64 -accel tcg -s -S -kernel bzImage \
    -initrd initramfs.img -append "nokaslr console=ttyS0" \
    -nographic -m 1G

# Connect GDB
gdb vmlinux -ex "target remote localhost:1234" \
    -ex "break start_kernel" -ex "continue"
```

```gdb
# Essential GDB commands
target remote localhost:1234   # Connect to QEMU
break start_kernel             # Set breakpoint
continue                       # Start/resume execution
info registers                 # CPU registers
x/20i $rip                     # Disassemble at PC
x/16gx $rsp                    # Examine stack
stepi                          # Step one instruction
step / next                    # Step source line
backtrace                      # Stack trace
print some_variable            # Inspect kernel data
watch *(int *)0xaddr           # Watchpoint
```
