# qmon — external introspection of a TCG QEMU guest, via a plugin

`qmon.so` is a QEMU **TCG plugin** that exposes a small unix-socket protocol so an
*external* program can inspect and control a running `qemu-system-x86_64` guest
**without ptrace and without freezing the whole VM**. It satisfies five objectives:

| # | Objective                                   | Request(s)                  |
|---|---------------------------------------------|-----------------------------|
| 1 | Dump guest CPU registers                    | `READ_REGS`                 |
| 2 | Dump guest virtual / physical memory        | `READ_VMEM` / `READ_PMEM`   |
| 3 | Translate gva→gpa and list mappings         | `XLATE` / `LIST_MAP`        |
| 4 | Watchpoint on a memory location (+ event)   | `SET_WATCH` → `EV_WATCH`    |
| 5 | Breakpoint on a %rip VA (+ freeze/inspect)  | `SET_BREAK` → `EV_BREAK`    |
| 6 | Symbolized kernel **call trace** + **current context** (ring / function / process) | `BACKTRACE` / `CONTEXT`; also folded into `EV_BREAK` |

It builds **out-of-tree** — it only needs the in-tree header `include/plugins/qemu-plugin.h`
and system glib; you do **not** need to (re)build QEMU.

## Build

```sh
# deps (Debian/Ubuntu):
sudo apt-get install -y libglib2.0-dev pkg-config

cd qmon
make                 # -> qmon.so
```

The plugin is loaded by a QEMU that was itself built with TCG plugins enabled
(`configure --enable-plugins`, i.e. meson `-Dplugins=true`). The in-tree build at
`/root/qemu/build/qemu-system-x86_64` already has this.

## Run

Launch QEMU in TCG mode with the plugin:

```sh
qemu-system-x86_64 -accel tcg \
    -plugin /path/to/qmon.so,sock=/tmp/qmon.sock \
    ... your normal VM options ...
```

Plugin arguments (`-plugin qmon.so,key=val,...`):

| arg       | default                   | meaning                                                     |
|-----------|---------------------------|-------------------------------------------------------------|
| `sock`    | `/tmp/qmon.sock`          | unix socket path the plugin listens on                      |
| `bp`      | `on`                      | instrument instructions for breakpoints (objective 5)       |
| `wp`      | `on`                      | instrument memory ops for watchpoints (objective 4)         |
| `ksyms`   | (none)                    | `System.map` or kallsyms file → symbolize call traces       |
| `slide`   | `0`                       | KASLR text slide (`runtime = linktime + slide`)             |
| `btf`     | `/sys/kernel/btf/vmlinux` | BTF for `task_struct` `comm`/`pid` offsets (current process)|
| `comm_off`/`pid_off` | (from BTF)     | override `task_struct` member offsets if BTF is unavailable  |

> For read-only introspection (objectives 1–3 only) launch with `bp=off,wp=off` to run
> at near-native TCG speed — there is then no per-instruction instrumentation.

Then talk to it from the host:

```sh
python3 client.py /tmp/qmon.sock ping
python3 client.py /tmp/qmon.sock regs 0
python3 client.py /tmp/qmon.sock xlate 0 0xffffffff81000000
python3 client.py /tmp/qmon.sock vmem  0 0xffffffff81000000 64
python3 client.py /tmp/qmon.sock maps  0
python3 client.py /tmp/qmon.sock break ksys_write    # by symbol (needs ksyms=)
python3 client.py /tmp/qmon.sock listen 30           # EV_BREAK w/ context + call trace
python3 client.py /tmp/qmon.sock cont  0             # resume the frozen vCPU
python3 client.py /tmp/qmon.sock watch 0x404010 8 w  # EV_WATCH on writes
python3 client.py /tmp/qmon.sock context 0           # ring / function / process
python3 client.py /tmp/qmon.sock backtrace 0         # symbolized call trace
python3 client.py /tmp/qmon.sock resolve do_syscall_64
python3 client.py /tmp/qmon.sock sym 0xffffffff81dd4c26
```

## Protocol (binary, length-prefixed)

Each message is `u32 len` (little-endian) followed by `len` payload bytes; `payload[0]`
is the type. Requests (client→plugin) and responses/events (plugin→client):

```
REQ_PING       0x01
REQ_READ_REGS  0x10  u32 vcpu
REQ_READ_VMEM  0x11  u32 vcpu, u64 addr, u32 len
REQ_READ_PMEM  0x12  u32 vcpu, u64 addr, u32 len
REQ_XLATE      0x13  u32 vcpu, u64 addr
REQ_LIST_MAP   0x14  u32 vcpu
REQ_CONTEXT    0x15  u32 vcpu
REQ_BACKTRACE  0x16  u32 vcpu, u32 max_frames
REQ_SET_BREAK  0x20  u64 addr
REQ_CLR_BREAK  0x21  u64 addr
REQ_SET_WATCH  0x22  u64 addr, u64 len, u8 rw   (1=R,2=W,3=RW)
REQ_CLR_WATCH  0x23  u64 addr
REQ_RESOLVE    0x24  cstring name                (-> u64 runtime addr)
REQ_SYM        0x25  u64 addr                    (-> sym)
REQ_CONTINUE   0x30  u32 vcpu                    (0xffffffff = all)

RSP_OK         0x80  <type-specific payload>
RSP_ERR        0x81  u32 code, cstring msg
EV_BREAK       0xA0  u32 vcpu, u64 rip, u64 bp_addr, <context>, <backtrace>
EV_WATCH       0xA1  u32 vcpu, u64 rip, u64 addr, u8 store, u8 size, u64 value
```

`READ_REGS` RSP_OK: `u32 nregs`, then per register `u8 namelen, name, u8 width, value[width]`
(value in target byte order). `LIST_MAP` RSP_OK: `u32 nranges`, then per range
`u64 gva, u64 gpa, u64 size, u32 flags` (flags: 1=P 2=W 4=U 8=NX 16=large).

Sub-encodings reused by several messages:

```
sym       = u8 namelen, name[namelen], u64 offset   (namelen 0 => unknown, raw addr)
context   = u8 ring, sym(rip), u32 pid, u8 commlen, comm[commlen]
backtrace = u32 nframes, nframes x { u64 addr, sym(addr) }
```

`CONTEXT` RSP_OK is a `context`; `BACKTRACE` RSP_OK is a `backtrace`; `EV_BREAK` carries
both inline so a hit is self-describing.

## How it works (and why no ptrace / no whole-VM freeze)

`qemu_plugin_read_register()`, `qemu_plugin_read_memory_vaddr()/_hwaddr()` and
`qemu_plugin_translate_vaddr()` are only valid on a **vCPU thread inside a callback**.
The socket I/O runs on its own thread, so it cannot touch guest state directly. Instead
it enqueues a command that a vCPU-thread callback executes:

- a per-TB **pump** (`tb_exec` cb) drains read requests at a TB boundary — so register/
  memory snapshots are *consistent*, not torn;
- **breakpoints** are per-instruction `insn_exec` callbacks compiled *into* each TB, so
  they fire even across chained TBs (unlike a uprobe on the dispatch loop); a hit emits
  `EV_BREAK` and freezes **only that vCPU** in a loop that still answers reads, until you
  send `CONTINUE`;
- **watchpoints** are `mem` callbacks that filter the access address; a hit emits
  `EV_WATCH` *after* the access (post-access semantics) and keeps running.

## Kernel call trace & "current context"

When `ksyms=` (a matching `System.map` or kallsyms file) is given, the plugin symbolizes
addresses and, at any stop, reports:

- **ring** — `cs & 3` (`ring0/kernel` vs `ring3/user`);
- **function** — the symbol the RIP is in (only addresses in `[_stext,_etext)` are named);
- **process** — the current task's `comm` + `pid`, read from the per-CPU `current_task`
  (`gs_base`/`kernel_gs_base + offset`) using `task_struct` offsets parsed from BTF;
- **call trace** — an exact **frame-pointer (RBP) chain** unwind, each return address
  symbolized, with a function-entry heuristic (`*rsp`) for the immediate caller.

This is built inside `EV_BREAK` (self-describing hits) and also available on demand via
`CONTEXT` / `BACKTRACE`. Example, breaking in the nanosleep path:

```
context : ring0/kernel in hrtimer_nanosleep+0x0 | qmon_target(pid 131)
  #0 hrtimer_nanosleep+0x0
  #1 __x64_sys_nanosleep+0xb0
  #2 x64_sys_call+0x1e96
  #3 do_syscall_64+0x56
  #4 entry_SYSCALL_64_after_hwframe+0x6c
```

Requirements/assumptions: the kernel is built with `CONFIG_FRAME_POINTER=y` (exact RBP
unwind; an ORC-only kernel would need a different unwinder). The `System.map`/BTF must
match the running kernel. For KASLR, either boot the guest with `nokaslr` (text slide 0,
what `verify.sh` does) or pass the correct `slide=`. The per-CPU `current_task` value and
the per-CPU base (`gs_base`) are not KASLR-text-slid, so the process readout works either
way once the right gs base is used.

## Verify on the bundled appliance

```sh
make verify          # builds qmon.so + a guest workload, boots 000_run, runs all 5 checks
```

`verify.sh` builds `target/qmon_target.c` (a freestanding, fixed-VA loop that bumps a
global and calls `marker()`), drops it into the appliance, boots `../000_run/start.sh`
with the plugin, then uses `client.py selftest` to exercise every objective and print
PASS/FAIL. Console/boot output is captured to `../000_run/qemu.log`.

## Caveats / limitations (v1)

- **Instrumentation overhead.** With `bp=on,wp=on` every instruction / memory op is
  instrumented, so the guest runs much slower (boots take longer). Use `bp=off,wp=off`
  for fast read-only work, or extend the plugin with selective instrumentation.
- **Breakpoint freeze.** A breakpoint hit blocks that vCPU until `CONTINUE`. If the client
  disconnects, all breakpoints/watchpoints are disarmed and frozen vCPUs are released.
- **Idle/halted guest.** Reads are serviced at a vCPU safe point; if the target vCPU is
  halted, a read returns a timeout error after ~2 s rather than hanging.
- **`LIST_MAP`** targets x86_64 long mode and needs `cr3` in the gdb register set; if it
  isn't exposed it returns a clear error.
- **Call trace** needs `CONFIG_FRAME_POINTER` and a matching `System.map`; on an ORC-only
  kernel the RBP unwind degrades (future work: ORC / heuristic scan). KASLR needs `nokaslr`
  or a correct `slide=` (auto-slide detection is future work).
- **One client** connection at a time. Multi-client and a richer client are future work.
