# QEMU TCG Internals (x86-64 guest focus)

This document explains how QEMU's **TCG** (Tiny Code Generator) — QEMU's portable
dynamic binary translator — runs an x86-64 guest. TCG works by *translating* short
runs of guest instructions into native host instructions, caching the result, and
jumping into the cached host code. There is no per-instruction interpreter loop in
the hot path: the guest effectively runs as host code that reads and writes a big
in-memory `struct` representing the virtual CPU.

All file paths are relative to the repository root. Line numbers refer to the
current tree and may drift slightly as the code evolves; function names are stable
anchors.

Throughout, keep three address spaces distinct:

- **Guest virtual** — what the emulated x86-64 program sees (RIP, pointers, etc.).
- **Guest physical** — what the emulated x86-64 MMU produces after a page-table walk.
- **Host virtual** — a real pointer in the QEMU process where that guest byte lives.

---

## 1. How are guest CPU instructions executed?

The execution model is **translate once, execute many**. A chunk of guest code
(a *Translation Block*, or **TB**) is decoded, lowered to TCG's intermediate
representation (IR), compiled to host machine code, and cached. Subsequent
executions jump straight into the cached host code.

### 1.1 The main execution loop

Entry point: [`cpu_exec()`](accel/tcg/cpu-exec.c#L1022) in
[accel/tcg/cpu-exec.c](accel/tcg/cpu-exec.c#L1022). It sets up clocks and an
RCU read-side critical section, then calls into
[`cpu_exec_loop()`](accel/tcg/cpu-exec.c#L936) (via a `sigsetjmp` wrapper so that
exceptions/interrupts can long-jump back to the top of the loop).

[`cpu_exec_loop()`](accel/tcg/cpu-exec.c#L936) is the heart of the interpreter
dispatch. Each iteration:

1. Handles any pending exception or interrupt.
2. Looks up the TB for the current guest PC with
   [`tb_lookup()`](accel/tcg/cpu-exec.c#L230).
3. Executes the TB's host code via `cpu_loop_exec_tb()` →
   [`cpu_tb_exec()`](accel/tcg/cpu-exec.c#L431).

### 1.2 Finding or building a Translation Block

[`tb_lookup()`](accel/tcg/cpu-exec.c#L230) first probes a fast per-CPU jump cache,
then a global hash table (`qht_lookup_custom`, see
[`tb_lookup_cmp()`](accel/tcg/cpu-exec.c#L161)). A TB is keyed on more than the PC:
it also depends on `cs_base` and the CPU's `flags` (operand size, CPL, paging mode,
etc.), because the same bytes can mean different things in 16/32/64-bit mode.

On a miss, [`tb_gen_code()`](accel/tcg/translate-all.c#L261) in
[accel/tcg/translate-all.c](accel/tcg/translate-all.c#L261) allocates a fresh
[`TranslationBlock`](include/exec/translation-block.h#L46) and drives translation.
The `TranslationBlock` struct records the guest `pc`, `cs_base`, `flags`, a pointer
to the generated host code (`tc`), and the *block-chaining* pointers
(`jmp_dest[]`, `jmp_list_*`) that let one TB jump directly to its successor without
returning to the dispatch loop.

### 1.3 The target-independent translator loop

Translation is split into a generic driver and target-specific callbacks. The
driver is [`translator_loop()`](accel/tcg/translator.c#L122) in
[accel/tcg/translator.c](accel/tcg/translator.c#L122). It walks instructions one at
a time, calling a vtable of callbacks of type
[`TranslatorOps`](include/exec/translator.h#L118):

```
ops->init_disas_context()   // set up per-block state
ops->tb_start()
loop:
  ops->insn_start()
  ops->translate_insn()     // decode ONE guest insn -> emit TCG IR
  (until block-ending condition)
ops->tb_stop()              // emit block exit / chaining
```

The loop stops at a branch, a page boundary, or after a cap on instructions, then
emits the code that returns control to the dispatcher.

### 1.4 x86-specific decoding

The x86 implementation of those callbacks lives in
[target/i386/tcg/translate.c](target/i386/tcg/translate.c). Key functions:

- [`i386_tr_init_disas_context()`](target/i386/tcg/translate.c#L3438) — builds the
  x86 [`DisasContext`](target/i386/tcg/translate.c#L85): operand/address size
  (`dflag`/`aflag`), REX bits, CPL, MMU index, and a **cached copy of the guest's
  CPUID feature words** (see §4).
- [`i386_tr_translate_insn()`](target/i386/tcg/translate.c#L3507) — decodes a single
  instruction, dispatching into
  [`disas_insn()`](target/i386/tcg/decode-new.c.inc#L2763) in the table-driven
  decoder [target/i386/tcg/decode-new.c.inc](target/i386/tcg/decode-new.c.inc).
- The `TranslatorOps` vtable for i386 is wired up around
  [translate.c:3606](target/i386/tcg/translate.c#L3606).

`disas_insn()` recognizes the opcode (handling legacy, VEX, and EVEX prefixes) and
emits **TCG IR ops** — a small, architecture-neutral RISC-like instruction set —
that describe the instruction's effect on the guest CPU state.

### 1.5 From TCG IR to host code, and running it

After the whole block is expressed as TCG IR, the backend compiler
[`tcg_gen_code()`](tcg/tcg.c#L6556) in [tcg/tcg.c](tcg/tcg.c) optimizes the IR, does
register allocation and liveness analysis, and emits **native host instructions**
through a per-host backend. For an x86-64 host that backend is
[tcg/i386/tcg-target.c.inc](tcg/i386/tcg-target.c.inc).

> Note the two independent x86 roles: the **guest** ISA decoder lives under
> `target/i386/`, while the **host** code emitter lives under `tcg/i386/`. Running
> an x86-64 guest on an x86-64 host uses both, but they are different subsystems.

Finally, [`cpu_tb_exec()`](accel/tcg/cpu-exec.c#L431) actually runs the generated
code by calling `tcg_qemu_tb_exec()` (declared in
[include/tcg/tcg.h](include/tcg/tcg.h#L937)). This is just a call into the host
code buffer with the guest-CPU pointer in a register. Its return value packs an
exit reason in the low bits together with the next TB pointer, which the dispatch
loop uses to decide what to do next.

**End-to-end call chain:**

```
cpu_exec()                       accel/tcg/cpu-exec.c:1022
 └ cpu_exec_loop()               accel/tcg/cpu-exec.c:936
    ├ tb_lookup()                accel/tcg/cpu-exec.c:230   (cache hit?)
    │  └ tb_gen_code()           accel/tcg/translate-all.c:261  (on miss)
    │     └ translator_loop()    accel/tcg/translator.c:122
    │        ├ i386_tr_translate_insn()  target/i386/tcg/translate.c:3507
    │        │  └ disas_insn()           target/i386/tcg/decode-new.c.inc:2763  -> emit TCG IR
    │        └ tcg_gen_code()    tcg/tcg.c:6556   -> emit host machine code
    └ cpu_tb_exec()              accel/tcg/cpu-exec.c:431
       └ tcg_qemu_tb_exec()      include/tcg/tcg.h:937   -> run native code
```

---

## 2. How are CPU registers stored in memory?

The emulated CPU is a plain C `struct` on the host heap. Generated host code does
not keep guest registers in host registers across instruction boundaries; instead
it **loads from and stores to fields of this struct**. (TCG *does* temporarily hold
values in host registers within a block, but the architectural state of record is
always the struct.)

### 2.1 The `CPUX86State` struct

Defined as `typedef struct CPUArchState { ... } CPUX86State;` at
[target/i386/cpu.h:1986](target/i386/cpu.h#L1986) (closing at
[cpu.h:2316](target/i386/cpu.h#L2316)). `CPUArchState` is the generic name; for the
i386 target it *is* `CPUX86State`. Highlights:

| Guest state | Field | Location |
|---|---|---|
| GPRs (RAX..R15) | `target_ulong regs[CPU_NB_EREGS]` | [cpu.h:1988](target/i386/cpu.h#L1988) |
| Instruction pointer | `target_ulong eip` | [cpu.h:1989](target/i386/cpu.h#L1989) |
| Flags | `target_ulong eflags` (+ lazy `cc_*`) | [cpu.h:1990](target/i386/cpu.h#L1990) |
| Lazy condition codes | `cc_dst`, `cc_src`, `cc_src2`, `cc_op` | [cpu.h:1995](target/i386/cpu.h#L1995) |
| Segment registers | `SegmentCache segs[6]` (CS,DS,ES,FS,GS,SS) | [cpu.h:2005](target/i386/cpu.h#L2005) |
| x87 stack | `FPReg fpregs[8]` | [cpu.h:2030](target/i386/cpu.h#L2030) |
| SSE/AVX/AVX-512 vectors | `ZMMReg xmm_regs[CPU_NB_EREGS]` | [cpu.h:2045](target/i386/cpu.h#L2045) |
| AVX-512 mask regs | `uint64_t opmask_regs[...]` | [cpu.h:2049](target/i386/cpu.h#L2049) |
| CPUID feature words | `FeatureWordArray features` | [cpu.h:2233](target/i386/cpu.h#L2233) |

Two design points worth calling out:

- **Lazy flags.** Rather than recompute EFLAGS after every arithmetic op, x86 TCG
  stores the *operands* (`cc_src`/`cc_dst`/`cc_src2`) and an opcode (`cc_op`)
  describing how to derive the flags on demand. EFLAGS is materialized only when
  actually read.

- **Vector register aliasing.** XMM/YMM/ZMM are the same physical storage at
  different widths. `ZMMReg` is a 512-bit union overlaying `XMMReg` (128-bit) and
  `YMMReg` (256-bit); the union/typedef chain is defined around
  [cpu.h:1647-1675](target/i386/cpu.h#L1647). So `xmm_regs[0]` is XMM0, YMM0, and
  ZMM0 simultaneously.

### 2.2 How the struct is reached at runtime

`CPUX86State` is embedded inside the per-CPU object `ArchCPU` (a.k.a. `X86CPU`),
defined at [target/i386/cpu.h:2329](target/i386/cpu.h#L2329), which begins with the
generic `CPUState parent_obj` followed by `CPUX86State env`. Helper accessors:

- [`cpu_env(cpu)`](include/hw/core/cpu.h#L597) returns `(CPUArchState *)(cpu + 1)` —
  i.e. `env` sits immediately after `CPUState`.
- [`env_cpu(env)`](include/exec/cpu-common.h#L110) and
  [`env_archcpu(env)`](include/exec/cpu-common.h#L88) go the other way.

Frequently-used, latency-sensitive state (notably the software TLB — see §3) is
placed in a `CPUNegativeOffsetState` *before* `env` so it is reachable at small
**negative** offsets from the `env` pointer, which keeps the generated code compact.

### 2.3 How generated code references registers

At init time, [`tcg_x86_init()`](target/i386/tcg/translate.c#L3349) creates TCG
"global" variables that are bound to fixed byte offsets inside `CPUX86State`:

```c
/* target/i386/tcg/translate.c  (excerpt) */
cpu_regs[i] = tcg_global_mem_new(tcg_env,
                                 offsetof(CPUX86State, regs[i]),
                                 reg_names[i]);   /* "rax", "rbx", ... */
```

`tcg_env` (declared `extern TCGv_env tcg_env;` in
[include/tcg/tcg.h:451](include/tcg/tcg.h#L451)) is the IR value that, at runtime,
holds the pointer to `CPUX86State` — it is effectively the first argument to every
generated block. The `cpu_regs[]` / `cpu_seg_base[]` / `cpu_eip` TCGv globals are
declared near [translate.c:77](target/i386/tcg/translate.c#L77).

So a guest `mov %rbx, %rax` becomes IR roughly equivalent to
`st_tl(cpu_regs[RBX], tcg_env, offsetof(CPUX86State, regs[RAX]))`, which the host
backend turns into a single host load/store relative to the `env` register. Helpers
[`gen_op_mov_v_reg()`](target/i386/tcg/translate.c#L454) and
[`gen_op_mov_reg_v()`](target/i386/tcg/translate.c#L448) wrap this pattern. Fields
without a dedicated global (e.g. `hflags`, `eflags`) are accessed by explicit
`tcg_gen_ld_tl/st_tl(..., offsetof(CPUX86State, field))`.

---

## 3. How is guest memory translated to host memory?

A guest memory access must traverse **guest-virtual → guest-physical → host-virtual**.
TCG splits this into a fast inline path (a software TLB lookup emitted directly into
the generated code) and a slow path (an x86 page-table walk plus a physical→host
resolution) that runs only on a TLB miss.

### 3.1 The software TLB (fast path)

Each CPU carries a [`CPUTLB`](include/hw/core/cpu.h#L327), reachable at a negative
offset from `env` (see §2.2). Its per-entry payload,
[`CPUTLBEntry`](include/exec/tlb-common.h#L25), holds:

- comparator words `addr_read` / `addr_write` / `addr_code` — the guest virtual page
  tag for each access type, and
- `addend` ([tlb-common.h:34](include/exec/tlb-common.h#L34)) — the value to *add* to
  a guest virtual address to obtain the **host** address, valid only for directly
  accessible RAM.

The TCG memory-access op generators in
[tcg/tcg-op-ldst.c](tcg/tcg-op-ldst.c) emit, for every guest load/store, inline host
code that: indexes the TLB by virtual page, compares against the entry's comparator,
and on a hit computes `host_ptr = guest_vaddr + addend` and performs the access — no
function call. This is why steady-state emulated memory access is cheap.

### 3.2 TLB miss → x86 page-table walk (slow path)

On a comparator mismatch, the generated code calls into
[accel/tcg/cputlb.c](accel/tcg/cputlb.c). The refill machinery
[`tlb_fill_align()`](accel/tcg/cputlb.c#L1238) invokes the target's
`tlb_fill` callback. For i386 that callback is registered in the
[`x86_tcg_ops`](target/i386/tcg/tcg-cpu.c#L160) table as
`.tlb_fill = x86_cpu_tlb_fill` ([tcg-cpu.c:180](target/i386/tcg/tcg-cpu.c#L180)).

[`x86_cpu_tlb_fill()`](target/i386/tcg/system/excp_helper.c#L613) (in
[target/i386/tcg/system/excp_helper.c](target/i386/tcg/system/excp_helper.c)) calls
[`get_physical_address()`](target/i386/tcg/system/excp_helper.c#L546), which selects
the paging mode from CR0/CR4/EFER and calls
[`mmu_translate()`](target/i386/tcg/system/excp_helper.c#L142). `mmu_translate()` is
the actual x86 page walker: starting from CR3 it descends the paging structures
(PML5E → PML4E → PDPTE → PDE → PTE for 5-level paging, with shortcuts for 1 GiB and
2 MiB large pages), checks Present/Writable/User/NX permissions, and produces the
guest **physical** address plus a protection mask. On a fault it raises #PF with the
faulting address in CR2.

### 3.3 Guest-physical → host-virtual, and TLB population

A successful walk yields a guest physical address, which must be resolved to a real
host pointer. That mapping is owned by the memory subsystem in
[system/physmem.c](system/physmem.c): `address_space_translate_*` walks the
`FlatView` of mapped regions to find the `MemoryRegionSection`, and
`qemu_ram_ptr_length()` / `qemu_map_ram_ptr()` convert a `RAMBlock` + offset into a
host pointer (`RAMBlock.host + offset`).

The result is written back into the TLB by
[`tlb_set_page_full()`](accel/tcg/cputlb.c#L1024). For ordinary RAM it computes
`addend = host_ram_pointer + xlat - guest_vaddr_page` so that the fast-path formula
`guest_vaddr + addend` lands on the correct host byte; for MMIO it sets `addend = 0`
and flags the entry so accesses are routed through the device-emulation
(`MemoryRegion` read/write) path instead of a raw pointer dereference. Slow-path
metadata (physical address, attributes, page size, protections) lives in
[`CPUTLBEntryFull`](include/hw/core/cpu.h#L214).

Once the entry is installed, control returns to the faulting instruction, which
re-runs the inline lookup — now a hit — and completes. Subsequent accesses to the
same page stay entirely on the fast path.

**Slow-path chain:**

```
(inline TLB miss in generated code)
 └ tlb_fill_align()              accel/tcg/cputlb.c:1238
    └ x86_cpu_tlb_fill()         target/i386/tcg/system/excp_helper.c:613
       └ get_physical_address()  target/i386/tcg/system/excp_helper.c:546
          └ mmu_translate()      target/i386/tcg/system/excp_helper.c:142   (walk page tables)
    └ tlb_set_page_full()        accel/tcg/cputlb.c:1024
       └ address_space_translate_* / qemu_ram_ptr_length()   system/physmem.c   (phys -> host)
```

> User-mode emulation (`qemu-x86_64` running a Linux binary) skips the page-table
> walk: there is no guest MMU, so guest-virtual maps to host-virtual through a fixed
> offset and the `tlb_fill` path resolves directly against the process address space.

---

## 4. How are CPU features handled (SSE, AVX, AVX2, AVX-512, APX, …)?

CPU features have two jobs in QEMU: (a) tell the guest what exists, via CPUID, and
(b) gate the decoder so that an instruction the configured CPU doesn't support
raises #UD instead of executing.

### 4.1 Feature words and bit definitions

Features are grouped into **feature words**, each corresponding to one CPUID
leaf/register. The [`enum FeatureWord`](target/i386/cpu.h#L681) lists them
(`FEAT_1_EDX`, `FEAT_1_ECX`, `FEAT_7_0_EBX`, `FEAT_7_1_EDX`, …), and the
[`feature_word_info[]`](target/i386/cpu.c#L1046) table in
[target/i386/cpu.c](target/i386/cpu.c) ties each word to its CPUID leaf, register,
and the human-readable name of every bit.

The individual bit macros are in [target/i386/cpu.h](target/i386/cpu.h):

| Feature | Macro | Word | Line |
|---|---|---|---|
| SSE / SSE2 | `CPUID_SSE`, `CPUID_SSE2` | FEAT_1_EDX | [762](target/i386/cpu.h#L762) |
| SSE3/SSSE3/SSE4.1/SSE4.2 | `CPUID_EXT_SSE3` … `CPUID_EXT_SSE42` | FEAT_1_ECX | [773](target/i386/cpu.h#L773) |
| AVX | `CPUID_EXT_AVX` | FEAT_1_ECX | [803](target/i386/cpu.h#L803) |
| AVX2 | `CPUID_7_0_EBX_AVX2` | FEAT_7_0_EBX | [899](target/i386/cpu.h#L899) |
| AVX-512F | `CPUID_7_0_EBX_AVX512F` | FEAT_7_0_EBX | [917](target/i386/cpu.h#L917) |
| AVX-512 DQ/BW/VL | `CPUID_7_0_EBX_AVX512{DQ,BW,VL}` | FEAT_7_0_EBX | [919](target/i386/cpu.h#L919) |
| AVX-512 FP16 | `CPUID_7_0_EDX_AVX512_FP16` | FEAT_7_0_EDX | [1013](target/i386/cpu.h#L1013) |
| APX Foundation | `CPUID_7_1_EDX_APXF` | FEAT_7_1_EDX | [1082](target/i386/cpu.h#L1082) |

### 4.2 Per-CPU feature storage

Each CPU's enabled feature set lives in the `features` array inside `CPUX86State`
([cpu.h:2233](target/i386/cpu.h#L2233)), typed
`FeatureWordArray` (`uint64_t[FEATURE_WORDS]`). A check is simply
`env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_AVX2`. Companion arrays track
`user_features` (explicit `+feat`/`-feat` requests) and `filtered_features`
(requested but unavailable on this host/accelerator).

### 4.3 Reporting features to the guest (CPUID)

When the guest executes `CPUID`, the decoder calls a helper that lands in
[`cpu_x86_cpuid()`](target/i386/cpu.c#L8603). It composes each leaf from
`env->features[]`: leaf 1 returns `FEAT_1_ECX`/`FEAT_1_EDX` (SSE/AVX), leaf 7
subleaf 0 returns `FEAT_7_0_EBX/ECX/EDX` (AVX2, AVX-512), leaf 7 subleaf 1 returns
`FEAT_7_1_EAX/EDX` (AVX-VNNI, APX), and so on. Dependent leaves are gated — e.g. the
APX leaf `0x29` is only populated when `CPUID_7_1_EDX_APXF` is set.

### 4.4 Gating the decoder

At the start of each block, [`i386_tr_init_disas_context()`](target/i386/tcg/translate.c#L3438)
caches the relevant feature words into the `DisasContext` (fields
`cpuid_features`, `cpuid_ext_features`, `cpuid_7_0_ebx_features`, …, populated around
[translate.c:3472](target/i386/tcg/translate.c#L3472)). Caching avoids chasing the
`env` pointer for every instruction.

The table-driven decoder then checks these bits before emitting code. The central
predicate is [`has_cpuid_feature()`](target/i386/tcg/decode-new.c.inc#L2510) in
[target/i386/tcg/decode-new.c.inc](target/i386/tcg/decode-new.c.inc), e.g.:

```c
case X86_FEAT_AVX:    return s->cpuid_ext_features    & CPUID_EXT_AVX;
case X86_FEAT_AVX2:   return s->cpuid_7_0_ebx_features & CPUID_7_0_EBX_AVX2;  /* :2574 */
```

Each decoded entry names the feature it requires; the common dispatch path checks it
at [decode-new.c.inc:2952](target/i386/tcg/decode-new.c.inc#L2952)
(`if (!has_cpuid_feature(s, decode.e.cpuid)) goto illegal;`), and specific cases add
extra constraints — for instance a 256-bit VEX form requires AVX2
([decode-new.c.inc:2625](target/i386/tcg/decode-new.c.inc#L2625)). A failed check
emits a #UD (illegal-opcode) exception into the guest rather than the instruction's
semantics. Thus the *same* host build of QEMU will run or refuse AVX-512 purely based
on the configured guest CPU model.

### 4.5 Where feature sets come from: CPU models and filtering

Named guest CPUs (`-cpu Skylake-Server`, `Granite-Rapids`, etc.) are defined in the
[`builtin_x86_defs[]`](target/i386/cpu.c#L3542) table, each enumerating its
`.features[FEAT_*]` bits. `-cpu max` (and KVM's `-cpu host`) instead turns on
everything the accelerator can support, handled by the `max` CPU class around
[cpu.c:7355](target/i386/cpu.c#L7355).

During realize, [`x86_cpu_expand_features()`](target/i386/cpu.c#L9689) applies the
`feature_dependencies[]` graph (auto-enabling implied features — e.g. enabling APXF
pulls in the `FEAT_29_0_EBX` APX sub-features), and
[`x86_cpu_filter_features()`](target/i386/cpu.c#L9888) removes any bit the current
accelerator can't actually emulate, recording it in `filtered_features` so the user
gets a warning. The net result is the `env->features[]` array that both CPUID
reporting (§4.3) and decoder gating (§4.4) read.

### 4.6 A note on APX

As of this tree, **APX** (Advanced Performance Extensions: the REX2 prefix, EVEX-promoted
GPR forms, R16–R31) is **defined and plumbed but not yet executed under TCG**. The
`CPUID_7_1_EDX_APXF` bit, the `0x29` CPUID leaf, XSAVE/migration state, and GDB stub
register exposure all exist, but `decode-new.c.inc` does not yet decode the APX
instruction forms — a guest issuing them under TCG will take #UD. Contrast this with
SSE/AVX/AVX2/AVX-512, which are fully decoded and emulated. (Support is evolving;
re-check `decode-new.c.inc` for REX2/EVEX-APX handling against the current tree.)

---

## Quick file map

| Concern | Primary files |
|---|---|
| Execution loop & TB cache | [accel/tcg/cpu-exec.c](accel/tcg/cpu-exec.c), [accel/tcg/translate-all.c](accel/tcg/translate-all.c) |
| Generic translator driver | [accel/tcg/translator.c](accel/tcg/translator.c), [include/exec/translator.h](include/exec/translator.h) |
| x86 guest decoder | [target/i386/tcg/translate.c](target/i386/tcg/translate.c), [target/i386/tcg/decode-new.c.inc](target/i386/tcg/decode-new.c.inc) |
| TCG IR → host code | [tcg/tcg.c](tcg/tcg.c), [tcg/tcg-op.c](tcg/tcg-op.c), host backend [tcg/i386/tcg-target.c.inc](tcg/i386/tcg-target.c.inc) |
| Guest CPU state | [target/i386/cpu.h](target/i386/cpu.h) (`CPUX86State`) |
| Software TLB / mem access | [accel/tcg/cputlb.c](accel/tcg/cputlb.c), [tcg/tcg-op-ldst.c](tcg/tcg-op-ldst.c), [include/exec/tlb-common.h](include/exec/tlb-common.h) |
| x86 page-table walk | [target/i386/tcg/system/excp_helper.c](target/i386/tcg/system/excp_helper.c) |
| Guest-phys → host | [system/physmem.c](system/physmem.c) |
| CPU features / CPUID | [target/i386/cpu.c](target/i386/cpu.c), [target/i386/cpu.h](target/i386/cpu.h) |
