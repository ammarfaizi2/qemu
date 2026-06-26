# QEMU TCG Internals (x86-64 guest focus)

This document explains how QEMU's **TCG** (Tiny Code Generator) — QEMU's portable
dynamic binary translator — executes a guest, how it translates guest memory to
host memory, and how many guest instructions the x86 target understands.

The focus throughout is the **x86-64 guest** (`target/i386`). All file paths are
relative to the repository root, and line numbers refer to the tree this document
was written against (QEMU v11.0.0-rc2). Function names are stable across releases;
exact line numbers may drift by a few lines over time.

TCG runs in two modes:

* **System emulation** (`CONFIG_USER_ONLY` *not* defined, a.k.a. "softmmu"):
  emulates the full machine, including the guest MMU, page tables and devices.
* **User-mode emulation** (`linux-user/`, `CONFIG_USER_ONLY` defined): runs a single
  guest Linux process; guest virtual addresses map directly into the host process.

Both modes share the same translation engine; they differ mainly in how memory is
resolved (see §2).

---

## Table of contents

1. [How guest CPU instructions are executed](#1-how-guest-cpu-instructions-are-executed)
2. [How guest memory is translated to the host](#2-how-guest-memory-is-translated-to-the-host)
3. [How many instructions are there](#3-how-many-instructions-are-there)

---

## 1. How guest CPU instructions are executed

QEMU does **not** interpret guest instructions one at a time. Instead it works like
a JIT compiler: it translates a *basic block* of guest code (a **Translation Block**,
or **TB**) into native host instructions once, caches the result, and re-executes
the cached host code on every subsequent visit. Translation happens in two stages:

```
guest x86-64 bytes  --frontend-->  TCG IR ops  --backend-->  native host (x86-64) code
   (target/i386)                  (architecture-neutral)         (tcg/<host-arch>)
```

### 1.1 The execution loop

Entry point: **`cpu_exec()`** — `accel/tcg/cpu-exec.c:1019`.

It sets up clocks/RCU and calls into the inner loop via `cpu_exec_setjmp()`, which
runs **`cpu_exec_loop()`** — `accel/tcg/cpu-exec.c:933`. The core of that loop is:

```c
while (!cpu_handle_exception(cpu, &ret)) {
    TranslationBlock *last_tb = NULL;
    int tb_exit = 0;
    while (!cpu_handle_interrupt(cpu, &last_tb)) {
        TCGTBCPUState s = cpu->cc->tcg_ops->get_tb_cpu_state(cpu);
        s.cflags = cpu->cflags_next_tb;

        tb = tb_lookup(cpu, s);            /* find cached TB ...        */
        if (tb == NULL) {
            tb = tb_gen_code(cpu, s);      /* ... or translate one now  */
        }
        tb_add_jump(last_tb, tb_exit, tb); /* chain previous TB -> this */
        cpu_loop_exec_tb(cpu, tb, s.pc, &last_tb, &tb_exit); /* run it  */
    }
}
```

Each iteration: **look up** the TB for the current guest PC, **translate** it if
missing, **chain** it to the previously executed TB, then **execute** it.

The "CPU state" key (`s`) bundles the guest PC, the segment base (`cs_base`), and
the `flags` that capture the current execution mode (CPL, operand/address size,
long-mode, etc.) — for x86 these are produced by the target's `get_tb_cpu_state`
hook. A TB is only valid for one exact combination of these, which is why mode
switches force fresh translations.

### 1.2 Looking up a cached TB

**`tb_lookup()`** — `accel/tcg/cpu-exec.c:227` — uses a two-level cache:

* **L1: per-CPU jump cache** (`cpu->tb_jmp_cache`), a direct-mapped array of
  `TB_JMP_CACHE_SIZE = 1 << 12` = 4096 entries indexed by a hash of the guest PC.
  Defined in `accel/tcg/tb-jmp-cache.h` (`CPUJumpCache`, ~line 25). This is the
  fast path — one hash, one comparison.
* **L2: global hash table** `tb_ctx.htable`, a lock-free QHT keyed by the full
  `(phys_pc, pc, flags, cs_base, cflags)` tuple. Looked up by
  `tb_htable_lookup()` (`accel/tcg/cpu-exec.c:195`); the hash is computed by
  `tb_hash_func()` in `accel/tcg/tb-hash.h` (xxhash over the key).

On an L1 miss but L2 hit, the L1 entry is refilled. On a full miss, `tb_lookup`
returns `NULL` and the loop translates a new block.

### 1.3 Translating a block (frontend → IR → host code)

**`tb_gen_code()`** — `accel/tcg/translate-all.c:261` — orchestrates translation:
it allocates a TB and a slot in the host code buffer, runs the translation under a
`sigsetjmp` guard, encodes unwind/search metadata, and links the finished TB into
the hash table.

The actual codegen happens in **`setjmp_gen_code()`** —
`accel/tcg/translate-all.c:238`, called at `translate-all.c:325`:

```c
tcg_func_start(tcg_ctx);
...
cs->cc->tcg_ops->translate_code(cs, tb, max_insns, pc, host_pc); /* FRONTEND */
...
return tcg_gen_code(tcg_ctx, tb, pc);                            /* BACKEND  */
```

**Stage A — Frontend (guest → TCG IR).**
For x86 the `translate_code` hook is **`x86_translate_code()`** —
`target/i386/tcg/translate.c:3613`, which simply drives the generic
**`translator_loop()`** — `accel/tcg/translator.c:122` — with the x86 operation
table `i386_tr_ops` (`target/i386/tcg/translate.c:3605`):

```c
void x86_translate_code(CPUState *cpu, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext dc;
    translator_loop(cpu, tb, max_insns, pc, host_pc, &i386_tr_ops, &dc.base);
}
```

`translator_loop()` is the architecture-neutral skeleton. It calls a small set of
target callbacks (`TranslatorOps`, declared in `include/exec/translator.h`):

| Callback | x86 implementation | Role |
|----------|-------------------|------|
| `init_disas_context` | `i386_tr_init_disas_context` | seed `DisasContext` from TB flags (CPL, sizes, mode) |
| `insn_start` | `i386_tr_insn_start` | emit `insn_start` IR op, record guest PC for unwinding |
| `translate_insn` | `i386_tr_translate_insn` (`translate.c:3507`) | **decode + emit IR for one guest instruction** |
| `tb_stop` | `i386_tr_tb_stop` | emit the block-exit / branch code |

The loop calls `translate_insn` repeatedly until the block ends (a branch, a mode
change, the TCG op buffer filling up, or hitting `max_insns`). For x86,
`i386_tr_translate_insn` (under a `sigsetjmp` so a faulting fetch can be turned into
a guest exception) calls **`disas_insn()`** at `target/i386/tcg/translate.c:3527`.

`disas_insn` (the table-driven decoder, **`decode-new.c.inc:2774`**) reads the
opcode bytes (prefixes, REX/VEX, ModRM, SIB, immediates), decodes the instruction
into an `X86DecodedInsn`, and calls the matching `gen_*` *emitter* (in
`target/i386/tcg/emit.c.inc`) which appends TCG IR ops — not host instructions yet.
See §3 for the decoder in detail.

**Stage B — Backend (TCG IR → host code).**
**`tcg_gen_code()`** — `tcg/tcg.c:6556` — turns the IR op stream into native host
machine code. Its passes:

1. `tcg_optimize()` — constant folding / strength reduction on the IR.
2. Liveness analysis (`liveness_pass_1`, optionally `_2` for indirect temps).
3. Register allocation + emission: it walks every `TCGOp`
   (`QTAILQ_FOREACH(op, &s->ops, link)`), emitting host instructions via the
   host backend in `tcg/<host-arch>/` (e.g. `tcg/i386/tcg-target.c.inc` for an
   x86-64 host). Special ops (`insn_start`, `goto_tb`, `exit_tb`, `br`) are handled
   directly; everything else goes through `tcg_reg_alloc_op()`.
4. Relocation/constant-pool finalization and an instruction-cache flush
   (`flush_idcache_range()`).

The emitted host code is written into the TB's code buffer (`tb->tc.ptr`).

### 1.4 Executing the host code

**`cpu_tb_exec()`** — `accel/tcg/cpu-exec.c:428` — runs the translated block:

```c
ret = tcg_qemu_tb_exec(cpu_env(cpu), tb_ptr);  /* jump into native code */
last_tb = tcg_splitwx_to_rw((void *)(ret & ~TB_EXIT_MASK));
*tb_exit = ret & TB_EXIT_MASK;
```

`tcg_qemu_tb_exec` is the TCG **prologue/epilogue** — a small piece of native code
that loads guest CPU state into host registers, jumps to `tb_ptr`, and on return
hands back the address of the last TB plus an exit code. The guest CPU register
file lives in `CPUArchState` (for x86, `CPUX86State` — `env`), and the generated
code reads/writes guest registers as offsets from the `env` pointer.

### 1.5 Block chaining (why it's fast)

Re-entering `cpu_exec_loop` for every block would be expensive. Instead, when one
TB falls through or jumps to another, **`tb_add_jump()`**
(`accel/tcg/cpu-exec.c:616`) *patches* the first TB's exit so the host code jumps
**directly** into the next TB's host code, bypassing the dispatch loop entirely:

```c
tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc.ptr); /* overwrite the jump */
```

Chained TBs form a linked list (`jmp_list_head` / `jmp_list_next`) so the chain can
be unpicked when a TB is invalidated. The result: hot loops execute almost entirely
in cached, directly-chained native code, returning to `cpu_exec()` only for
interrupts, exceptions, or invalidated blocks.

TB invalidation (e.g. self-modifying code, or the guest unmapping a page) is handled
in `accel/tcg/tb-maint.c` — `tb_link_page()` (`tb-maint.c:992`) inserts a TB and
records which guest pages it covers; writes to those pages trigger invalidation.

### 1.6 End-to-end flow

```
cpu_exec()                                  cpu-exec.c:1019
└─ cpu_exec_loop()                          cpu-exec.c:933
   ├─ tb_lookup()                           cpu-exec.c:227   (L1 jmp cache → L2 QHT)
   │   └─ (miss) tb_gen_code()              translate-all.c:261
   │       └─ setjmp_gen_code()             translate-all.c:238
   │           ├─ x86_translate_code()      i386/tcg/translate.c:3613   [FRONTEND]
   │           │   └─ translator_loop()     translator.c:122
   │           │       └─ i386_tr_translate_insn() → disas_insn()  decode-new.c.inc:2774
   │           │                              └─ gen_*() emitters    emit.c.inc
   │           └─ tcg_gen_code()            tcg/tcg.c:6556              [BACKEND]
   ├─ tb_add_jump()                         cpu-exec.c:616   (patch direct chain)
   └─ cpu_loop_exec_tb() → cpu_tb_exec()    cpu-exec.c:428
       └─ tcg_qemu_tb_exec()                run native host code
```

---

## 2. How guest memory is translated to the host

There are **two** address translations to keep separate:

* **Guest virtual → guest physical** — emulating the *guest* MMU (x86 page tables,
  CR3, 4-/5-level paging). Only in system emulation.
* **Guest physical → host virtual** — mapping the guest's RAM/devices onto memory
  inside the QEMU host process (RAMBlocks, MemoryRegions).

TCG accelerates the common case with a **software TLB** ("softmmu") so that most
guest loads/stores never walk page tables.

### 2.1 The software TLB (softmmu)

Every guest memory access generated by TCG first consults a per-CPU software TLB.
The TLB entry is **`CPUTLBEntry`** — `include/exec/tlb-common.h:25`:

```c
typedef union CPUTLBEntry {
    struct {
        uintptr_t addr_read;    /* comparator for loads          */
        uintptr_t addr_write;   /* comparator for stores         */
        uintptr_t addr_code;    /* comparator for code fetch     */
        uintptr_t addend;       /* host_addr = guest_vaddr + addend */
    };
    ...
} CPUTLBEntry;
```

The trick is `addend`: for a RAM page it is precomputed as
`host_page_pointer - guest_virtual_page_address`, so once a virtual address passes
the TLB tag check, the host address is a single add — `haddr = vaddr + addend`.

The TLB is indexed by a hash of the virtual page. **`tlb_index()`** —
`accel/tcg/cputlb.c:127`:

```c
return (addr >> TARGET_PAGE_BITS) & size_mask;   /* TARGET_PAGE_BITS = 12 (4 KiB) */
```

There is one TLB per MMU mode (`CPUTLB.f[NB_MMU_MODES]`, see
`include/hw/core/cpu.h`). Slow-path metadata that doesn't fit in the fast entry
(physical address, `MemoryRegionSection`, attributes, permissions, page size) lives
in the parallel **`CPUTLBEntryFull`** array (`include/hw/core/cpu.h:220`).

**Fast path.** The TCG backend *inlines* the TLB check directly into the generated
host code (no function call): compute the index, load the comparator
(`addr_read`/`addr_write`/`addr_code`), compare against the access address; on a
match, add `addend` and do the load/store inline. The IR-level memory ops are
`qemu_ld`/`qemu_st`, lowered per host in `tcg/<host>/tcg-target.c.inc`.

**Slow path (TLB miss).** The inline check falls through to a helper
(`helper_ldub_mmu`, `helper_stq_mmu`, … in `accel/tcg/ldst_common.c.inc`), which
calls `do_ld*/do_st*_mmu` → `mmu_lookup()` in `accel/tcg/cputlb.c`. If the page is
not resident, it calls **`tlb_fill_align()`** — `cputlb.c:1238` — which invokes the
target's `tlb_fill` to populate the entry (§2.2), then installs it via
**`tlb_set_page_full()`** — `cputlb.c:1024`.

### 2.2 Guest virtual → guest physical (x86 page-table walk)

When the softmmu TLB misses, QEMU asks the x86 target to walk the *guest's* page
tables. Entry point: **`x86_cpu_tlb_fill()`** —
`target/i386/tcg/system/excp_helper.c:613`:

```c
if (get_physical_address(env, addr, access_type, mmu_idx, &out, &err, retaddr)) {
    tlb_set_page_with_attrs(cs, addr & TARGET_PAGE_MASK,
                            out.paddr & TARGET_PAGE_MASK,
                            cpu_get_mem_attrs(env),
                            out.prot, mmu_idx, out.page_size);
    return true;             /* success: TLB entry installed */
}
/* else: raise #PF (page fault) into the guest */
```

* **`get_physical_address()`** — `excp_helper.c:546` — handles the mode dispatch:
  paging disabled (identity map), real mode, and nested paging. For x86-64 with
  paging on, it validates the address is **canonical** (correct sign-extension of
  the unused high bits) and calls `mmu_translate`.
* **`mmu_translate()`** — `excp_helper.c:142` — the actual page-table walker.
  Starting from **CR3**, it reads each level of the hierarchy, checking
  `PG_PRESENT_MASK`, permission bits (`PG_RW_MASK`, `PG_USER_MASK`, `PG_NX_MASK`),
  reserved bits, and large-page (`PG_PSE_MASK`) flags, and sets the
  accessed/dirty bits.

For 64-bit long mode the walk uses 9 bits of the virtual address per level:

```
4-level paging (48-bit VA):  CR3 → PML4[47:39] → PDPT[38:30] → PD[29:21] → PT[20:12] → page[11:0]
5-level paging (LA57, 57-bit VA) adds: PML5[56:48] on top
```

Large pages short-circuit the walk: a 1 GiB page stops at the PDPT level, a 2 MiB
page at the PD level, otherwise a 4 KiB page resolves at the PT level. The chosen
size is returned as `out.page_size` and recorded in the TLB so one entry can cover
a large page. `TARGET_VIRT_ADDR_SPACE_BITS` is 47 and `TARGET_PAGE_BITS` is 12 for
x86-64 (`target/i386/cpu-param.h`).

### 2.3 Guest physical → host virtual

`tlb_set_page_full()` must convert the guest *physical* address into a real host
pointer to compute `addend`. It calls **`address_space_translate_for_iotlb()`** —
`system/physmem.c:686` — which walks QEMU's memory map (`MemoryRegion` /
`MemoryRegionSection`, traversing any IOMMU layers) to find the region backing that
physical address. Then in `cputlb.c` (~line 1068):

```c
if (is_ram || is_romd) {
    /* RAM: addend points addend = host_base + (guest_paddr - region_offset) */
    addend = (uintptr_t)memory_region_get_ram_ptr(section->mr) + xlat;
} else {
    /* MMIO/device: no host RAM — force slow path on every access */
    addend = 0;
}
```

For RAM, the host pointer ultimately comes from a **`RAMBlock`** (host mmap'd
memory). `qemu_ram_ptr_length()` — `system/physmem.c:2720` — resolves
`(RAMBlock, offset)` to `block->host + offset`. For MMIO, `addend == 0` and the
matching TLB comparator carries `TLB_MMIO`, so accesses always trap to the slow
path and are dispatched to the device model instead of touching host RAM.

So the full chain for one guest load, on a cold TLB, is:

```
guest virtual addr
   │  x86 page-table walk (mmu_translate, CR3 → PML4/…/PT)   excp_helper.c:142
   ▼
guest physical addr
   │  memory-map / IOMMU lookup (address_space_translate_for_iotlb) physmem.c:686
   ▼
MemoryRegion + offset  →  RAMBlock host pointer (qemu_ram_ptr_length)  physmem.c:2720
   │  addend = host_ptr - guest_vaddr   (cached in CPUTLBEntry)        cputlb.c:1024
   ▼
host virtual addr      →  subsequent hits: haddr = vaddr + addend (inline, no walk)
```

### 2.4 User-mode emulation: no software TLB

In `linux-user` mode there is **no guest MMU** and no software TLB. The guest
address space is a single contiguous mapping inside the host process at a fixed
offset, `guest_base`. Translation is a plain add — **`g2h_untagged_vaddr()`** —
`include/user/guest-host.h:47`:

```c
static inline void *g2h_untagged_vaddr(vaddr x)
{
    return (void *)((uintptr_t)(x) + guest_base);  /* host = guest + guest_base */
}
```

with the inverse `h2g()` subtracting `guest_base` (`guest-host.h:71`). Guest page
permissions are tracked in a software page table (`page_get_flags`) and access
violations are delivered as guest signals. The split is selected at compile time in
`include/accel/tcg/cpu-ldst.h` via `CONFIG_USER_ONLY`.

---

## 3. How many instructions are there

"How many x86 instructions does QEMU's TCG frontend support?" has a few defensible
answers depending on what you count. The decoder lives in `target/i386/tcg/` and is
split into a modern table-driven decoder plus a legacy switch-based path.

### 3.1 The decoder structure

The current decoder is **table-driven**, in
`target/i386/tcg/decode-new.c.inc` (entry: `disas_insn()` at line 2774). Decoding
proceeds through opcode tables, one per opcode "map":

| Table | Location | Slots | Covers |
|-------|----------|-------|--------|
| `opcodes_root[256]` | `decode-new.c.inc:1698` | 256 | one-byte opcodes `00–FF` |
| `opcodes_0F[256]` | `decode-new.c.inc:1270` | 256 | two-byte `0F xx` (most SSE/MMX) |
| `opcodes_0F38_00toEF[240]` | `decode-new.c.inc:704` | 240 | three-byte `0F 38 xx` (SSSE3/SSE4/AVX/FMA/AES/SHA) |
| `opcodes_0F3A[256]` | `decode-new.c.inc:957` | 256 | three-byte `0F 3A xx` (immediate-form AVX etc.) |

Each populated slot is an `X86OpEntry` produced by `X86_OP_ENTRY*` macros, naming
the operation, its operand specifiers, and a CPUID feature gate. Sub-byte "groups"
(opcodes that select an operation via the ModRM `reg` field) are expanded by
dedicated decoders, e.g. `decode_group1` (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP),
`decode_group2` (the rotates/shifts ROL/ROR/RCL/RCR/SHL/SHR/SAR), `decode_group3`
(TEST/NOT/NEG/MUL/IMUL/DIV/IDIV), etc.

A **legacy decoder** still lives in `target/i386/tcg/translate.c`. It handles
opcodes not yet migrated to the new tables — primarily the **x87 FPU** opcodes
`D8–DF` and various **system/privileged** instructions (`0F 00`/`0F 01`/`0F C7`
groups: LGDT/LIDT/SGDT/SIDT/LMSW/INVLPG/SWAPGS/RDTSCP/XGETBV/MONITOR/MWAIT/…) and
MPX. Both decoders coexist in one build: `translate.c` `#include`s both
`emit.c.inc` (line 2151) and `decode-new.c.inc` (line 3347).

### 3.2 Counting by emitter functions

After decoding, each instruction is realized by a `gen_*` *emitter* in
`target/i386/tcg/emit.c.inc`. Counting these gives a concrete lower bound on
distinct operations handled by the new decoder:

```
$ grep -c '^static void gen_'                 target/i386/tcg/emit.c.inc   →  284
$ grep -oE '^static void gen_[A-Za-z0-9_]+' …  | sort -u | wc -l           →  260
```

So roughly **~260 distinct instruction emitters** in the table-driven path. Some
emitters are shared across many encodings (one `gen_*` serves several opcode-table
slots — e.g. the ALU and shift groups), so the number of *encodings* is larger than
the number of emitters.

### 3.3 Counting by mnemonics

Counting distinct instruction **mnemonics** referenced across the opcode tables
(via `X86_OP_ENTRY*`) plus the legacy x87/system instructions in `translate.c`
lands in the **~370–400** range. The exact figure depends on how you count
families: each of `Jcc`, `SETcc`, and `CMOVcc` is one emitter but 16 condition
encodings; SSE/AVX often pair a legacy form and a VEX form of "the same"
instruction.

### 3.4 Why there's no single number

The honest answer is a **range with a definition attached**:

| What you count | Approximate number | Where |
|----------------|--------------------|-------|
| Distinct `gen_*` emitters (new decoder) | **~260** | `emit.c.inc` |
| `static void gen_*` definitions incl. helpers | **284** | `emit.c.inc` |
| Distinct instruction mnemonics (new + legacy) | **~370–400** | opcode tables + `translate.c` |
| Opcode-table slots (encodings, incl. prefix variants) | **>700** | the four `opcodes_*` tables |

QEMU's x86 frontend targets essentially the full modern instruction set: the base
integer ISA, x87, MMX, the SSE family (SSE/SSE2/SSE3/SSSE3/SSE4.1/SSE4.2/SSE4A),
AVX/AVX2, FMA, BMI1/BMI2, ADX, AES-NI, PCLMULQDQ, SHA-NI, F16C, and the common
system instructions — gated at decode time by per-instruction **CPUID feature
flags** (`X86CPUIDFeature`, `decode-new.h:103`) so that a guest only sees the
instructions its configured CPU model advertises.

---

## Quick reference — key files

| Concern | File | Key symbols |
|---------|------|-------------|
| CPU dispatch loop | `accel/tcg/cpu-exec.c` | `cpu_exec` (1019), `cpu_exec_loop` (933), `tb_lookup` (227), `cpu_tb_exec` (428), `tb_add_jump` (616) |
| TB generation | `accel/tcg/translate-all.c` | `tb_gen_code` (261), `setjmp_gen_code` (238) |
| Translation skeleton | `accel/tcg/translator.c` | `translator_loop` (122) |
| TB cache/invalidation | `accel/tcg/tb-maint.c`, `tb-jmp-cache.h`, `tb-hash.h` | `tb_link_page` (992), `CPUJumpCache`, `tb_hash_func` |
| TCG backend (IR→host) | `tcg/tcg.c`, `tcg/<host>/tcg-target.c.inc` | `tcg_gen_code` (6556) |
| x86 frontend | `target/i386/tcg/translate.c` | `x86_translate_code` (3613), `i386_tr_ops` (3605), `disas_insn` call (3527) |
| x86 decoder | `target/i386/tcg/decode-new.c.inc`, `decode-new.h` | `disas_insn` (2774), `opcodes_root` (1698) |
| x86 emitters | `target/i386/tcg/emit.c.inc` | `gen_*` functions |
| Software TLB | `accel/tcg/cputlb.c`, `include/exec/tlb-common.h` | `CPUTLBEntry` (25), `tlb_index` (127), `tlb_set_page_full` (1024), `tlb_fill_align` (1238) |
| x86 page-table walk | `target/i386/tcg/system/excp_helper.c` | `x86_cpu_tlb_fill` (613), `get_physical_address` (546), `mmu_translate` (142) |
| Guest-phys → host | `system/physmem.c` | `address_space_translate_for_iotlb` (686), `qemu_ram_ptr_length` (2720) |
| User-mode mapping | `include/user/guest-host.h` | `g2h_untagged_vaddr` (47), `h2g` (71) |
| x86 address params | `target/i386/cpu-param.h` | `TARGET_PAGE_BITS` 12, `TARGET_VIRT_ADDR_SPACE_BITS` 47 |
