
struct qemu_backtrace {
	unsigned int nr_frames;
	uintptr_t *frames;
	char **symbols;
};

struct qemu_mem_dump {
	unsigned long size;
	unsigned char *data;
};

struct qemu_watchpoint {
	uintptr_t addr;
	unsigned long size;
	uint64_t hit_count;
};

/*
 * Guest CPU state handed to the ylang cpu_reg_dump probe.
 *
 * The layout is deliberately FLAT with only named scalar fields: ylang's stap+
 * backend reads struct members by name but does not handle arrays or nested
 * structs in tracer land, so every register is a top-level uint64_t.  Registers
 * the QEMU gdb set does not expose (the APX eGPRs r16-r31) are always zero.
 *
 * This file must stay byte-identical to ylang/qmon_ylang.y so the C producer
 * (probe_ylang.c / qmon.c) and the ylang consumer agree on the layout.
 */
struct qemu_cpu_state {
	unsigned int cpu_index;

	uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

	/*
	 * Starting Nova Lake and Diamond Rapids, Intel adds 16 more extra
	 * general-purpose registers (r16-r31).
	 */
	uint64_t r16, r17, r18, r19, r20, r21, r22, r23;
	uint64_t r24, r25, r26, r27, r28, r29, r30, r31;

	uint64_t rip;
	uint64_t eflags;

	/* segment selectors */
	uint64_t es, cs, ss, ds, fs, gs;

	/* control registers */
	uint64_t cr0, cr2, cr3, cr4, cr8;
};
