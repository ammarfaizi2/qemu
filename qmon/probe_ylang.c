/*
 * probe_ylang.c - definitions of the qmon ylang probe targets.
 *
 * Each function here is an intentionally opaque no-op that lives in its own
 * translation unit so the compiler cannot inline it into qmon.c or optimise
 * away the caller's struct fill.  The plugin calls them with a fully populated
 * snapshot of the guest state; a ylang script uprobes them by name and reads
 * the argument struct out of the qemu process (see probe_ylang.h).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "probe_ylang.h"

/*
 * The asm barrier keeps `cpu` live and the body non-empty, so with
 * __noinline__ the symbol survives and the argument is materialised in memory
 * for the uprobe to read.  It performs no work of its own.
 */
QMON_YLANG_PROBE __attribute__((__noinline__))
void qemu_ylang_cpu_reg_dump(struct qemu_cpu_state *cpu)
{
    __asm__ volatile("" : : "r"(cpu) : "memory");
}
