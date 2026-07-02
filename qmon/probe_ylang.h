/*
 * probe_ylang.h - ylang probe targets exported by the qmon plugin.
 *
 * These functions are deliberately opaque no-ops that the plugin *calls* from a
 * vCPU thread with the guest state already snapshotted into the shared structs
 * (see qmon_ylang.h).  An external ylang script places a uprobe on one of them
 * by name and reads the pointed-to struct out of the qemu process, e.g.:
 *
 *     #include "ylang/qmon_ylang.y"
 *     _probe qemu_ylang_cpu_reg_dump(struct qemu_cpu_state *cpu) {
 *         printf("rip=%#lx\n", cpu->regs.rip);
 *     }
 *
 * There is one probe target per qmon command; this is the ylang-facing analogue
 * of the unix-socket protocol in qmon.c.  The struct definitions come from
 * qmon_ylang.h, which MUST stay byte-identical to ylang/qmon_ylang.y so the C
 * producer and the ylang consumer agree on the memory layout.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef QMON_PROBE_YLANG_H
#define QMON_PROBE_YLANG_H

/*
 * qmon_ylang.h stays free of #includes so it can be byte-identical to the ylang
 * copy (ylang provides uintNN_t itself and cannot include C headers).  On the C
 * side we supply the fixed-width types it relies on here first.
 */
#include <stdint.h>

#include "qmon_ylang.h"

/*
 * Force default ELF visibility: qmon.so is built with -fvisibility=hidden, but
 * the probe targets must be resolvable by name from outside the process.
 */
#define QMON_YLANG_PROBE __attribute__((visibility("default")))

/* Objective 1 - dump guest CPU registers. */
QMON_YLANG_PROBE void qemu_ylang_cpu_reg_dump(struct qemu_cpu_state *cpu);

#endif /* QMON_PROBE_YLANG_H */
