/*
 * qmon_target - a tiny, deterministic guest workload for verifying qmon.so.
 *
 * Built freestanding (-static -no-pie -nostartfiles) so that the addresses of
 * marker() and g_counter are FIXED and can be discovered on the host with
 *   nm qmon_target
 * The host can then set a breakpoint on marker() (objective 5) and a watchpoint
 * on g_counter (objective 4) at exact guest virtual addresses.
 *
 * _start loops forever: bump g_counter (a store -> watchpoint), call marker()
 * (an instruction at a known VA -> breakpoint), then nanosleep ~100 ms so the
 * events fire at a human rate and instrumentation overhead stays low.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Global in .data/.bss; stores to it drive the watchpoint test. */
volatile unsigned long g_counter = 0;

/* A named function at a fixed VA; executing it drives the breakpoint test. */
__attribute__((noinline))
void marker(void)
{
    __asm__ volatile ("nop" ::: "memory");
}

/* raw nanosleep(2) (syscall 60-ish: __NR_nanosleep == 35 on x86_64) */
static void sleep_ms(long ms)
{
    struct timespec_ { long tv_sec; long tv_nsec; } ts =
        { ms / 1000, (ms % 1000) * 1000000L };
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(35L), "D"(&ts), "S"(0L)
        : "rcx", "r11", "memory");
    (void)ret;
}

__attribute__((noreturn))
void _start(void)
{
    for (;;) {
        g_counter++;
        marker();
        sleep_ms(100);
    }
}
