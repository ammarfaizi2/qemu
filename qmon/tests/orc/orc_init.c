/*
 * orc_init - PID 1 for the ORC test kernel's initramfs.
 * Static/-no-pie so marker() and g_counter have fixed VAs (like qmon_target).
 * Prints a boot banner, then loops: bump g_counter, call marker(), nanosleep
 * ~100ms (a kernel syscall path to unwind with ORC).
 *
 * build: gcc -static -no-pie -nostartfiles -O2 -fno-stack-protector -o qmon_target orc_init.c
 */
volatile unsigned long g_counter = 0;

__attribute__((noinline))
void marker(void)
{
    __asm__ volatile ("nop" ::: "memory");
}

static long sys_write(int fd, const void *buf, unsigned long n)
{
    long r;
    __asm__ volatile ("syscall" : "=a"(r)
                      : "a"(1L), "D"(fd), "S"(buf), "d"(n)
                      : "rcx", "r11", "memory");
    return r;
}

static void sleep_ms(long ms)
{
    struct { long tv_sec; long tv_nsec; } ts = { ms / 1000, (ms % 1000) * 1000000L };
    long r;
    __asm__ volatile ("syscall" : "=a"(r)
                      : "a"(35L), "D"(&ts), "S"(0L)
                      : "rcx", "r11", "memory");
    (void)r;
}

__attribute__((noreturn))
void _start(void)
{
    static const char banner[] = "QMON-ORC-INIT: booted, looping\n";
    sys_write(1, banner, sizeof(banner) - 1);
    for (;;) {
        g_counter++;
        marker();
        sleep_ms(100);
    }
}
