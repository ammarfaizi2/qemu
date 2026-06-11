#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "or/logger.h"

/*
 * State guarding the single, lazily-opened log file.
 *
 * - mutex serializes both the one-time initialization and every write,
 *   making or_log() thread-safe.
 * - initialized records whether we have already attempted to open the
 *   file, so we only try once.
 * - fp is the open log stream, or NULL when logging is disabled (either
 *   OR_LOG_FILE is unset or the file could not be opened).
 */
static QemuMutex or_log_mutex;
static bool or_log_initialized;
static FILE *or_log_fp;

static void or_log_mutex_init(void)
{
    static gsize init_once;

    if (g_once_init_enter(&init_once)) {
        qemu_mutex_init(&or_log_mutex);
        g_once_init_leave(&init_once, 1);
    }
}

/* Caller must hold or_log_mutex. */
static void or_log_open_locked(void)
{
    const char *path;

    if (or_log_initialized) {
        return;
    }
    or_log_initialized = true;

    path = getenv("OR_LOG_FILE");
    if (path == NULL || path[0] == '\0') {
        /* No log file requested: or_log() stays a no-op. */
        return;
    }

    or_log_fp = fopen(path, "a");
}

/* Flush and close the log file when the program terminates. */
static void __attribute__((destructor)) or_log_close(void)
{
    if (or_log_fp != NULL) {
        fclose(or_log_fp);
        or_log_fp = NULL;
    }
}

void or_log(const char *fmt, ...)
{
    va_list ap;

    or_log_mutex_init();

    qemu_mutex_lock(&or_log_mutex);

    or_log_open_locked();

    if (or_log_fp != NULL) {
        va_start(ap, fmt);
        vfprintf(or_log_fp, fmt, ap);
        va_end(ap);
        fflush(or_log_fp);
    }

    qemu_mutex_unlock(&or_log_mutex);
}

FILE *or_log_get_fp(void)
{
    or_log_open_locked();
    return or_log_fp;
}
