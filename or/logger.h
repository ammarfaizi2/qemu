#ifndef OR_LOGGER_H
#define OR_LOGGER_H

#include <stdarg.h>

/*
 * or_log() behaves like printf(), but writes its output to a log file
 * instead of standard output.
 *
 * The log file is taken from the OR_LOG_FILE environment variable. If
 * that variable is not set, or_log() is a no-op.
 *
 * The log file is opened lazily on the first call and kept open for the
 * remainder of the program's lifetime. Access is serialized with a
 * mutex, so or_log() is safe to call from multiple threads.
 */
void or_log(const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#endif /* OR_LOGGER_H */
