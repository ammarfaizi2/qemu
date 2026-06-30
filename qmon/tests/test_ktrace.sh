#!/usr/bin/env bash
# Kernel call-trace + current context: break in hrtimer_nanosleep, check the
# symbolized backtrace reaches do_syscall_64 and the current task is qmon_target.
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check ktrace
