#!/usr/bin/env bash
# Objective 5: breakpoint on marker(); freeze, inspect regs, resume, re-arm.
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check break "$MARKER"
