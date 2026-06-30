#!/usr/bin/env bash
# Objective 1: dump guest CPU registers (rip/cr3 present).
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check regs
