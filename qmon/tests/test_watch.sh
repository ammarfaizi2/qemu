#!/usr/bin/env bash
# Objective 4: watchpoint on g_counter; observe write events with values.
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check watch "$COUNTER"
