#!/usr/bin/env bash
# Objective 2/3: read guest virtual memory and cross-check gva->gpa via pmem.
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check vmem
