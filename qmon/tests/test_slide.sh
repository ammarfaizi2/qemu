#!/usr/bin/env bash
# KASLR: the plugin auto-detects the kernel text slide (no nokaslr needed).
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check slide
