#!/usr/bin/env bash
# Smoke test: the plugin answers on its socket.
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check ping
