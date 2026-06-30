#!/usr/bin/env bash
# Objective 3: list guest virtual<->physical mappings (page-table walk).
source "$(cd "$(dirname "$0")" && pwd)/common.sh"
qmon_begin
run_check maps
