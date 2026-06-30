#!/usr/bin/env bash
# Boot ONE guest and run every per-test script against it (fast).  This is what
# `make test` invokes.  Each test connects independently; the plugin disarms
# breakpoints/watchpoints on disconnect, so tests stay isolated.
source "$(cd "$(dirname "$0")" && pwd)/common.sh"

qmon_build
qmon_symbols
qmon_repack
qmon_boot
trap qmon_teardown EXIT
export QMON_SOCK="$SOCK"      # tell child test scripts to reuse this guest

fails=0
for name in ping regs slide vmem maps watch break ktrace; do
    echo "===== test_$name ====="
    if bash "$TESTS_DIR/test_$name.sh"; then
        :
    else
        fails=$((fails + 1))
        echo "  -> test_$name FAILED"
    fi
    echo
done

if [ "$fails" -eq 0 ]; then
    echo "ALL TESTS PASSED"
else
    echo "$fails TEST(S) FAILED"
fi
exit "$fails"
