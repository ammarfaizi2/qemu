# qmon test suite

End-to-end tests for `qmon.so`, run against the bundled `000_run` TCG appliance
(host kernel). Each test boots the guest with the plugin, drives `client.py`, and
checks one capability.

## Running

```sh
make test            # from qmon/: boot the guest ONCE, run every test, summary
make test-break      # run a single test standalone (boots its own guest)
make test-ktrace     # ...names: ping regs vmem maps watch break ktrace

./tests/test_break.sh                 # same as `make test-break` (must be built first)
QMON_SOCK=/tmp/x.sock ./tests/test_regs.sh   # run against an already-running guest
```

`make test` boots one shared guest and runs all tests against it (fast). A single
`make test-NAME` / `./tests/test_NAME.sh` boots its own guest (slower, fully isolated).
Because the plugin disarms breakpoints/watchpoints when a client disconnects, each test
is naturally isolated even on the shared guest.

**Requirements:** run as root (the appliance image is loop-mounted to inject the
workload), and a `qemu-system-x86_64` built with TCG plugins (the in-tree
`/root/qemu/build` one). Overridable via env: `QEMU`, `KSYMS`, `BTF`, `SOCK`, `LOG`.

## The tests

| script            | checks                                                                 |
|-------------------|------------------------------------------------------------------------|
| `test_ping.sh`    | plugin answers on its socket                                           |
| `test_regs.sh`    | obj 1 — dump CPU registers (`rip`/`cr3` present)                       |
| `test_vmem.sh`    | obj 2/3 — read guest VA memory; cross-check `gva→gpa` via `pmem`       |
| `test_maps.sh`    | obj 3 — page-table walk returns guest virt↔phys mappings              |
| `test_watch.sh`   | obj 4 — watchpoint on `g_counter`, observe write events                |
| `test_break.sh`   | obj 5 — breakpoint on `marker()`; freeze, read regs, resume, re-arm    |
| `test_ktrace.sh`  | kernel call-trace + current context at `hrtimer_nanosleep`             |

The deterministic guest workload `target/qmon_target.c` (static, fixed VAs) loops:
bump `g_counter` → call `marker()` → `nanosleep`. So `marker` (0x401000) drives the
breakpoint test, `g_counter` (0x404000) the watchpoint, and the `nanosleep` syscall the
kernel call-trace.

## Layout / how it works

- **`common.sh`** — sourced by every test (DRY). Provides `qmon_build`, `qmon_symbols`
  (fixed VAs via `nm`), `qmon_repack` (loop-mount the workload in), `qmon_boot`/`qmon_teardown`
  (fifo console, plugin args `bp=on,wp=on,ksyms=,btf=` + `nokaslr`), and `qmon_begin`:
  reuse a shared guest when `QMON_SOCK` is exported, else boot+teardown our own.
- **`test_<name>.sh`** — ~3 lines: `source common.sh; qmon_begin; run_check <name> [args]`.
- **`run_all.sh`** — what `make test` runs: boot one shared guest, `export QMON_SOCK`, run
  each `test_*.sh`, aggregate, exit non-zero on any failure.

The assertions themselves live in `../client.py` as `tc_<name>` functions, dispatched by
`client.py <sock> test <name> [args]` (one connection per case — required by the
disarm-on-disconnect behavior). `client.py <sock> test all <marker> <counter>` runs the
whole suite in a single connection.

## Adding a test

1. Add a `tc_<name>(q, ck, ...)` check in `../client.py` and register it in `TESTS` /
   `TEST_ORDER`.
2. Add `tests/test_<name>.sh` (3 lines, mirror an existing one).
3. Add `<name>` to the loop in `run_all.sh`.
