# Standalone build for qmon.so - the QEMU TCG introspection plugin.
#
# Depends only on the in-tree <qemu-plugin.h> header and system glib.
# It does NOT require building QEMU itself (no meson/ninja).
#
#   make            # build qmon.so
#   make guest      # build the deterministic guest test program
#   make test       # build everything and run the test suite (tests/) on 000_run
#   make test-NAME  # run a single test standalone, e.g. make test-break
#   make clean

QEMU_ROOT  ?= $(abspath $(CURDIR)/..)
PLUGIN_INC ?= $(QEMU_ROOT)/include/plugins      # in-tree qemu-plugin.h
CC         ?= cc
PKG_CONFIG ?= pkg-config

GLIB_CFLAGS := $(shell $(PKG_CONFIG) --cflags glib-2.0)
GLIB_LIBS   := $(shell $(PKG_CONFIG) --libs glib-2.0)

CFLAGS  ?= -O2 -g -Wall -Wextra
CFLAGS  += -std=gnu11 -fPIC -fvisibility=hidden -pthread -I$(PLUGIN_INC) $(GLIB_CFLAGS)

TARGET  := qmon.so
SRCS    := qmon.c probe_ylang.c
HDRS    := qmon_ylang.h probe_ylang.h
GUEST   := $(QEMU_ROOT)/000_run/root/qmon_target

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ -shared $(GLIB_LIBS) -pthread

# Freestanding, fixed-VA guest workload used only for verification.
guest: $(GUEST)
$(GUEST): target/qmon_target.c
	$(CC) -O2 -ggdb3 -static -no-pie -nostartfiles -fno-stack-protector -o $@ $<

# Run the whole suite against a freshly-booted 000_run guest (one boot).
test: all guest
	./tests/run_all.sh

# Run a single test standalone (boots its own guest), e.g. `make test-break`.
# Names: ping regs vmem maps watch break ktrace.
test-%: all guest
	./tests/test_$*.sh

# ORC unwinder test on a frame-pointer-less kernel (needs an ORC kernel; build
# it once with tests/orc/build-orc-kernel.sh). Explicit rule; overrides test-%.
test-orc: all
	./tests/orc/test_ktrace_orc.sh

# ylang bridge test: boot with ylang=on and uprobe qemu_ylang_cpu_reg_dump()
# from an external ylang script (needs the OpenResty XRay CLI `run-y`; skips if
# absent). Explicit rule; overrides test-%.
test-ylang: all guest
	./tests/test_ylang_cpu_reg_dump.sh

verify: test          # back-compat alias

clean:
	rm -f $(TARGET)

.PHONY: all guest test test-orc test-ylang verify clean
