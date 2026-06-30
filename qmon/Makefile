# Standalone build for qmon.so - the QEMU TCG introspection plugin.
#
# Depends only on the in-tree <qemu-plugin.h> header and system glib.
# It does NOT require building QEMU itself (no meson/ninja).
#
#   make            # build qmon.so
#   make guest      # build the deterministic guest test program
#   make verify     # build everything and run the end-to-end test on 000_run
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
GUEST   := $(QEMU_ROOT)/000_run/root/qmon_target

all: $(TARGET)

$(TARGET): qmon.c
	$(CC) $(CFLAGS) $< -o $@ -shared $(GLIB_LIBS) -pthread

# Freestanding, fixed-VA guest workload used only for verification.
guest: $(GUEST)
$(GUEST): target/qmon_target.c
	$(CC) -O2 -ggdb3 -static -no-pie -nostartfiles -fno-stack-protector -o $@ $<

verify: all guest
	./verify.sh

clean:
	rm -f $(TARGET)

.PHONY: all guest verify clean
