# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = ssloff

# all source are stored in SRCS-y
# SRCS-y := main.c tcp.c dpdk_io.c ssl.c cert.c ssl_crypto.c host.c pka_helper.c fhash.c
SRCS-y := main.c tcp.c dpdk_io.c ssl.c cert.c ssl_crypto.c host.c pka_helper.c fhash.c tc_rule/tc.c tc_rule/netlink-socket.c tc_rule/netlink.c tc_rule/ofpbuf.c

# Build using pkg-config variables if possible
$(shell pkg-config --exists libdpdk)
ifeq ($(.SHELLSTATUS),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell pkg-config --path libdpdk)
CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)

LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk)
LDFLAGS_STATIC = -Wl,-Bstatic $(shell pkg-config --static --libs libdpdk)

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared helper/*.o
	rmdir --ignore-fail-on-non-empty build

else # Build using legacy build system

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += $(WERROR_FLAGS)

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

PKA_DIRECTORY = /root/pkalib-1.0

PKA_INC = -I$(PKA_DIRECTORY)/lib -I$(PKA_DIRECTORY)/include -I./helper
TC_RULE_INC = -I/root/SmartTLS/smartnic/offload_ssl/tc_rule/include


#EXTRA_CFLAGS += -O3 -g -Wfatal-errors -lgmp

# Added PKA
# EXTRA_CFLAGS += -std=gnu99 -O3 -g -lgmp -lssl -lcrypto -lPKA -DGNU_SOURCE ${PKA_INC} ${TC_RULE_INC}

# Added PKA and TC_RULE
EXTRA_CFLAGS += -std=gnu99 -DHAVE_NETLINK -O3 -g -lgmp -lssl -lcrypto \
				-lPKA -DGNU_SOURCE ${PKA_INC} ${TC_RULE_INC}

include $(RTE_SDK)/mk/rte.extapp.mk
endif
