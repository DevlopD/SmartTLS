# TODO: Make this Makefile.in pretty

TARGETS = ssl_server
CC=gcc -g -O3 -Wall -Werror -fgnu89-inline
DPDK=1
PS=0
UCTX=1
USE_BLUEFIELD=1
NETMAP=0
ONVM=0
CFLAGS=-g -O2

# Add arch-specific optimization
ifeq ($(shell uname -m),x86_64)
LIBS += -m64
endif

# mtcp library and header 
MTCP_FLD    =../../mtcp/
MTCP_INC    =-I${MTCP_FLD}/include
MTCP_LIB    =-L${MTCP_FLD}/lib
MTCP_TARGET = ${MTCP_LIB}/libmtcp.a

UTIL_FLD = ../../util
UTIL_INC = -I${UTIL_FLD}/include
UTIL_OBJ = ${UTIL_FLD}/http_parsing.o ${UTIL_FLD}/tdate_parse.o ${UTIL_FLD}/netlib.o

# util library and header
INC = -I./ -I./include/ ${UTIL_INC} ${MTCP_INC} -I${UTIL_FLD}/include
LIBS = ${MTCP_LIB} -L/usr/local/lib/ -lcrypto -lssl

# psio-specific variables
ifeq ($(PS),1)
PS_DIR = ../../io_engine/
PS_INC = ${PS_DIR}/include
INC += -I{PS_INC}
LIBS += -lmtcp -L${PS_DIR}/lib -lps -lpthread -lnuma -lrt
endif

# netmap-specific variables
ifeq ($(NETMAP),1)
LIBS += -lmtcp -lpthread -lnuma -lrt
endif

# dpdk-specific variables
ifeq ($(DPDK),1)
DPDK_MACHINE_LINKER_FLAGS=${RTE_SDK}/${RTE_TARGET}/lib/ldflags.txt
DPDK_MACHINE_LDFLAGS=$(shell cat ${DPDK_MACHINE_LINKER_FLAGS})
LIBS += -g -O3 -pthread -lrt -march=native ${MTCP_FLD}/lib/libmtcp.a -lnuma -lmtcp -lpthread -lrt -ldl -lgmp -L${RTE_SDK}/${RTE_TARGET}/lib ${DPDK_MACHINE_LDFLAGS}
endif

ifeq ($(UCTX),1)
CFLAGS += -DENABLE_UCTX
endif

# onvm-specific variables
ifeq ($(ONVM),1)
ifeq ($(RTE_TARGET),)
$(error "Please define RTE_TARGET environment variable")
endif

INC += -I/onvm_nflib
INC += -I/lib
INC += -DENABLE_ONVM
LIBS += /onvm_nflib/$(RTE_TARGET)/libonvm.a
LIBS += /lib/$(RTE_TARGET)/lib/libonvmhelper.a -lm
endif

ifeq ($V,) # no echo
	export MSG=@echo
	export HIDE=@
else
	export MSG=@\#
	export HIDE=
endif

all: ssl_server

ssl_cert.o: ssl_cert.c
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}

ssl_server.o: ssl_server.c
	$(MSG) "   CC $<"
	$(HIDE) ${CC} -c $< ${CFLAGS} ${INC}

ssl_server: ssl_server.o ssl_cert.o ${MTCP_FLD}/lib/libmtcp.a
	$(MSG) "   LD $<"
	$(HIDE) ${CC} $< ${LIBS} ssl_cert.o ${UTIL_OBJ} ${INC} -o $@

clean:
	$(MSG) "   CLEAN $(TARGETS)"
	$(HIDE) rm -f *~ *.o ${TARGETS} log_*

distclean: clean
	rm -rf Makefile
