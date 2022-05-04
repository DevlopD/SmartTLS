CC = /usr/bin/gcc -std=gnu99
CFLAGS =
CFLAGS += -D_GNU_SOURCE -DHAVE_NETLINK
LDFLAGS = -lpthread
LIBS = /usr/local/lib/libsflow.a
# LIBS = /usr/local/lib/libopenvswitch.a /usr/local/lib/libsflow.a

all: core

core: core.c
	$(CC) -I./include $(CFLAGS) $(LDFLAGS) -o tc_test \
		core.c tc.c netlink-socket.c netlink.c ofpbuf.c 

#  # util.c
# packets.c timeval.c socket-util.c dynamic-string.c vlog.c ovs-thread.c seq.c latch-unix.c poll-loop.c hmap.c unixctl.c $(LIBS) 


clean:
	rm -f tc_test *~
