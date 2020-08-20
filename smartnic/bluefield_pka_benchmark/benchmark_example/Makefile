CC = gcc
PKA_DIRECTORY = /root/pkalib-1.0

INC = -I$(PKA_DIRECTORY)/lib -I$(PKA_DIRECTORY)/include
LIBRARY = -lpthread -lPKA -lcrypto

all: pka_benchmark

pka_benchmark: pka_benchmark.c
	$(CC) -W -Wall $(INC) -o pka_benchmark pka_benchmark.c helper/pka_helper.c -D_GNU_SOURCE $(LIBRARY)

clean:
	rm -f *~ *.o helper/*~ helper/*.o pka_benchmark
