TARGETS = aes_test

CC = gcc -g -Wall -Werror
LIBS = -lssl -lcrypto
INCLUDE = -I.

all: aes_test

aes_test.o: aes_test.c
	${CC} -c $< ${INCLUDE}

aes_test: aes_test.o
	${CC} $< ${LIBS} -o $@
