CC=gcc

all:
	$(CC) -Wall -o ssl-server server.c -L/usr/lib -D_GNU_SOURCE -lpthread -lssl -lcrypto
	$(CC) -Wall -o ssl-client client.c -L/usr/lib -lpthread -lssl -lcrypto

clean:
	rm -f ssl-*
