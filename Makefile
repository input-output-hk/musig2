CC=clang
CFLAGS=-Wall -g -lsodium

all: musig2test

libmusig2.o: libmusig2.c libmusig2.h
	$(CC) $(CFLAGS) -c libmusig2.c

musig2test: musig2test.c libmusig2.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm *.o musig2test