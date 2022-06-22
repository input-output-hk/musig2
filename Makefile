CC=clang
CFLAGS=-Wall -Wno-unused-variable -Wno-unused-function -g -lsecp256k1

all: musig2test

libmusig2.o: libmusig2.c libmusig2.h random.h
	$(CC) $(CFLAGS) -c libmusig2.c

musig2test: musig2test.c libmusig2.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf *.o musig2test libmusig2.o
