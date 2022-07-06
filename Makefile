CC=clang
CFLAGS=-Wall -Wno-unused-variable -Wno-unused-function -g -lsecp256k1

OBJECTS = src/libmusig2.o genmusig.o

all: musig2test

src/libmusig2.o: src/libmusig2.c src/libmusig2.h src/random.h
	$(CC) -c $(CFLAGS)  src/libmusig2.c -o src/libmusig2.o

genmusig.o: genmusig.c api_musig2.h
	$(CC) -c $(CFLAGS) genmusig.c -o genmusig.o

musig2test: musig2test.c $(OBJECTS)
	$(CC)  $(CFLAGS) -o $@ $^

clean:
	rm -rf *.o musig2test src/libmusig2.o genmusig.o
