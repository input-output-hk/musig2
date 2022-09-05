
CC = clang

CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-command-line-argument -g

CPPFLAGS = $(CFLAGS) -x c++ -Wextra -std=c++11


LDLIBS = -lsecp256k1
GTEST_LDLIBS = $(LDLIBS) -lstdc++ -lgtest -lgtest_main
INCLUDES = src/libmusig2.h src/random.h

AR=ar rcs
RANLIB=ranlib

all: tests lib_musig2


build/musig2.o: src/libmusig2.c $(INCLUDES)
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(LDLIBS) src/libmusig2.c -o build/musig2.o

lib_musig2: build/musig2.o
	$(AR) build/libmusig2.a $^
	$(RANLIB) build/libmusig2.a

tests: lib_musig2
	rm -rf test_musig2
	mkdir test_musig2
	$(CC) $(CPPFLAGS) $(GTEST_LDLIBS) tests/gtestmusig2.c -L./build -lmusig2 -o test_musig2/gtest
	$(CC) $(CFLAGS) $(LDLIBS) tests/musig2test.c -L./build -lmusig2 -o test_musig2/mtest

clean:
	rm -rf *.o build test_musig2
