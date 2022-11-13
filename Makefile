
CC = clang

CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-command-line-argument -g

CPPFLAGS = $(CFLAGS) -x c++ -Wextra -std=c++11


LDLIBS = -lsecp256k1
GTEST_LDLIBS = $(LDLIBS) -lstdc++ -lgtest -lgtest_main
INCLUDES = src/libmusig2.h src/random.h


AR=ar rcs
RANLIB=ranlib

all: test example


build/musig2.o: src/libmusig2.c $(INCLUDES)
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(LDLIBS) src/libmusig2.c -o build/musig2.o

lib_musig2: build/musig2.o
	$(AR) build/libmusig2.a $^
	$(RANLIB) build/libmusig2.a

test: lib_musig2
	rm -rf test_run
	mkdir test_run
	$(CC) $(CPPFLAGS) $(GTEST_LDLIBS) tests/testmusig2.c -L./build -lmusig2 -o test_run/test
	rm build/musig2.o


example: lib_musig2
	rm -rf example_run
	mkdir example_run
	$(CC) $(CFLAGS) $(LDLIBS) examplemusig2.c -L./build -lmusig2 -o example_run/example

run_tests: test example
	example_run/example
	test_run/test

valgrind: example
	valgrind --tool=memcheck --error-exitcode=1 --leak-check=full --show-reachable=yes example_run/example

clean:
	rm -rf *.o build test_run example_run
