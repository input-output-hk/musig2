
CC = clang

CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-command-line-argument -g

CPPFLAGS = $(CFLAGS) -x c++ -Wextra -std=c++11


LDLIBS = -lsecp256k1
GTEST_LDLIBS = $(LDLIBS) -lstdc++ -lgtest -lgtest_main
INCLUDES = src/libmusig2.h src/random.h

AR=ar rcs
RANLIB=ranlib

all: gtest ctest lib_musig2


build/musig2.o: src/libmusig2.c $(INCLUDES)
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(LDLIBS) src/libmusig2.c -o build/musig2.o

lib_musig2: build/musig2.o
	$(AR) build/libmusig2.a $^
	$(RANLIB) build/libmusig2.a

gtest: lib_musig2
	rm -rf gtest_run
	mkdir gtest_run
	$(CC) $(CPPFLAGS) $(GTEST_LDLIBS) tests/gtestmusig2.c -L./build -lmusig2 -o gtest_run/gtest

ctest: lib_musig2
	rm -rf ctest_run
	mkdir ctest_run
	$(CC) $(CFLAGS) $(LDLIBS) examplemusig2.c -L./build -lmusig2 -o ctest_run/ctest

run_tests: gtest ctest
	ctest_run/ctest
	gtest_run/gtest

valgrind: ctest
	valgrind --tool=memcheck --error-exitcode=1 --leak-check=full --show-reachable=yes ctest_run/ctest

clean:
	rm -rf *.o build gtest_run ctest_run
