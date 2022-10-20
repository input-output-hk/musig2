FROM debian:bullseye-slim 
RUN apt-get update
RUN apt-get install curl valgrind make vim git build-essential cmake libcppunit-dev automake -y
RUN apt-get install -y libtool inotify-tools autoconf clang

RUN git clone https://github.com/bitcoin-core/secp256k1.git &&\
        cd secp256k1 &&\
        git reset --hard 694ce8f &&\
        ./autogen.sh &&\
        ./configure --prefix=/usr --enable-module-schnorrsig --enable-experimental &&\
        make &&\
	    make check &&\
        make install &&\
        cd ../..
