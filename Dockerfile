FROM ubuntu:latest
RUN apt-get update && apt-get -y install sudo
RUN sudo apt-get install g++
RUN sudo apt-get install valgrind
RUN sudo apt-get -y install clang 
RUN sudo apt-get -y install make
COPY ./libsodium-1.0.18-stable.tar.gz .
RUN tar -xf libsodium-1.0.18-stable.tar.gz
RUN cd libsodium-stable && ./configure && make && make check && sudo make install
COPY . .
RUN make

RUN valgrind --leak-check=yes ./musig2test
