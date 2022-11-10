# MuSig2 Implementation with libsecp256k1

This is a MuSig2 implementation using the libsecp256k1 library for EC operations.

To install the library, follow the directions in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
The library provides an optimized C library for ECDSA signatures and secret and public key operations on curve ecp256k1, as well as usage examples including ECDSA and Schnorr signatures.

This implementation requires configuring the libsecp256k1 with an additional flag `--enable-module-schnorrsig` as stated in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

Run the example with examplemusig2.c

```shell
make example
./example_run/example
```

Run the Google tests with

```shell
make test
./test_run/test
```

Note that you need to install *Google Test* by following the instructions given [here](https://google.github.io/googletest/).

Running Valgrind in MacOs can be quite painful.
We included a Dockerfile to run valgrind checks on MacOs with an arm chip (e.g. M1).
To test the code with valgrind, run the following:
```shell
 docker build -t "valgrind:1.0" .
 docker run -it -v $PWD:/tmp -w /tmp valgrind:1.0
```

and once you are interacting with the container, run
```shell
make valgrind
```

### Security of MuSig2 with BIP-340 Compatibility

See [Security](https://github.com/input-output-hk/musig2/blob/readme-bip-compat/Security.md) for the BIP-340 compatibility of MuSig2.
