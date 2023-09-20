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


## MuSig2 in a Nutshell
[MuSig2](https://eprint.iacr.org/2020/1261.pdf)
is a two-round multi-signature scheme that outputs an ordinary Schnorr signature.

1. **Setup:** Let $p$ be a prime and $E$ be an elliptic curve defined over the finite field $F_p$ with the base point $G$ of order $p$.

2. **Key generation:** Every signer selects $x_i$ randomly in $\bmod p$ as secret key, and computes the corresponding
   public key as $X_i = x_i \cdot G$.

3. **Batch commitment:** Signers create a list of batch commitments including $V$ elements.
   The $j^{th}$ commitment of the $i^{th}$ signer is an elliptic curve point such that $R_{ij} = r_{ij} \cdot G$ where
   $r_{ij}$ is the nonce, randomly selected in $\bmod p$. Then, the batch commitments of the system are

$$ {R_{11}, R_{12}, \ldots, R_{1V},\ldots, R_{N1}, \ldots, R_{NV}} $$

where $N$ is the number of signers.

4. **Aggregate public key:** After receiving the public keys of the registered signers, each signer aggregate the public key as follows:

$$ L = (X_1 || X_2 || \ldots || X_N) $$

$$ a_i = H_{agg}(L || X_i)_{i = 1..N} $$

$$ X = \Sigma_{i = 1}^{N} (a_i \cdot X_i) $$

Finally, the signer obtains the public key $X$ and keeps her own $a_i$.

5. **Aggregate commitments:** After receiving the batch commitment list, a signer computes the aggregate nonce as follows:

$$ R_i = (R_{i1}, \ldots, R_{iV})_{i = 1..N} $$

$$ R_j = (\Sigma_{i = 1}^{V} (R_{ij})_{i = 1..N}) $$

6. **Single signature:** A single signature $s_i$ is generated as:

$$ b = H_{non}(X || (R_1 || \ldots || R_V) || m) $$

$$ R = \Sigma_{i = 1}^{V}(R_j^{b^{j-1}}) $$

$$ c = H_{sig}(X || R || m) $$

$$ s_i = c  a_i x_i + \Sigma_{i = 1}^{V}(r_{ij}   b^{j-1})$$

7. **Aggregate signature:** The aggregate signature $s$ is:

$$ s = \Sigma_{i = 1}^{N}(s_i) $$

So, the MuSig2 is $(R, s)$.

8. **Verification:** The verifier computes $c = H_{sig}(X || R || m)$ and accepts the signature if $s \cdot G = R + c \cdot X$.

$$ s \cdot G = R + c \cdot X. $$

The aggregated public key $X$ is generated with the public keys of all signers:

$$ X = \Sigma_{i = 1}^{N} (a_i \cdot X_i) $$

where $a_i$ is the key aggregate coefficient.
The commitment $R$ is also generated with the commitments of signers and the nonce $b$.

$$ R = \Sigma_{i = 1}^{V}(R_j^{b^{j-1}}). $$

## Schnorr Signature of libsecp256k1
The library offers an optional module implementing Schnorr signatures over the curve `secp256k1`. 
The scheme is compatible with [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) that produces 64-byte Schnorr signatures. 
BIP-340 standardized the scheme with some modifications for practical purposes.
MuSig2 adopts the BIP-340 standard. As a consequence, the proposed modifications also apply for this implementation. 
The security of BIP-340 compatible MuSig2 implementation is discussed in [security](/SECURITY.md).

