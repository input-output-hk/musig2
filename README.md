# MuSig2 Implementation with libsecp256k1

This is a MuSig2 implementation using the libsecp256k1 library for EC operations.

To install the library, follow the directions in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
The library provides an optimized C library for ECDSA signatures and secret and public key operations on curve ecp256k1, as well as usage examples including ECDSA and Schnorr signatures.

This implementation requires configuring the libsecp256k1 with an additional flag `--enable-module-schnorrsig` as stated in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

Run the example with examplemusig2.c

```shell
make ctest
./ctest_run/ctest
```

Run the Google tests with

```shell
make gtest
./gtest_run/gtest
```

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

## Schnorr Signature of libsecp256k1

The library offers an optional module implementing Schnorr signatures over the curve `secp256k1`. 
The scheme is compatible with [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) that produces 64-byte Schnorr signatures. 
BIP-340 standardized the scheme with some modifications for practical purposes.


### Modifications

- **Encoding nonce and public key:**
Instead of encoding full `X`, `Y` coordinates of $R$ and $X$ (64-byte public key, 96-byte signature), or compressed encoding (33-byte public key, 65-byte signature), BIP-430 preferred to use xonly encoding (32-byte public key, 64-byte signature).

- **Implicit `Y` coordinate:**
Schnorr signatures of BIP-430 implicitly choose the `Y` coordinate that is even.

- **Tagged hashes:**
In order to prevent the collisions and reuse of nonce, it is preferred to include the tag by prefixing the hash data with `SHA256(tag) || SHA256(tag)`.

### Security considerations

The xonly encoding of elliptic curve points causes ambiguity since every `X` coordinate has two possible `Y` coordinates. 
To avoid this ambiguity they chose to select elliptic curve points with even `Y` coordinates.
The xonly encoding of a point prefixed by the byte `0x02` is equivalent to representing it with a 33-byte but more compact. 
Moreover, this encoding does not reduce the security of the system. 
Even if there is an algorithm to solve ECDLP for the xonly encoding, then the full encoding will also be automatically broken since the `X` coordinate has two possible `Y` coordinates as negative and positive.

## Adapting MuSig2 to PIB-430

[MuSig2](https://eprint.iacr.org/2020/1261.pdf) 
is a two-round multi-signature scheme that outputs an ordinary Schnorr signature.

$$ G \cdot s = R + X \cdot c. $$

The aggregated public key $X$ is generated with the public keys of all signers:

$$ X = \Sigma_{i = 1}^{N} (X_i \cdot a_i) $$

where $a_i$ is the key aggregate coefficient.
The commitment $R$ is also generated with the commitments of signers and the nonce $b$.

$$ R = \Sigma_{i = 1}^{V}(R_j^{b^{j-1}}). $$

In order to verify MuSig2 by using the function `secp256k1_schnorrsig_verify`, the signature must be obtained by $X$ and $R$ with even `Y` coordinates.
However, the aggregation of public keys and the commitments may not result points with even `Y` coordinates. 
Therefore, signers do the following in the single signature generation step:


- **Case 1** ($X$ has odd, $R$ has even `Y` coordinate): In this case, signers negate $c$. 
Negating $c$ is equivalent to negating $X$, since

$$ G \cdot s = R + (-X) \cdot (-c) $$

- **Case 2** ($X$ has even, $R$ has odd `Y` coordinate): In this case, 
signers negate every element in the list $b^0, b^1, \ldots, b^{V-1}$, so $R$ is also negated.

- **Case 3** (Both have odd `Y` coordinates): Signers negates their partial signature, so that the aggregated signature will be negated:

$$ G \cdot (-s) = (-R) + (-X) \cdot c. $$

### AOMDL
The security of MuSig2 depends on the hardness of *algebraic one more discrete logarithm (AOMDL)* problem. 
In the standard one more discrete logarithm problem, an adversary is given the public parameters ($E(F_p), G, p$) and wins if it can solve the discrete logarithms ($x_1, \ldots, x_{q+1}$) of $q+1$ challenge group elements ($X_1, \ldots, X_{q+1}$) by only making at most $q$ queries to $D_{LOG}$ oracle.
The algebraic version of this problem requires to include an algebraic representation $(\alpha, (\beta_i)_{1 \leq i \leq c})$ of the challenge $X$ such $X = G \cdot \alpha + \Sigma_{i=1}^{c}(X_i \cdot \beta_i)$.
The question is that whether using xonly encoding for the public keys reduce the security of the scheme.
If there exists a polynomial algorithm to solve AOMDL for xonly encoding of a curve point, then it basically implies that AOMDL is broken for full-size encoding as well, since every `X` coordinate has two possible `Y` coordinate as odd or even. 



___

### Progress

- [x] Update the function and parameter namings.
- [x] Prevent reuse of r values.
- [x] Create musig2 context to simplify the API.
- [ ] Tests (Valgrind).
- [ ] Tests (GoogleTest).
- [ ] Documentation.
