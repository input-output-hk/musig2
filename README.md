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

### Security considerations

The xonly encoding of elliptic curve points causes ambiguity since every `X` coordinate has two possible `Y` coordinates. 
To avoid this ambiguity they chose to select elliptic curve points with even `Y` coordinates.
The xonly encoding of a point is equivalent to representing it with a 33-byte but more compact since only the points with even `Y` coordinate are preferred there is no need to use one extra byte to specify the sign of the point. 
Moreover, this encoding does not reduce the security of the system (see [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#:~:text=Despite%20halving%20the,8%5D.)). 
Even if there is an algorithm to solve ECDLP for the xonly encoding, then the full encoding will also be automatically broken since the `X` coordinate has two possible `Y` coordinates as negative and positive.

## Adapting MuSig2 to PIB-430

[MuSig2](https://eprint.iacr.org/2020/1261.pdf) 
is a two-round multi-signature scheme that outputs an ordinary Schnorr signature. 

1. **Setup:** Let $p$ be a prime and $E$ be an elliptic curve defined over the finite field $F_p$ with the base point $G$ of order $p$.

2. **Key generation:** Every signer selects $x_i$ randomly in $\bmod p$ as secret key, and corresponding public key is $X_i = x_i \cdot G$.

3. **Batch commitment:** Signers create a list of batch commitments including $V$ elements.
   The commitment of a signer is an elliptic curve point such that $R = r \cdot G$ where $r$ is randomly selected in $\bmod p$. Then, the batch commitments of the system are

$$ {R_{11}, R_{12}, \ldots, R_{1V},\ldots, R_{N1}, \ldots, R_{NV}} $$

where $N$ is the number of signers, and $V$ is the number of nonces.

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

In order to verify MuSig2 by using the function `secp256k1_schnorrsig_verify`, the signature must be obtained by $X$ and $R$ with even `Y` coordinates.
However, the aggregation of public keys and the commitments may not result points with even `Y` coordinates. 
Therefore, signers do the following in the single signature generation step:


- **Case 1** ( $X$ has odd, $R$ has even `Y` coordinate): In this case, signers negate $c$. 
Negating $c$ is equivalent to negating $X$, since

$$ s \cdot G = R + (-c) \cdot (-X) $$

- **Case 2** ( $X$ has even, $R$ has odd `Y` coordinate): In this case, 
signers negate every element in the list $b^0, b^1, \ldots, b^{V-1}$, so $R$ is also negated.

- **Case 3** (Both have odd `Y` coordinates): Signers negates their partial signature, so that the aggregated signature will be negated:

$$ (-s) \cdot G = (-R) + c \cdot (-X). $$

### AOMDL
The security of MuSig2 depends on the hardness of *algebraic one more discrete logarithm (AOMDL)* problem. 
In the standard one more discrete logarithm problem, an adversary is given the public parameters $(E(F_p), G, p)$ and wins if it can solve the discrete logarithms $(x_1, \ldots, x_{q+1})$ of $q+1$ challenge group elements $(X_1, \ldots, X_{q+1})$ by only making at most $q$ queries to $D_{LOG}$ oracle.
The algebraic version of this problem requires to include an algebraic representation $(\alpha, (\beta_i)_{1 \leq i \leq c})$ 
of the challenge $X$ such that:

$$ X = \alpha \cdot G  + \Sigma_{i = 1}^{c}(\beta_i \cdot X_i). $$

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
