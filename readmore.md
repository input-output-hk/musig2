# MuSig2 Implementation with libsecp256k1

This is a MuSig2 implementation using the libsecp256k1 library for EC operations.

To install the library, follow the directions in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
The library provides an optimized C library for ECDSA signatures and secret and public key operations on curve ecp256k1, as well as usage examples including ECDSA and Schnorr signatures.

This implementation requires configuring the libsecp256k1 with an additional flag `--enable-module-schnorrsig` as stated in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

Run the example with examplemusig2.c

```
make ctest
./ctest_run/ctest
```

Run the Google tests with

```
make gtest
./gtest_run/gtest
```

## Schnorr Signature of libsecp256k1

The library offers an optional module implementing Schnorr signatures over the curve `secp256k1`.
The scheme is compatible with [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) that produces 64-byte Schnorr signatures.
BIP-340 standardized the scheme with some modifications for practical purposes.

### Schnorr Signature in a nutshell

Let $p$ be a prime and $E$ be an elliptic curve defined over the finite field $F_p$ with the base point $G$.
The signature scheme works as follows:

1. **Key generation:** The secret key $x$ is randomly chosen in $\bmod p$, the  corresponding public key is $X = G \cdot x$.

2. **Signing:** Signer selects a random number $r$ in $\bmod p$, and computes the  nonce $R = G \cdot r$.
   For the message $m$, signer sets the challenge as $c = H (X, R,  m)$ and computes $s = r + cx$.
   The signature is obtained as $(R, s)$.

3. **Verification:** The signature is valid if $G \cdot s = R + X \cdot c$.

### Modifications

- #### Encoding nonce and public key:
Instead of encoding full `X`, `Y` coordinates of $R$ and $X$ (64-byte public key, 96-byte signature), or compressed encoding (33-byte public key, 65-byte signature), BIP-430 preferred to use xonly encoding (32-byte public key, 64-byte signature).

- #### Implicit `Y` coordinate:
Schnorr signatures of BIP-430 implicitly choose the `Y` coordinate that is even.

- #### Tagged hashes:
In order to prevent the collisions and reuse of nonce, it is preferred to include the tag by prefixing the hash data with `SHA256(tag) || SHA256(tag)`.

### Security considerations

The xonly encoding of elliptic curve points causes ambiguity since every `X` coordinate has two possible `Y` coordinates.
To avoid this ambiguity they chose to select elliptic curve points with even `Y` coordinates.
The xonly encoding of a point prefixed by the byte `0x02` is equivalent to representing it with a 33-byte but more compact.
Moreover, this encoding does not reduce the security of the system.
Even if there is an algorithm to solve ECDLP for the xonly encoding, then the full encoding will also be automatically broken since the `X` coordinate has two possible `Y` coordinates as negative and positive.

## Adapting MuSig2 to PIB-430

The original scheme of [MuSig2](https://eprint.iacr.org/2020/1261.pdf) is as follows:

1. **Setup:** Let $p$ be a prime and $E$ be an elliptic curve defined over the finite field $F_p$ with the base point $G$.

2. **Key generation:** Every signer selects $x_i$ randomly in $\bmod p$ as secret key, and corresponding public key is $X_i = G \cdot x_i$.

3. **Batch commitment:** Signers create a list of batch commitments including $V$ elements.
   The commitment of a signer is an elliptic curve point such that $R = G \cdot r$ where $r$ is randomly selected in $\bmod p$. Then, the batch commitments of the system are

$$ {R_{11}, R_{12}, \ldots, R_{1V},\ldots, R_{N1}, \ldots, R_{NV}} $$

where $N$ is the number of signers, and $V$ is the number of nonces.

4. **Aggregate public key:** After receiving the public keys of the registered signers, each signer aggregate the public key as follows:

$$ L = (X_1 || X_2 || \ldots || X_N) $$

$$ a_i = H_{agg}(L || X_i)_{i = 1..N} $$

$$ X = \Sigma_{i = 1}^{N} (X_i \cdot a_i) $$

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

8. **Verification:** The verifier computes $c = H_{sig}(X || R || m)$ and accepts the signature if $G \cdot s = R + X \cdot c$.

### Modifications
- **Aggregate public key:** To compute the aggregate public key, we need to concatenate the public keys of the signers.
  Instead of using 64-byte of a full public key, we use only the `X` coordinates of the public keys.

$$ L = ((X_1)_x || \ldots || (X_N)_x). $$

So, the key aggregate coefficient of the signer $i$ is:

$$ a_i = H_{agg}(L || (X_i)_x). $$

The aggregate public key is computed as usual and stored as a full-size public key.

- **Single signature:** We obtain $b$ by hashing (tagged hash) the concatenation of the public key, list of aggregate batch commitments, and the message.
  The content to be hashed includes only the `X` coordinates of the elliptic curve points:

$$ b = H_{non}((X)_x || ((R_1)_x || \ldots || (R_V)_x) || m). $$

After computing the nonce $R$, the challenge $c$ is computed by using only the $X$ coordinates similarly:

$$ c = H_{sig}((X)_x || (R)_x || m). $$

The signer checks whether the `Y` coordinates of $X$ and $R$ are even or not.
- **$X$ has odd, $R$ has even `Y` coordinate:** The signer negates $c$.
- **$X$ has even, $R$ has odd `Y` coordinate:** The signer negates $b$ and $R$.
- **Both have odd or even `Y` coordinate:** The signer makes no changes.

After the checks, the single signature is calculated as usual.

- **Final signature:** In order to obtain a schnorr signature that can be verified by the `secp256k1_schnorrsig_verify` function, we need the aggregate signature, the xonly encoding of the aggregate public key, and aggregate nonce.
  However, they may have odd `Y` coordinate, and this will cause the rejection of the MuSig2.
  Therefore, while generating the final signature, we check whether both $X$ and $R$ have odd `Y` coordinates; if so, the aggregate signature is negated.
  Other possibilities have already been handled in the single signature step.

### Correctness of the modifications

- **Case 1** *($X$ has odd, $R$ has even `Y` coordinate):* In this case, signer negates $c$.

$$ s_i = - c a_i x_i + \Sigma_{j=1}^{V}(r_{ij} \cdot b^{j-1})$$

Negating $c$ is equivalent to negating $X$, since

$$ X = \Sigma_{i=1}^{N} (a_i \cdot X_i) $$

$$ a_i  x_i \cdot G = X_i $$

$$ G \cdot s = R + (-X) \cdot (-c) $$

So, the final signature can be verified successfully by `secp256k1_schnorrsig_verify`.

- **Case 2** *($X$ has even, $R$ has odd `Y` coordinate)*: In this case, signer negates $R$ and every element in the list $b^0, b^1, \ldots, b^{V-1}$.
  Note that a single signature includes

$$ \Sigma_{j=1}^{V}(r_{ij} b^{j-1}),$$

the aggregate nonce is obtained by

$$ R = \Sigma_{i = 1}^{V}(R_j^{b^{j-1}}) $$

where $R_j$ is the combination of the signers' batch commitments of the form  $R_{ij} = G \cdot r_{ij}$.
Therefore, the final signature will be valid.

- **Case 3** *(Both have odd `Y` coordinates)*: In this case, we need to negate the aggregate signature since

$$ G \cdot (-s) = (-R) + (-X) \cdot c. $$


___

### Progress

- [x] Update the function and parameter namings.
- [x] Prevent reuse of r values.
- [x] Create musig2 context to simplify the API.
- [ ] Tests (Valgrind).
- [ ] Tests (GoogleTest).
- [ ] Documentation.
