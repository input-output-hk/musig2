# Security of MuSig2
The libsecp256k1 library offers an optional module implementing Schnorr signatures over the curve `secp256k1`.
The scheme is compatible with [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) that produces 64-byte Schnorr signatures.
BIP-340 standardized the scheme with some modifications for practical purposes.

MuSig2 adopts the BIP-340 standard. As a consequence, the proposed modifications also apply for this implementation.
The security of BIP-340 compatible MuSig2 implementation is explained below.

## BIP-340
For authenticating transactions, ECDSA signatures over the secp256k1 curve with SHA256 hashes are used traditionally
and standardized.
There are several disadvantages of ECDSA signatures compared to Schnorr signatures over the secp256k1 curve, yet 
there are no virtual disadvantages of Schnorr signatures.
So, the motivation of [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) is to propose a new 
standard with some improvements.

## Modifications
The following are the modifications that relates to the implementation of MuSig2.
- **Encoding nonce and public key:** Instead of encoding full `X`, `Y` coordinates of $R$ and $X$ (64-byte public
  key, 96-byte signature), or compressed
  encoding (33-byte public key, 65-byte signature, BIP-430 preferred to use xonly encoding (32-byte public key,
  64-byte signature).
- **Implicit `Y` coordinate:** The xonly encoding of elliptic curve points causes ambiguity since every `X` coordinate has two possible `Y` coordinates.
  To avoid this ambiguity, Schnorr signatures of BIP-430 implicitly chooses the `Y` coordinate that is even, in
  other words, xonly encoding is used to represent elliptic curve points that are sent over the wire.
### Security considerations
The xonly encoding of a point is equivalent to representing it with a 33-byte but more compact since only the points with even `Y` coordinate are preferred there is no need to use one extra byte to specify the sign of the point.
Moreover, this encoding does not reduce the security of the system (see [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#:~:text=Despite%20halving%20the,8%5D.)).
Even if there is an algorithm to solve ECDLP for the xonly encoding, then the full encoding will also be
automatically broken since the `X` coordinate has only two possible `Y` coordinates.


## Adapting MuSig2 to PIB-430
In order to verify MuSig2 by using the function `secp256k1_schnorrsig_verify`, the signature must be obtained by $X$ and $R$ with even `Y` coordinates.
However, the aggregation of public keys and the commitments may not result points with even `Y` coordinates.
Therefore, signers do the following in the single signature generation step:

- **Case 1** ( $X$ has odd, $R$ has even `Y` coordinate): In this case, signers negate $c$.
  Negating $c$ is equivalent to negating $X$, since

$$ s \cdot G = R + (-c) \cdot (-X) $$

- **Case 2** ( $X$ has even, $R$ has odd `Y` coordinate): In this case,
  signers negate every element in the list $b^0, b^1, \ldots, b^{V-1}$, so $R$ is also negated.

- **Case 3** (Both have odd `Y` coordinates): Signers negate their partial signature, so that the aggregated signature will be negated:

$$ (-s) \cdot G = (-R) + c \cdot (-X). $$

### AOMDL
The security of MuSig2 depends on the hardness of *algebraic one more discrete logarithm (AOMDL)* problem.
In the standard one more discrete logarithm problem, an adversary is given the public parameters $(E(F_p), G, p)$ and wins if it can solve the discrete logarithms $(x_1, \ldots, x_{q+1})$ of $q+1$ challenge group elements $(X_1, \ldots, X_{q+1})$ by only making at most $q$ queries to $D_{LOG}$ oracle.
The algebraic version of this problem requires to include an algebraic representation $(\alpha, (\beta_i)_{1 \leq i \leq c})$
of the challenge $X$ such that:

$$ X = \alpha \cdot G  + \Sigma_{i = 1}^{c}(\beta_i \cdot X_i). $$

The question is that whether using xonly encoding for the public keys reduce the security of the scheme.
If there exists a polynomial algorithm to solve AOMDL for xonly encoding of a curve point, then it basically implies that AOMDL is broken for full-size encoding as well, since every `X` coordinate has two possible `Y` coordinate as odd or even.
