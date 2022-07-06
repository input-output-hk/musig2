# MuSig2
Implementation of 
["MuSig2: Simple Two-Round Schnorr Multi-Signatures"](https://eprint.iacr.org/2020/1261.pdf)
using the Ristretto prime order group over Curve25519. We used libsodium for the 
implementation of ristretto255. This code compiles using the `musig2_compat` [branch](https://github.
com/input-output-hk/libsodium/tree/musig2_compat)
of IOHK's `libsodium` fork. To install `musig2_compat` branch, run the following: 
```shell
git clone https://github.com/input-output-hk/libsodium
cd libsodium
git checkout musig2_compat
./autogen.sh -f
./configure
make
make install
```

Test with two signers available in `musig2test.c`. To run test: 
```
make
./musig2test
```

# Disclaimer
This code is work in progress, and has not been audited. Do not use in production. 

# Batch verification equation
Using batch verification equation avoids the need of multiplying by the torsion-safe component. Similarly, it would 
ensure that, even if a party uses a pk with a torsion component (or sends an announcement), the equation will still 
validate. Study needed, to see whether this affects the protocol.

___

# MuSig2 Implementation with libsecp256k1
This is a MuSig2 implementation using the libsecp256k1 library for EC operations.

To install the library, follow the directions in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
The library provides an optimized C library for ECDSA signatures and secret and public key operations on curve 
secp256k1, as well as usage examples including ECDSA and Schnorr signatures.

This implementation requires to configure the libsecp256k1 with an additional flag 
`--enable-module-schnorrsig` as stated in [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

Test the implementation with musig2test.c

```
make
./musig2test
```

## Verify MuSig2 with `secp256k1_schnorrsig_verify`
The standard for 64-byte Schnorr signatures over secp256k1 uses x only encoding for _R_ and PK (aggregated public 
key _X_ in our case) that results in 32-byte public keys and 64-byte signatures.

Every valid x coordinate has two possible y coordinates, in order to avoid ambiguity the library uses points with 
even y coordinates. The signature generation and verification are done with using only x coordinates of public key 
and R since they only have even y coordinates.

However, to obtain _R_ and aggregated public key _X_ with even y coordinates may not be the case for every trial of 
MuSig2.

The aggregated public key is `X = X_1 * a_1 + ... + X_n * a_n` and _R_ is `R = R_1 * b^(j-1) + ... + R_V * b^(V-1)`.

The verification of MuSig2 checks whether:

```
    G * sig = R + X * c.
```

Therefore, we made a little tweak to make sure MuSig2 can be verified by `secp256k1_schnorrsig_verify`.

1. If _X_ has an odd y coordinate and _R_ has even: **Negate _c_**

2. If _R_ has an odd y coordinate and _X_ has even: **Negate every element in _b_LIST_ and recompute _R_.**

3. If both _X_ and _R_ have odd y coordinates: **Negate aggregated signature _agg_sig_.** 






















