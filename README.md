# MuSig2
Implementation of 
["MuSig2: Simple Two-Round Schnorr Multi-Signatures"](https://eprint.iacr.org/2020/1261.pdf)
using the Ristretto prime order group over Curve25519. We used libsodium for the 
implementation of ristretto255. This code compiles using the `musig2_compat` [branch](https://github.com/input-output-hk/libsodium/tree/musig2_compat)
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
