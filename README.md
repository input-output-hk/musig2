# MuSig2
Implementation of 
["MuSig2: Simple Two-Round Schnorr Multi-Signatures"](https://eprint.iacr.org/2020/1261.pdf)
using the Ristretto prime order group over Curve25519. We used libsodium for the 
implementation of ristretto255.

Test with two signers available in `musig2test.c`. To run test: 
```
make
./musig2test
```

# Disclaimer
This code is work in progress, and has not been audited. Do not use in production. 
