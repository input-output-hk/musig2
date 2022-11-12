# TODO:


1. Prep signer to register in init_signer
2. verify function
3. reorganize lib functions
4. reorganize tests
5. update header
 
 
............ 


1. **ERR_01:** *musig2_key_gen*
- fill_random
- secp256k1_keypair_create

2. **ERR_02:** *musig2_batch_commitment*
- fill_random
- secp256k1_keypair_create

3. **ERR_03:** *musig2_calc_R*
- secp256k1_ec_seckey_tweak_mul
- secp256k1_ec_pubkey_combine
- secp256k1_ec_seckey_negate

4. **ERR_04:** *musig2_set_parsig*
- secp256k1_ec_seckey_negate
- secp256k1_ec_seckey_tweak_mul

5. **ERR_11:** *musig2_init_signer*
- *ERR_01:* musig2_key_gen
- *ERR_02:* musig2_batch_commitment

6. **ERR_12:** *musig2_aggregate_pubkey*
- secp256k1_ec_seckey_tweak_mul
- secp256k1_ec_pubkey_combine

7. **ERR_13:** *musig2_aggregate_R*
- secp256k1_ec_pubkey_combine

8. **ERR_14:** *musig2_signer_precomputation*
- *ERR_13:* musig2_aggregate_R
- *ERR_12:* musig2_aggregate_pubkey

9. **ERR_15:** *musig2_sign*
10. **ERR_21:** *(mcs->comm_list[index + j] == NULL)*
- *ERR_03:* musig2_calc_R
- *ERR_04:* musig2_set_parsig

11. **ERR_16:** *musig2_aggregate_partial_sig*
12. **ERR_22:** *(secp256k1_xonly_pubkey_cmp(ctx, &mps[i].R, &mps[i - 1].R) != 0)*
- secp256k1_ec_seckey_tweak_add

13. **ERR_17:** *musig2_prepare_verifier*
- *ERR_12:* musig2_aggregate_pubkey











