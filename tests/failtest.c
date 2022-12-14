extern "C" {

    TEST (musig2, fail_excessive_num_of_participants) {
    #define more_signers  (NR_SIGNERS + 1) // We define less signers.

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
        musig2_context_signature mps[NR_SIGNERS];
        musig2_aggr_pubkey aggr_pubkey;
        unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
        unsigned char signature[MUSIG2_BYTES];
        int err, i;

        err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
        ASSERT_EQ(err, MUSIG2_OK);

        // Precomputation for less signers that succeeds
        for (i = 1; i < NR_SIGNERS; i++){
            err = musig2_signer_precomputation(&mcs_list[i].mc, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_OK);
        }
        // Precomputation for a signer that fails
        err = musig2_signer_precomputation(&mcs_list[0].mc, serialized_pubkey_list, serialized_batch_list, more_signers);
        ASSERT_EQ(err, MUSIG2_ERR_PARSE_PK_COMM);

        // Generate partial signatures for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
        // Failing participant cannot sign.
        err = musig2_helper_sign(&mcs_list[1], mps, less_signers);
        ASSERT_EQ(err, MUSIG2_OK);

        // Aggregate partial signatures for ``mcs_list[0], ..., mcs_list[NR_SIGNERS]` will fail.
        err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
        ASSERT_EQ(err, MUSIG2_ERR_CMP_R);

        err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
        ASSERT_EQ(err, MUSIG2_INVALID);
    }

}
