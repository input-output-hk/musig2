extern "C" {

TEST (musig2, valid_signature) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Generate partial signatures for `less_signers`.
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Aggregate partial signatures for `NR_SIGNERS`..
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 1);
}

TEST (musig2, not_enough_signatures) {
#define less_signers (NR_SIGNERS - 1)

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[less_signers];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Generate partial signatures for `less_signers`.
    err = musig2_helper_sign(mcs_list, mps, less_signers);
    ASSERT_EQ(err, 1);

    // Aggregate partial signatures for `NR_SIGNERS`..
    err = musig2_aggregate_partial_sig(mps, signature, less_signers);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);
}

TEST (musig2, non_corresponding_signers) {
#define nr_participants  (NR_SIGNERS + 1) // We define more signers.

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[nr_participants]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[nr_participants * NR_MESSAGES * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[nr_participants * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    // Init signers, store public keys, create batch commitments for `nr_participants`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, nr_participants);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, &mcs_list[1]);
    ASSERT_EQ(err, 1);

    // Generate partial signatures for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
    err = musig2_helper_sign(&mcs_list[1], mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Aggregate partial signatures for ``mcs_list[0], ..., mcs_list[NR_SIGNERS - 1]`.
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verify the aggregated signature with secp256k1_schnorrsig_verify
    // Verification should fail since the aggregated signature does not correspond to the aggregated public key.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, incorrect_aggregated_commitment_of_nonces) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    secp256k1_pubkey temp_pubkey;
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    unsigned char tweak[MUSIG2_SCALAR_BYTES] = {7};
    int err;

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Modify one of the aggregated commitment of nonce of one of the signers.
    assert(secp256k1_xonly_pubkey_tweak_add(ctx, &temp_pubkey, &mps[0].R, tweak));
    assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &mps[0].R, NULL, &temp_pubkey));

    // Aggregation of partial signatures should fail since one of the signatures have incorrect aggregated commitment of nonce.
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_NE(err, MUSIG2_OK);

    // Verify the aggregated signature with secp256k1_schnorrsig_verify
    // Verification should fail because the aggregation is not complete.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, previous_state) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps1[NR_SIGNERS];
    musig2_context_signature mps2[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature1[MUSIG2_BYTES];
    unsigned char signature2[MUSIG2_BYTES];
    int i, err;

    /*** STATE = 0 ****************************************************************************************************/
    // Musig2 proceeds as it is supposed to do for the first state.

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    err = musig2_helper_sign(mcs_list, mps1, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(mps1, signature1, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature1, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 1);

    /*** STATE = 1 ****************************************************************************************************/
    // One of the signers will sign for the previous state.
    mcs_list[0].state = 0;

    // Signature generation should fail for the incorrect state.
    err = musig2_sign(&mcs_list[0], &mps2[0], MSG_2, MSG_2_LEN);
    ASSERT_NE(err, MUSIG2_OK);

    // The rest of the signers generate their partial signatures.
    for (i = 1; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN);
        ASSERT_EQ(err, MUSIG2_OK);
    }

    // Aggregation should fail.
    err = musig2_aggregate_partial_sig(mps2, signature2, NR_SIGNERS);
    ASSERT_NE(err, MUSIG2_OK);

    // Verification should fail.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature2, MSG_2, MSG_2_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, future_state) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // One of the signers will sign for a future state.
    mcs_list[0].state = 1;
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_NE(err, MUSIG2_OK);

    // Verification should fail since one of the signers' signature used a future state.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, invalid_signer_key) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Flip a bit of a signer's keypair.
    mcs_list[0].keypair.data[31] ^= 1;
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the signers' key is incorrect.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, invalid_single_signature) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Flip a bit of a single signature.
    mps[0].signature[0] ^= 1;

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the single signatures is incorrect.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, aggregate_invalid_public_key) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    int err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Flip a bit of one of the signers' public key.
    serialized_pubkey_list[0] ^= 1;
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the signers' public key is incorrect.
    err = musig2_helper_verify(ctx, mcs_list[0].mc.aggr_pubkey, signature, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

}
