extern "C" {
/* Test for a valid flow. */
TEST (musig2, valid_signature) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Generate partial signatures for `less_signers`.
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate partial signatures for `NR_SIGNERS`..
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);
}

/* Insufficient number of single signatures aggregated should fail to verify with aggregate public key. */
TEST (musig2, not_enough_signatures) {
#define less_signers (NR_SIGNERS - 1)

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[less_signers];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Generate partial signatures for `less_signers`.
    err = musig2_helper_sign(mcs_list, mps, less_signers);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate partial signatures for `NR_SIGNERS`..
    err = musig2_aggregate_partial_sig(mps, signature, less_signers);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);
}

/* Verification of aggregate signature with respect to non-corresponding aggregate public key. */
TEST (musig2, non_corresponding_signers) {
#define nr_participants  (NR_SIGNERS + 1) // We define more signers.

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[nr_participants]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[nr_participants * NR_MESSAGES * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[nr_participants * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    // Init signers, store public keys, create batch commitments for `nr_participants`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, nr_participants);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate public keys and batch commitments for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, &mcs_list[1], NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Generate partial signatures for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
    err = musig2_helper_sign(&mcs_list[1], mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate partial signatures for ``mcs_list[0], ..., mcs_list[NR_SIGNERS - 1]`.
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verify the aggregated signature with secp256k1_schnorrsig_verify
    // Verification should fail since the aggregated signature does not correspond to the aggregated public key.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* Tweak `R` for one of the single signatures, aggregate signature fails and so the verification fails. */
TEST (musig2, incorrect_aggregated_commitment_of_nonces) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    secp256k1_pubkey temp_pubkey;
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    unsigned char tweak[MUSIG2_SCALAR_BYTES] = {7};
    MUSIG2_ERROR err;

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Modify one of the aggregated commitment of nonce of one of the signers.
    assert(secp256k1_xonly_pubkey_tweak_add(ctx, &temp_pubkey, &mps[0].R, tweak));
    assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &mps[0].R, NULL, &temp_pubkey));

    // Aggregation of partial signatures should fail since one of the signatures have incorrect aggregated commitment of nonce.
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_ERR_CMP_R);

    // Verify the aggregated signature with secp256k1_schnorrsig_verify
    // Verification should fail because the aggregation is not complete.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* First state runs correctly, one of the signers will try to sign for previous state, so signing fails for that signer.
 * Consequently, aggregate signature and verification fails.*/
TEST (musig2, previous_state) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps1[NR_SIGNERS];
    musig2_context_signature mps2[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature1[MUSIG2_BYTES];
    unsigned char signature2[MUSIG2_BYTES];
    int i;
    MUSIG2_ERROR err;

    /*** STATE = 0 ****************************************************************************************************/
    // Musig2 proceeds as it is supposed to do for the first state.

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_sign(mcs_list, mps1, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_aggregate_partial_sig(mps1, signature1, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_verify(serialized_pubkey_list, signature1, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    /*** STATE = 1 ****************************************************************************************************/
    // One of the signers will sign for the previous state.
    mcs_list[0].state = 0;

    // Signature generation should fail for the incorrect state.
    err = musig2_sign(&mcs_list[0], &mps2[0], MSG_2, MSG_2_LEN);
    ASSERT_EQ(err, MUSIG2_ERR_CHECK_COMM);

    // The rest of the signers generate their partial signatures.
    for (i = 1; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN);
        ASSERT_EQ(err, MUSIG2_OK);
    }

    // Aggregation should fail.
    err = musig2_aggregate_partial_sig(mps2, signature2, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_ERR_CMP_R);

    // Verification should fail.
    err = musig2_helper_verify(serialized_pubkey_list, signature2, MSG_2, MSG_2_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* One of the signers signs for a future state. Aggregate signature fails due to `R` comparison, and so the verification. */
TEST (musig2, future_state) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // One of the signers will sign for a future state.
    mcs_list[0].state = 1;
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_ERR_CMP_R);

    // Verification should fail since one of the signers; signature used a future state.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* Tweak the secret key of one of the signers before single signature generation. Aggregate verification fails due to non-matching secret/public key. */
TEST (musig2, invalid_signer_key) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Flip a bit of a signer;s keypair.
    mcs_list[0].keypair.data[31] ^= 1;
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the signers; key is incorrect.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* Tweak one of the single signatures before aggregate signature. Verification fails due to tweaked single signature. */
TEST (musig2, invalid_single_signature) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Flip a bit of a single signature.
    mps[0].signature[0] ^= 1;

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the single signatures is incorrect.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* Verification fails for a single signature aggregates public keys with a bit flipped. */
TEST (musig2, aggregate_invalid_public_key) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Flip a bit of one of the signers' public key.
    serialized_pubkey_list[0] ^= 1;
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the signers; public key is incorrect.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);

}

/* Precomputation for more entries fails. */
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

/* Aggregate signature fails for an invalid type single signature. */
TEST (musig2, fail_aggregate_invalid_signature) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Aggregate public keys and batch commitments.
    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Generate partial signatures for `less_signers`.
    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    unsigned char invalid_sig[32] = {0};
    memcpy(  mps[0].signature, invalid_sig, 32);

    // Aggregate partial signatures for `NR_SIGNERS`..
    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_ERR_ADD_PARSIG);

    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);
}

}
