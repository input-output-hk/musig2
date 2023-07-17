extern "C" {

void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

TEST (musig2, pk_list_serialize_deserialize) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    secp256k1_pubkey deser_pubkey_list[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char serde_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i, err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    for (i = 0; i < NR_SIGNERS; i++)
        ASSERT_EQ(secp256k1_ec_pubkey_parse(ctx, &deser_pubkey_list[i], &serialized_pubkey_list[i * ser_size], ser_size), 1);

    for (i = 0; i < NR_SIGNERS; i++)
        secp256k1_ec_pubkey_serialize(ctx, &serde_pubkey_list[i * ser_size], &ser_size, &deser_pubkey_list[i], SECP256K1_EC_COMPRESSED);

    for (i = 0; i < NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED; i++)
        ASSERT_EQ(serde_pubkey_list[i], serialized_pubkey_list[i]);
}

TEST (musig2, commitments_serialize_deserialize) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    secp256k1_pubkey deser_batch_list[NR_SIGNERS * V * NR_MESSAGES];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char serde_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i, err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    for (i = 0; i < NR_SIGNERS * V * NR_MESSAGES; i++)
        ASSERT_EQ(secp256k1_ec_pubkey_parse(ctx, &deser_batch_list[i], &serialized_batch_list[i * ser_size], ser_size), 1);

    for (i = 0; i < NR_SIGNERS * V * NR_MESSAGES; i++)
        secp256k1_ec_pubkey_serialize(ctx, &serde_batch_list[i * ser_size], &ser_size, &deser_batch_list[i], SECP256K1_EC_COMPRESSED);

    for (i = 0; i < NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED; i++)
        ASSERT_EQ(serde_batch_list[i], serialized_batch_list[i]);
}

/* Fuzz a public key then try to generate the aggregate public key */
TEST (musig2, fuzz_pubkey_precomputation) {

    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    MUSIG2_ERROR err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    int fuzz_index = (rand() % NR_SIGNERS) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
    musig2_helper_fuzz_pubkey(&serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);

    err = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_NE(err, MUSIG2_OK);
}

/* Fuzz a public key of a signer after the aggregate public key is generated.
 * Try to verify the aggregate signature that includes a single signature created with an invalid public key.  */
TEST (musig2, fuzz_pubkey_single_signature) {
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

    int fuzz_index = rand() % NR_SIGNERS;
    musig2_helper_fuzz_pubkey(&mcs_list[fuzz_index].keypair.data[MUSIG2_SCALAR_BYTES], MUSIG2_PUBKEY_BYTES_FULL);

    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the signers' public key is incorrect.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_NE(err, MUSIG2_OK);
}

/* Set up the verifier given a list of public keys including a fuzzed public key in it.
 * Try to verify the aggregate signature. */
TEST (musig2, fuzz_pubkey_verify_aggregate) {

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

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    int fuzz_index = (rand() % NR_SIGNERS) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
    musig2_helper_fuzz_pubkey(&serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);

    // Verification should fail since one of the signers' public key is incorrect.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_NE(err, MUSIG2_OK);
}

}
