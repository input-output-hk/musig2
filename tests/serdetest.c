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

TEST (musig2, fuzz_test_pk_list) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    secp256k1_pubkey deser_pubkey_list[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' serialized public key list
    unsigned char serde_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // A list of public keys serialized from invalid public keys.
    unsigned char fuzz_ser_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // A list of incorrect serialized public keys.
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i, err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Assign random bytes
    for (i = 0; i < NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED; i++)
        fuzz_ser_pubkey_list[i] = rand();

    // Try to parse invalid public keys
    for (i = 0; i < NR_SIGNERS; i++) {
        ASSERT_NE(secp256k1_ec_pubkey_parse(ctx, &deser_pubkey_list[i], &fuzz_ser_pubkey_list[i * ser_size], ser_size), 1);
        // The header byte of a valid pubkey is 0x02 or 0x03. This assignment is done to call secp256k1_ec_pubkey_serialize below.
        deser_pubkey_list[i].data[0] = '\x02';
    }
    // Serialize invalid public keys
    for (i = 0; i < NR_SIGNERS; i++)
        secp256k1_ec_pubkey_serialize(ctx, &serde_pubkey_list[i * ser_size], &ser_size, &deser_pubkey_list[i], SECP256K1_EC_COMPRESSED);

    for (i = 0; i < NR_SIGNERS; i++)
        ASSERT_NE(musig2_helper_compare_ser_pubkey(&serde_pubkey_list[i * ser_size], &serialized_pubkey_list[i * ser_size], ser_size), 1);
}

TEST (musig2, fuzz_test_commitments) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    secp256k1_pubkey deser_batch_list[NR_SIGNERS * V * NR_MESSAGES];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' serialized public key list
    unsigned char serde_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED]; // A list of commitments serialized from invalid commitments.
    unsigned char fuzz_ser_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED]; // A list of incorrect serialized commitments.
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i, err;

    err = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Assign random bytes
    for (i = 0; i < NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED; i++)
        fuzz_ser_batch_list[i] = rand();

    // Try to parse invalid commitments
    for (i = 0; i < NR_SIGNERS * V * NR_MESSAGES; i++) {
        ASSERT_NE(secp256k1_ec_pubkey_parse(ctx, &deser_batch_list[i], &fuzz_ser_batch_list[i * ser_size], ser_size), 1);
        // The header byte of a valid pubkey is 0x02 or 0x03. This assignment is done to call secp256k1_ec_pubkey_serialize below.
        deser_batch_list[i].data[0] = '\x02';
    }

    // Serialize invalid commitments
    for (i = 0; i < NR_SIGNERS * V * NR_MESSAGES; i++)
        secp256k1_ec_pubkey_serialize(ctx, &serde_batch_list[i * ser_size], &ser_size, &deser_batch_list[i], SECP256K1_EC_COMPRESSED);

    for (i = 0; i < NR_MESSAGES * NR_SIGNERS * V; i++)
        ASSERT_NE(musig2_helper_compare_ser_pubkey(&serde_batch_list[i * ser_size], &serialized_batch_list[i * ser_size], ser_size), 1);
}
}
