extern "C" {


TEST (musig2, pk_list_serialize_deserialize) {

    int i, err;
    size_t ser_size = 33; // Size of the compressed ec pubkey of secp256k1.
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    unsigned char serialized_pk_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    secp256k1_pubkey serde_pk_list[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];

    err = init_musig2(ctx, serialized_pk_list, serialized_batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    for (i = 0; i < NR_SIGNERS; i++)
        assert(secp256k1_ec_pubkey_parse(ctx, &serde_pk_list[i], &serialized_pk_list[i * ser_size], ser_size));

//    for (i = 0; i < NR_SIGNERS; i++){
//        err = secp256k1_ec_pubkey_cmp(ctx, &pk_list[i], &serde_pk_list[i]);
//        ASSERT_EQ(err, 0);
//    }
}

TEST (musig2, commitments_serialize_deserialize) {

    int i, err;
    size_t ser_size = 33; // Size of the compressed ec pubkey of secp256k1.
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    secp256k1_pubkey deserialized_batch_list[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_SIGNERS * NR_MESSAGES * ser_size * V];

    int j, k, l, ind;
    for (i = 0; i < NR_SIGNERS; i++) {
        if (musig2_init_signer(&mcs_list[i], NR_MESSAGES)) {
// Store the public key of the signer in pk_list
            assert (secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair));

// Store the batch commitments of the signer in batch_list
            l = 0; // the index of the signer's commitment list.
            for (k = 0; k < NR_MESSAGES; k++) {
                for (j = 0; j < V; j++, l++) {
                    ind = (NR_SIGNERS * V * k) + (j * NR_SIGNERS) + i; // the index for the list of collected batches.
                    assert(secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]));
// Serialize the commitments and store in serialized_batch_list.
                    secp256k1_ec_pubkey_serialize(ctx, &serialized_batch_list[ind * ser_size], &ser_size,
                                                  &batch_list[ind], SECP256K1_EC_COMPRESSED);
                }
            }
        }
    }

    for (i = 0; i < NR_SIGNERS; i++)
        assert(secp256k1_ec_pubkey_parse(ctx, &deserialized_batch_list[i], &serialized_batch_list[i * ser_size], ser_size));

    for (i = 0; i < NR_SIGNERS; i++) {
        err = secp256k1_ec_pubkey_cmp(ctx, &batch_list[i], &deserialized_batch_list[i]);
        ASSERT_EQ(err, 0);
    }
}
}