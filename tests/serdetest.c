extern "C" {
#include "../src/libmusig2.h"

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
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    secp256k1_pubkey pubkey;
    MUSIG2_ERROR res;
    int err;

    res = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(res, MUSIG2_OK);

    int fuzz_index = (rand() % NR_SIGNERS) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
    musig2_helper_fuzz_data(&serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);

    res = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);

    switch(res){
        case MUSIG2_ERR_PARSE_PK:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 0);
            break;
        case MUSIG2_ERR_AGGR_PK:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 1);
            break;
        default:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 1);

            err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_OK);

            err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_OK);

            err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_INVALID);
    }
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

    // Fuzz a public key of a randomly selected signer.
    int fuzz_index = rand() % NR_SIGNERS;
    musig2_helper_fuzz_data(&mcs_list[fuzz_index].keypair.data[MUSIG2_SCALAR_BYTES], MUSIG2_PUBKEY_BYTES_FULL);

    err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    // Verification should fail since one of the signers' signature is generated with an incorrect public key.
    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);
}

/* Set up the verifier given a list of public keys including a fuzzed public key in it.
 * Try to verify the aggregate signature. */
TEST (musig2, fuzz_pubkey_verify_aggregate) {

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

    err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_OK);

    int fuzz_index = (rand() % NR_SIGNERS) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
    musig2_helper_fuzz_data(&serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);

    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);

    switch(err){
        case MUSIG2_ERR_PARSE_PK:
            secp256k1_pubkey pubkey;
            int res;
            res = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_pubkey_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(res, 0);
            break;
        case MUSIG2_INVALID:
            int cmp_res;
            musig2_aggr_pubkey aggr_pubkey, fuzz_aggr_pubkey;
            assert(musig2_prepare_verifier(&aggr_pubkey, serialized_pubkey_list, NR_SIGNERS));
            assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &fuzz_aggr_pubkey, NULL, &mcs_list[0].mc.aggr_pubkey));
            cmp_res = secp256k1_xonly_pubkey_cmp(ctx, &fuzz_aggr_pubkey, &aggr_pubkey);
            ASSERT_NE(cmp_res, 0);
            break;
        default:
            ASSERT_NE(err, MUSIG2_OK);
    }
}

/* Fuzz a commitment then try to generate the aggregate R */
TEST (musig2, fuzz_commitment_precomputation) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
    unsigned char signature[MUSIG2_BYTES];
    secp256k1_pubkey pubkey;
    MUSIG2_ERROR res;
    int err;

    res = musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
    ASSERT_EQ(res, MUSIG2_OK);

    int fuzz_index = (rand() % (NR_SIGNERS * V));
    musig2_helper_fuzz_data(&serialized_batch_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);

    res = musig2_helper_precomputation(serialized_pubkey_list, serialized_batch_list, mcs_list, NR_SIGNERS);

    switch(res){
        case MUSIG2_ERR_PARSE_COMM:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_batch_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 0);
            break;
        case MUSIG2_ERR_AGGR_R:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_batch_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 1);
            break;
        case MUSIG2_OK:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_batch_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 1);

            err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_OK);

            err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_ERR_CMP_R);
            break;
        default:
            err = secp256k1_ec_pubkey_parse(ctx, &pubkey, &serialized_batch_list[fuzz_index], MUSIG2_PUBKEY_BYTES_COMPRESSED);
            ASSERT_EQ(err, 1);

            err = musig2_helper_sign(mcs_list, mps, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_OK);

            err = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_OK);

            err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
            ASSERT_EQ(err, MUSIG2_INVALID);
    }
}

/* Set up the verifier given a signature with fuzzed aggregate R.
 * Try to verify the aggregate signature. */
TEST (musig2, fuzz_commitment_verify_aggregate) {

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

    musig2_helper_fuzz_data(&signature[0], MUSIG2_AGGR_PUBKEY_BYTES);

    err = musig2_helper_verify(serialized_pubkey_list, signature, MSG_1, MSG_1_LEN, NR_SIGNERS);
    ASSERT_EQ(err, MUSIG2_INVALID);
}

}
