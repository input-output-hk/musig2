#include <gtest/gtest.h>
extern "C" {
#include "../src/libmusig2.h"
#include "config.h"


static int init_musig2(secp256k1_context *ctx, secp256k1_pubkey *pk_list, secp256k1_pubkey *batch_list, musig2_context_sig *mcs_list, int nr_participants){
    int i, j, k, l;
    int ind;
    int err;

    /**** Initialization ****/
    for (i = 0; i < nr_participants; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        if (err != 1) {
            return err;
        }

        /* Store the public key of the signer in pk_list */
        err = secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair);
        if (err != 1) {
            return err;
        }
        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (nr_participants * V * k) + (j * nr_participants) + i; // the index for the list of collected batches.
                err = secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]);
                if (err != 1) {
                    return err;
                }
            }
        }
    }
    return 1;
}

static int aggregate_pk_batch(secp256k1_pubkey *pk_list, secp256k1_pubkey *batch_list, musig2_context_sig *mcs_list){
    /**** Aggregate the public keys and batch commitments for each signer ****/
    int i;
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    if (cnt != NR_SIGNERS) {
        return cnt;
    }

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i], batch_list);
    if (cnt != NR_SIGNERS) {
        return cnt;
    }
    return 1;
}

static int sign_partial(musig2_context_sig *mcs_list, musig2_partial_signatures* mps, int nr_participants){
    int i, err;
    for (i = 0; i < nr_participants; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], &mps[i], MSG_1, MSG_1_LEN);
        if (err != 1) {
            return err;
        }
    }
    return 1;
}

TEST (musig2, not_enough_signatures) {
#define less_signers (NR_SIGNERS - 1)

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[less_signers];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments.
    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Generate partial signatures for `less_signers`.
    err = sign_partial(mcs_list, mps, less_signers);
    ASSERT_EQ(err, 1);

    // Aggregate partial signatures for `NR_SIGNERS`.
    // Aggregation should fail since there are fewer signatures than the registered signers.
    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, -2);

}

TEST (musig2, non_corresponding_signers) {
#define nr_participants  (NR_SIGNERS + 1) // We define more signers.

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[nr_participants];    // Signers' public key list
    secp256k1_pubkey batch_list[nr_participants * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[nr_participants]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[NR_SIGNERS];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    // Init signers, store public keys, create batch commitments for `nr_participants`.
    err = init_musig2(ctx, pk_list, batch_list, mcs_list, nr_participants);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
    err = aggregate_pk_batch(pk_list, batch_list, &mcs_list[1]);
    ASSERT_EQ(err, 1);

    // Generate partial signatures for `mcs_list[1], ..., mcs_list[NR_SIGNERS]`.
    err = sign_partial(&mcs_list[1], mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Aggregate partial signatures for ``mcs_list[0], ..., mcs_list[NR_SIGNERS - 1]`.
    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Verify the aggregated signature with secp256k1_schnorrsig_verify
    // Verification should fail since the aggregated signature does not correspond to the aggregated public key.
    err = musig2_ver_musig(ctx, signature, mca.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, incorrect_aggregated_commitment_of_nonces) {

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[NR_SIGNERS];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    // Init signers, store public keys, generate batch commitments for `NR_SIGNERS`.
    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Aggregate public keys and batch commitments.
    err = sign_partial(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Modify one of the aggregated commitment of nonce of one of the signers.
    assert(secp256k1_ec_pubkey_negate(ctx, &mps[0].R));

    // Aggregation of partial signatures should fail since one of the signatures have incorrect aggregated commitment of nonce.
    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, -1);

    // Verify the aggregated signature with secp256k1_schnorrsig_verify
    // Verification should fail because the aggregation is not complete.
    err = musig2_ver_musig(ctx, signature, mca.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, previous_state) {

    int i, err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps1[NR_SIGNERS];
    musig2_partial_signatures mps2[NR_SIGNERS];
    musig2_context mca1;
    musig2_context mca2;
    unsigned char signature1[SCH_SIG_BYTES];
    unsigned char signature2[SCH_SIG_BYTES];
    /******************************************************************************************************************/

    /*** STATE = 0 ****************************************************************************************************/
    // Musig2 proceeds as it is supposed to do for the first state.

    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    err = sign_partial(mcs_list, mps1, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(ctx, &mca1, mps1, pk_list, signature1, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_ver_musig(ctx, signature1, mca1.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 1);
    /******************************************************************************************************************/

    /*** STATE = 1 ****************************************************************************************************/
    // Aggregate the public keys and the batch commitments for `STATE = 1`.
    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // One of the signers will sign for the previous state.
    mcs_list[0].mc->state = 0;

    // Signature generation should fail for the incorrect state.
    err = musig2_sign(&mcs_list[0], &mps2[0], MSG_2, MSG_2_LEN);
    ASSERT_EQ(err, -1);

    // The rest of the signers generate their partial signatures.
    for (i = 1; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN);
        ASSERT_EQ(err, 1);
        memcpy(mps2[i].R.data, mcs_list[i].mc->aggr_R.data, PK_BYTES);
    }

    // Aggregation should fail.
    err = musig2_aggregate_partial_sig(ctx, &mca2, mps2, pk_list, signature2, NR_SIGNERS);
    ASSERT_EQ(err, -1);

    // Verification should fail.
    err = musig2_ver_musig(ctx, signature2, mca2.aggr_pk, MSG_2, MSG_2_LEN);
    ASSERT_EQ(err, 0);
    /******************************************************************************************************************/

}

TEST (musig2, future_state) {

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[NR_SIGNERS];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // One of the signers will sign for a future state.
    mcs_list[0].mc->state = 1;
    err = sign_partial(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Verification should fail since one of the signers' signature used a future state.
    err = musig2_ver_musig(ctx, signature, mca.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, invalid_signer_key) {

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[NR_SIGNERS];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    // Flip a bit of a signer's keypair.
    mcs_list[0].keypair.data[31] ^= 1;
    err = sign_partial(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Verification should fail since one of the signers' key is incorrect.
    err = musig2_ver_musig(ctx, signature, mca.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, invalid_single_signature) {

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[NR_SIGNERS];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    err = sign_partial(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Flip a bit of a single signature.
    mps[0].sig[0] ^= 1;

    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Verification should fail since one of the single signatures is incorrect.
    err = musig2_ver_musig(ctx, signature, mca.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, aggregate_invalid_public_key) {

    int err;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    musig2_partial_signatures mps[NR_SIGNERS];
    musig2_context mca;
    unsigned char signature[SCH_SIG_BYTES];

    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Flip a bit of one of the signers' public key.
    pk_list[0].data[0] ^= 1;
    err = aggregate_pk_batch(pk_list, batch_list, mcs_list);
    ASSERT_EQ(err, 1);

    err = sign_partial(mcs_list, mps, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    err = musig2_aggregate_partial_sig(ctx, &mca, mps, pk_list, signature, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    // Verification should fail since one of the signers' public key is incorrect.
    err = musig2_ver_musig(ctx, signature, mca.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, pk_list_serialize_deserialize) {

    int i, err;
    size_t ser_size = 33; // Size of the compressed ec pubkey of secp256k1.
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    secp256k1_pubkey serde_pk_list[NR_SIGNERS];
    unsigned char serialized_pk_list[ser_size * NR_SIGNERS];

    err = init_musig2(ctx, pk_list, batch_list, mcs_list, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    for (i = 0; i < NR_SIGNERS; i++)
        secp256k1_ec_pubkey_serialize(ctx, &serialized_pk_list[i * ser_size], &ser_size, &pk_list[i], SECP256K1_EC_COMPRESSED );

    for (i = 0; i < NR_SIGNERS; i++)
        assert(secp256k1_ec_pubkey_parse(ctx, &serde_pk_list[i], &serialized_pk_list[i * ser_size], ser_size ));

    for (i = 0; i < NR_SIGNERS; i++){
        err = secp256k1_ec_pubkey_cmp(ctx, &pk_list[i], &serde_pk_list[i]);
        ASSERT_EQ(err, 0);
    }
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
        if (musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES)) {
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
        assert(secp256k1_ec_pubkey_parse(ctx, &deserialized_batch_list[i], &serialized_batch_list[i * ser_size], ser_size ));

    for (i = 0; i < NR_SIGNERS; i++){
        err = secp256k1_ec_pubkey_cmp(ctx, &batch_list[i], &deserialized_batch_list[i]);
        ASSERT_EQ(err, 0);
    }
}


}

int main(int argc, char* argv[]){
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
