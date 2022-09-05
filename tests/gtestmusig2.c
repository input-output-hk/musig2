#include <gtest/gtest.h>
extern "C" {
#include "../src/libmusig2.h"
#ifndef NR_SIGS
#define NR_SIGS 3
#endif
#include "config.h"



TEST (musig2, not_enough_signatures) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);


    int i, j, k, l;
    int ind;
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    int err;

    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        ASSERT_EQ(err, 1);

        /* Store the public key of the signer in pk_list */
        err = secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair);
        ASSERT_EQ(err, 1);

        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (NR_SIGNERS * V * k) + (j * NR_SIGNERS) + i; // the index for the list of collected batches.
                err = secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]);
                ASSERT_EQ(err, 1);
            }
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer ****/
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    ASSERT_EQ(cnt, NR_SIGNERS);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i], batch_list);
    ASSERT_EQ(cnt, NR_SIGNERS);


    /**** Signature ****/
    musig2_partial_signatures mps1[NR_SIGS];

    for (i = 0; i < NR_SIGS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], MSG_1, MSG_1_LEN, mps1[i].sig);
        ASSERT_EQ(err, 1);
        memcpy(mps1[i].R.data, mcs_list[i].mc->aggr_R.data, PK_BYTES);
    }

    /**** Aggregation ****/
    musig2_context mca1;
    unsigned char signature1[SCH_SIG_BYTES];
    err = musig2_aggregate_partial_sig(ctx, &mca1, mps1, pk_list, signature1, NR_SIGS);
    ASSERT_EQ(err, 1);

    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    err = musig2_ver_musig(ctx, signature1, mca1.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, non_corresponding_signers) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);


    int i, j, k, l;
    int ind;
    int nr_participants = NR_SIGNERS + 1;
    secp256k1_pubkey pk_list[nr_participants];    // Signers' public key list
    secp256k1_pubkey batch_list[nr_participants * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[nr_participants]; // Array that holds NR_SIGNERS musig2_context_sig

    int err;


    /**** Initialization ****/
    for (i = 0; i < nr_participants; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        ASSERT_EQ(err, 1);

        /* Store the public key of the signer in pk_list */
        err = secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair);
        ASSERT_EQ(err, 1);

        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (nr_participants * V * k) + (j * nr_participants) + i; // the index for the list of collected batches.
                err = secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]);
                ASSERT_EQ(err, 1);
            }
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer ****/
    int cnt = 0;
    for (i = 1; i < nr_participants; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    ASSERT_EQ(cnt, NR_SIGNERS);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i + 1], batch_list);
    ASSERT_EQ(cnt, NR_SIGNERS);


    /**** Signature ****/
    musig2_partial_signatures mps1[NR_SIGNERS];

    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i + 1], MSG_1, MSG_1_LEN, mps1[i].sig);
        ASSERT_EQ(err, 1);
        memcpy(mps1[i].R.data, mcs_list[i + 1].mc->aggr_R.data, PK_BYTES);
    }

    /**** Aggregation ****/
    musig2_context mca1;
    unsigned char signature1[SCH_SIG_BYTES];
    err = musig2_aggregate_partial_sig(ctx, &mca1, mps1, pk_list, signature1, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    err = musig2_ver_musig(ctx, signature1, mca1.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, incorrect_nonce) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);


    int i, j, k, l;
    int ind;
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    int err;


    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        ASSERT_EQ(err, 1);

        /* Store the public key of the signer in pk_list */
        err = secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair);
        ASSERT_EQ(err, 1);

        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (NR_SIGNERS * V * k) + (j * NR_SIGNERS) + i; // the index for the list of collected batches.
                err = secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]);
                ASSERT_EQ(err, 1);
            }
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer ****/
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    ASSERT_EQ(cnt, NR_SIGNERS);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i], batch_list);
    ASSERT_EQ(cnt, NR_SIGNERS);


    /**** Signature ****/
    musig2_partial_signatures mps1[NR_SIGNERS];

    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], MSG_1, MSG_1_LEN, mps1[i].sig);
        ASSERT_EQ(err, 1);
        memcpy(mps1[i].R.data, mcs_list[i].mc->aggr_R.data, PK_BYTES);
    }

    assert(secp256k1_ec_pubkey_negate(ctx, &mps1[0].R));

    /**** Aggregation ****/
    musig2_context mca1;
    unsigned char signature1[SCH_SIG_BYTES];
    err = musig2_aggregate_partial_sig(ctx, &mca1, mps1, pk_list, signature1, NR_SIGNERS);
    ASSERT_EQ(err, -1);

    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    err = musig2_ver_musig(ctx, signature1, mca1.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, incorrect_state) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);


    int i, j, k, l;
    int ind;
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    int err;

    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        ASSERT_EQ(err, 1);

        /* Store the public key of the signer in pk_list */
        err = secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair);
        ASSERT_EQ(err, 1);

        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (NR_SIGNERS * V * k) + (j * NR_SIGNERS) + i; // the index for the list of collected batches.
                err = secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]);
                ASSERT_EQ(err, 1);
            }
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer ****/
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    ASSERT_EQ(cnt, NR_SIGNERS);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i], batch_list);
    ASSERT_EQ(cnt, NR_SIGNERS);


    /**** Signature ****/
    musig2_partial_signatures mps1[NR_SIGNERS];

    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], MSG_1, MSG_1_LEN, mps1[i].sig);
        ASSERT_EQ(err, 1);
        memcpy(mps1[i].R.data, mcs_list[i].mc->aggr_R.data, PK_BYTES);
    }

    /**** Aggregation ****/
    musig2_context mca1;
    unsigned char signature1[SCH_SIG_BYTES];
    err = musig2_aggregate_partial_sig(ctx, &mca1, mps1, pk_list, signature1, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    err = musig2_ver_musig(ctx, signature1, mca1.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 1);







    /**** Aggregate the public keys and batch commitments for each signer ****/
    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    ASSERT_EQ(cnt, NR_SIGNERS);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i], batch_list);
    ASSERT_EQ(cnt, NR_SIGNERS);


    /**** Signature ****/
    musig2_partial_signatures mps2[NR_SIGNERS];

    mcs_list[0].mc->state = 0;
    err = musig2_sign(&mcs_list[0], MSG_2, MSG_2_LEN, mps2[0].sig);
    ASSERT_EQ(err, -1);
    memcpy(mps2[0].R.data, mcs_list[0].mc->aggr_R.data, PK_BYTES);


    for (i = 1; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], MSG_2, MSG_2_LEN, mps2[i].sig);
        ASSERT_EQ(err, 1);
        memcpy(mps2[i].R.data, mcs_list[i].mc->aggr_R.data, PK_BYTES);
    }

    /**** Aggregation ****/
    musig2_context mca2;
    unsigned char signature2[SCH_SIG_BYTES];
    err = musig2_aggregate_partial_sig(ctx, &mca1, mps2, pk_list, signature2, NR_SIGNERS);
    ASSERT_EQ(err, -1);

    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    err = musig2_ver_musig(ctx, signature2, mca2.aggr_pk, MSG_2, MSG_2_LEN);
    ASSERT_EQ(err, 0);

}

TEST (musig2, invalid_partial_signature) {

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);


    int i, j, k, l;
    int ind;
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    int err;


    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        ASSERT_EQ(err, 1);

        /* Store the public key of the signer in pk_list */
        err = secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair);
        ASSERT_EQ(err, 1);

        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (NR_SIGNERS * V * k) + (j * NR_SIGNERS) + i; // the index for the list of collected batches.
                err = secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i].comm_list[l]);
                ASSERT_EQ(err, 1);
            }
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer ****/
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(mcs_list[i].mc, pk_list, NR_SIGNERS);
    ASSERT_EQ(cnt, NR_SIGNERS);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i], batch_list);
    ASSERT_EQ(cnt, NR_SIGNERS);


    /**** Signature ****/
    musig2_partial_signatures mps1[NR_SIGNERS];
    mcs_list[0].keypair.data[31] = mcs_list[0].keypair.data[31] ^ 1;

    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], MSG_1, MSG_1_LEN, mps1[i].sig);
        ASSERT_EQ(err, 1);
        memcpy(mps1[i].R.data, mcs_list[i].mc->aggr_R.data, PK_BYTES);
    }

    /**** Aggregation ****/
    musig2_context mca1;
    unsigned char signature1[SCH_SIG_BYTES];
    err = musig2_aggregate_partial_sig(ctx, &mca1, mps1, pk_list, signature1, NR_SIGNERS);
    ASSERT_EQ(err, 1);

    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    err = musig2_ver_musig(ctx, signature1, mca1.aggr_pk, MSG_1, MSG_1_LEN);
    ASSERT_EQ(err, 0);

}



}

int main(int argc, char* argv[]){
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

