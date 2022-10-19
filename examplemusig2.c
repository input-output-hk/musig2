#include "src/libmusig2.h"
#include "tests/config.h"



int main(void) {

    unsigned char randomize[SCALAR_BYTES];
    int return_val;

    /* Initialize the secp256k1_context to operate on secp256k1 curve.
     * MuSig2 library generates a multi-signature in the form of the schnorr signature obtained by secp256k1_schnorrsig_sign32
     * with the library functions of libsecp256k1, however we do not use secp256k1_schnorrsig_sign32 function.
     * Thus, we create the context with only SECP256K1_CONTEXT_VERIFY flag instead of using
     * SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY. */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }

    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", NR_SIGNERS);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t\t: %d \n", NR_MESSAGES);
    printf("--------------------------------------------------------------------------- \n");

    /**** musig2test parameters ****/
    int i, j, k, l;
    secp256k1_pubkey pk_list[NR_SIGNERS];    // Signers' public key list
    secp256k1_pubkey batch_list[NR_MESSAGES][NR_SIGNERS][V];   // Stores the batches of signers
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig


    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        if (musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES))
            printf("* Signer %d initialized.\n", i + 1);
        else
            printf("* Failed to initialize Signer %d.\n", i + 1);

        /* Store the public key of the signer in pk_list */
        assert (secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i].keypair));

        /* Store the batch commitments of the signer in batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                assert(secp256k1_keypair_pub(ctx, &batch_list[k][i][j], mcs_list[i].comm_list[l]));
            }
        }
    }
    printf("--------------------------------------------------------------------------- \n\n");



    printf("**** STATE 1 ************************************************************** \n");

    // todo: idea: would  be good to 'prepare' signers for all the batch. This prepare
    // function would compute the aggr pk, and all agr R values.
    /**** Aggregate the public keys and batch commitments for each signer ****/
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_pubkey(&mcs_list[i].mc, pk_list, NR_SIGNERS);
    printf("* %d signers aggregated public key.\n", cnt);

    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i].mc, batch_list[mcs_list[i].state]);
    printf("* %d signers aggregated commitment.\n", cnt);


    /**** Signature ****/
    printf("\n* Partial Signatures: \n");

    musig2_partial_signature mps1[NR_SIGNERS];

    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (musig2_sign(&mcs_list[i], &mps1[i], MSG_1, MSG_1_LEN)){
            printf(" S%d: ", i + 1);
            print_hex(mps1[i].sig, SCALAR_BYTES);
        }
        else {
            printf("* Failed to generate signature for Signer %d.\n", i + 1);
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
    }


    /**** Aggregation ****/
    printf("\n* Aggregate signature: \n");

    unsigned char signature1[SCH_SIG_BYTES];

    if (musig2_aggregate_partial_sig(ctx, mps1, signature1, NR_SIGNERS)){
        printf(" S: ");
        print_hex(&signature1[XONLY_BYTES], SCALAR_BYTES);
        printf(" R: ");
        print_hex(signature1, XONLY_BYTES);
    }
    else {
        printf("* Failed to aggregate signatures.\n");
        for (k = 0; k < NR_SIGNERS; k++) {
            musig2_context_sig_free(&mcs_list[k]);
        }
        return -1;
    }


    /**** Verification ****/
    secp256k1_xonly_pubkey aggr_pk;

    musig2_prepare_verifier(ctx, &aggr_pk, pk_list, NR_SIGNERS);
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (secp256k1_schnorrsig_verify(ctx, signature1, MSG_1, MSG_1_LEN, &aggr_pk))
        printf("\n* Musig2 is VALID!\n");
    else
        printf("\n* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n\n");

    printf("**** STATE 2 ************************************************************** \n");

    /**** Aggregate batch commitments for each signer ****/
    // todo: with the idea commented in STATE 1, the R computation (or initialisation) needs to be
    // computed only once per message batch. This makes sense because it is not message dependent.
    cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_aggregate_R(&mcs_list[i].mc, batch_list[mcs_list->state]);
    printf("* %d signers aggregated commitment.\n", cnt);


    /**** Signature ****/
    printf("\n* Partial Signatures: \n");

    musig2_partial_signature mps2[NR_SIGNERS];

    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN)){
            printf(" S%d: ", i + 1);
            print_hex(mps2[i].sig, SCALAR_BYTES);
            musig2_context_sig_free(&mcs_list[i]);
        }
        else {
            printf("* Failed to generate signature for Signer %d.\n", i + 1);
            for (int k = i; k < NR_SIGNERS; k++) {
                musig2_context_sig_free(&mcs_list[k]);
            }
            return -1;
        }
    }


    /**** Aggregation ****/
    printf("\n* Aggregate signature: \n");

    unsigned char signature2[SCH_SIG_BYTES];

    if (musig2_aggregate_partial_sig(ctx, mps2, signature2, NR_SIGNERS)){
        printf(" S: ");
        print_hex(&signature2[XONLY_BYTES], SCALAR_BYTES);
        printf(" R: ");
        print_hex(signature2, XONLY_BYTES);
    }
    else {
        printf("* Failed to aggregate signatures.\n");
        return -1;
    }


    /**** Verification ****/
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (secp256k1_schnorrsig_verify(ctx, signature2, MSG_2, MSG_2_LEN, &aggr_pk)) {
        printf("\n* Musig2 is VALID!\n");
    }
    else
        printf("\n* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n");


    /**** Destroy the context ****/
    secp256k1_context_destroy(ctx);

    return 0;
}
