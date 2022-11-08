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
    int i, j, k, l, ind;
    unsigned char serialized_pk_list[NR_SIGNERS * SER_PK_BYTES_COMPRESSED];    // Signers' public key list
    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * SER_PK_BYTES_COMPRESSED];
    secp256k1_pubkey temp_pk;

    size_t ser_size = SER_PK_BYTES_COMPRESSED;
    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        if (musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES))
            printf("* Signer %d initialized.\n", i + 1);
        else
            printf("* Failed to initialize Signer %d.\n", i + 1);

        /* Store the public key of the signer in pk_list */
        assert (secp256k1_keypair_pub(ctx, &temp_pk, &mcs_list[i].keypair));
        secp256k1_ec_pubkey_serialize(ctx, &serialized_pk_list[i * SER_PK_BYTES_COMPRESSED], &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED );

        /* Store the batch commitments of the signer in serialized batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (k * NR_SIGNERS * V + i * V + j) * SER_PK_BYTES_COMPRESSED;
                assert(secp256k1_keypair_pub(ctx, &temp_pk, mcs_list[i].comm_list[l]));
                secp256k1_ec_pubkey_serialize(ctx, &serialized_batch_list[ind], &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED );
            }
        }
    }
    printf("--------------------------------------------------------------------------- \n\n");

    /**** Aggregate the public keys and batch commitments for each signer for all messages ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        if (!musig2_signer_precomputation(&mcs_list[i].mc, serialized_pk_list, serialized_batch_list, NR_SIGNERS, NR_MESSAGES)) {
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
    }



    printf("**** STATE 1 ************************************************************** \n");
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

    musig2_prepare_verifier(ctx, &aggr_pk, serialized_pk_list, NR_SIGNERS);
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (secp256k1_schnorrsig_verify(ctx, signature1, MSG_1, MSG_1_LEN, &aggr_pk))
        printf("\n* Musig2 is VALID!\n");
    else
        printf("\n* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n\n");



    printf("**** STATE 2 ************************************************************** \n");
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
            for (k = i; k < NR_SIGNERS; k++) {
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
    // We could, in principle use `aggr_pk`, but we are just showcasing that
    // the verifier from round 2 might be different to that of round 1, and
    // therefore the key needs to be recomputed.
    secp256k1_xonly_pubkey aggr_pk_2;

    musig2_prepare_verifier(ctx, &aggr_pk_2, serialized_pk_list, NR_SIGNERS);
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (secp256k1_schnorrsig_verify(ctx, signature2, MSG_2, MSG_2_LEN, &aggr_pk_2)) {
        printf("\n* Musig2 is VALID!\n");
    }
    else
        printf("\n* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n");


    /**** Destroy the context ****/
    secp256k1_context_destroy(ctx);

    return 0;
}
