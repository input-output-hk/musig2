#include "src/libmusig2.h"
#include "tests/config.h"


int main(void) {

    unsigned char randomize[MUSIG2_SCALAR_BYTES];
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

    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    musig2_partial_signature mps1[NR_SIGNERS];
    musig2_partial_signature mps2[NR_SIGNERS];

    unsigned char serialized_pk_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED ];    // Signers' public key list
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
    unsigned char signature1[MUSIG2_BYTES];
    unsigned char signature2[MUSIG2_BYTES];

    secp256k1_xonly_pubkey aggr_pk_1;
    secp256k1_xonly_pubkey aggr_pk_2;
    secp256k1_pubkey temp_pk;

    MUSIG2_API res;
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i, j, k, l, ind;

    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", NR_SIGNERS);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t\t: %d \n", NR_MESSAGES);
    printf("--------------------------------------------------------------------------- \n\n");


    /**** Initialization ****/
    printf("\n______ Initialize Signers _________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        res = musig2_init_signer(&mcs_list[i], ctx, NR_MESSAGES);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));

        /* Store the public key of the signer in pk_list */
        assert (secp256k1_keypair_pub(ctx, &temp_pk, &mcs_list[i].keypair));
        secp256k1_ec_pubkey_serialize(ctx, &serialized_pk_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED );

        /* Store the batch commitments of the signer in serialized batch_list */
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++) {
            for (j = 0; j < V; j++, l++) {
                ind = (k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
                assert(secp256k1_keypair_pub(ctx, &temp_pk, mcs_list[i].comm_list[l]));
                secp256k1_ec_pubkey_serialize(ctx, &serialized_batch_list[ind], &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED );
            }
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer for all messages ****/
    printf("\n______ Precomputation _____________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        res = musig2_signer_precomputation(&mcs_list[i].mc, serialized_pk_list, serialized_batch_list, NR_SIGNERS, NR_MESSAGES);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));
        if (res != MUSIG2_OK) {
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
    }
    printf("--------------------------------------------------------------------------- \n\n");


    /************** STATE 1 **************/
    /**** Signature ****/
    printf("\nState 1: Partial Signatures _______________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        res = musig2_sign(&mcs_list[i], &mps1[i], MSG_1, MSG_1_LEN);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));
        if (res != MUSIG2_OK){
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
    }

    /**** Aggregation ****/
    printf("\nState 1: Aggregate ________________________________________________________ \n");
    res = musig2_aggregate_partial_sig(ctx, mps1, signature1, NR_SIGNERS);
    printf("  Signature %s", musig2_error_str(res));
    if (res == MUSIG2_OK){
        printf("  S .... ");
        print_hex(&signature1[MUSIG2_PUBKEY_BYTES], MUSIG2_SCALAR_BYTES);
        printf("  R .... ");
        print_hex(signature1, MUSIG2_PUBKEY_BYTES);
    }
    else {
        for (k = 0; k < NR_SIGNERS; k++)
            musig2_context_sig_free(&mcs_list[k]);
        return -1;
    }

    /**** Verification ****/
    printf("\nState 1: Verification _____________________________________________________ \n");
    res = musig2_prepare_verifier(ctx, &aggr_pk_1, serialized_pk_list, NR_SIGNERS);
    printf("  Prepare   %s", musig2_error_str(res));
    if (res == MUSIG2_OK) {
        /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
        if (secp256k1_schnorrsig_verify(ctx, signature1, MSG_1, MSG_1_LEN, &aggr_pk_1))
            printf("  Musig2 is VALID!\n");
        else
            printf("  Failed to verify Musig2!\n");
    }
    else {
        return -1;
    }
    printf("--------------------------------------------------------------------------- \n\n");


    /************** STATE 2 **************/
    /**** Signature ****/
    printf("\nState 2: Partial Signatures _______________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        res = musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));
        if (res != MUSIG2_OK){
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
    }

    /**** Aggregation ****/
    printf("\nState 2: Aggregate ________________________________________________________ \n");
    res = musig2_aggregate_partial_sig(ctx, mps2, signature2, NR_SIGNERS);
    printf("  Signature %s", musig2_error_str(res));
    if (res == MUSIG2_OK){
        printf("  S .... ");
        print_hex(&signature2[MUSIG2_PUBKEY_BYTES], MUSIG2_SCALAR_BYTES);
        printf("  R .... ");
        print_hex(signature2, MUSIG2_PUBKEY_BYTES);
    }
    else {
        for (k = 0; k < NR_SIGNERS; k++)
            musig2_context_sig_free(&mcs_list[k]);
        return -1;
    }

    /**** Verification ****/
    printf("\nState 2: Verification _____________________________________________________ \n");
    res = musig2_prepare_verifier(ctx, &aggr_pk_2, serialized_pk_list, NR_SIGNERS);
    printf("  Prepare   %s", musig2_error_str(res));
    if (res == MUSIG2_OK) {
        /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
        if (secp256k1_schnorrsig_verify(ctx, signature2, MSG_2, MSG_2_LEN, &aggr_pk_2))
            printf("  Musig2 is VALID!\n");
        else
            printf("  Failed to verify Musig2!\n");
    }
    else {
        return -1;
    }
    printf("--------------------------------------------------------------------------- \n\n");


    /**** Destroy the context ****/
    secp256k1_context_destroy(ctx);

    return 0;
}
