#include "src/libmusig2.h"
#include "tests/config.h"



int main(void) {

    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    musig2_partial_signature mps1[NR_SIGNERS];  // Array of partial signatures for the first state
    musig2_partial_signature mps2[NR_SIGNERS];  // Array of partial signatures for the second state

    musig2_aggr_pubkey aggr_pk_1;    // Aggregate public key of the first state
    musig2_aggr_pubkey aggr_pk_2;    // Aggregate public key of the second state

    unsigned char serialized_pk_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Serialized public keys of signers
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED]; // Serialized batch commitments

    unsigned char signature_1[MUSIG2_BYTES];    // Final signature for the first state
    unsigned char signature_2[MUSIG2_BYTES];    // Final signature for the second state

    int i, j, k, l;


    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", NR_SIGNERS);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t\t: %d \n", NR_MESSAGES);
    printf("--------------------------------------------------------------------------- \n");



    /**** Initialization ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        if (musig2_init_signer(&mcs_list[i], NR_MESSAGES)) {
            printf("* Signer %d initialized.\n", i + 1);
        }
        else {
            printf("* Failed to initialize Signer %d.\n", i + 1);
        }
    }
    printf("--------------------------------------------------------------------------- \n\n");

    /**** Registration ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        unsigned char serialized_comm_list[V * NR_MESSAGES][MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serialized_pubkey[MUSIG2_PUBKEY_BYTES_COMPRESSED];

        if (musig2_serialise_shareable_context(&mcs_list[i], serialized_pubkey, serialized_comm_list)){
            printf("* Signer %d registered.\n", i + 1);
            memcpy(&serialized_pk_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_pubkey, MUSIG2_PUBKEY_BYTES_COMPRESSED);
            l = 0; // the index of the signer's commitment list.
            for (k = 0; k < NR_MESSAGES; k++)
                for (j = 0; j < V; j++, l++)
                    memcpy(&serialized_batch_list[(k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_comm_list[l],
                           MUSIG2_PUBKEY_BYTES_COMPRESSED);

        }
        else {
            printf("* Failed to register Signer %d.\n", i + 1);
        }
    }
    printf("--------------------------------------------------------------------------- \n\n");

    /**** Aggregate the public keys and batch commitments for each signer for all messages ****/
    for (i = 0; i < NR_SIGNERS; i++) {
        if (!musig2_signer_precomputation(&mcs_list[i].mc, serialized_pk_list, serialized_batch_list, NR_SIGNERS, NR_MESSAGES)) {
            return -1;
        }
    }


    printf("**** STATE 1 ************************************************************** \n");
    /**** Signature ****/
    printf("\n* Partial Signatures: \n");


    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (musig2_sign(&mcs_list[i], &mps1[i], MSG_1, MSG_1_LEN)){
            printf(" S%d: ", i + 1);
            print_hex(mps1[i].sig, MUSIG2_PARSIG_BYTES);
        }
        else {
            printf("* Failed to generate signature for Signer %d.\n", i + 1);
            return -1;
        }
    }


    /**** Aggregation ****/
    printf("\n* Aggregate signature: \n");


    if (musig2_aggregate_partial_sig(mps1, signature_1, NR_SIGNERS)){
        printf(" S: ");
        print_hex(&signature_1[MUSIG2_AGGR_PUBKEY_BYTES], MUSIG2_PARSIG_BYTES);
        printf(" R: ");
        print_hex(signature_1, MUSIG2_AGGR_PUBKEY_BYTES);
    }
    else {
        printf("* Failed to aggregate signatures.\n");
        for (k = 0; k < NR_SIGNERS; k++) {
            musig2_context_sig_free(&mcs_list[k]);
        }
        return -1;
    }

    /**** Verification ****/

    musig2_prepare_verifier(&aggr_pk_1, serialized_pk_list, NR_SIGNERS);
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (musig2_verify(signature_1, MSG_1, MSG_1_LEN, &aggr_pk_1))
        printf("\n* Musig2 is VALID!\n");
    else
        printf("\n* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n\n");



    printf("**** STATE 2 ************************************************************** \n");
    /**** Signature ****/
    printf("\n* Partial Signatures: \n");


    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN)){
            printf(" S%d: ", i + 1);
            print_hex(mps2[i].sig, MUSIG2_PARSIG_BYTES);
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


    if (musig2_aggregate_partial_sig(mps2, signature_2, NR_SIGNERS)){
        printf(" S: ");
        print_hex(&signature_2[MUSIG2_AGGR_PUBKEY_BYTES], MUSIG2_PARSIG_BYTES);
        printf(" R: ");
        print_hex(signature_2, MUSIG2_AGGR_PUBKEY_BYTES);
    }
    else {
        printf("* Failed to aggregate signatures.\n");
        return -1;
    }


    /**** Verification ****/
    // We could, in principal use `aggr_pk_1`, but we are just showcasing that
    // the verifier from round 2 might be different to that of round 1, and
    // therefore the key needs to be recomputed.

    musig2_prepare_verifier(    &aggr_pk_2, serialized_pk_list, NR_SIGNERS);
    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (musig2_verify(signature_2, MSG_2, MSG_2_LEN, &aggr_pk_2))
        printf("\n* Musig2 is VALID!\n");
    else
        printf("\n* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n");

    return 0;
}
