#include "src/libmusig2.h"
#include "tests/config.h"



int main(void) {

    musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig

    musig2_partial_signature mps1[NR_SIGNERS];  // Array of partial signatures for the first state
    musig2_partial_signature mps2[NR_SIGNERS];  // Array of partial signatures for the second state

    musig2_aggr_pubkey aggr_pubkey1;    // Aggregate public key of the first state
    musig2_aggr_pubkey aggr_pubkey2;    // Aggregate public key of the second state

    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Serialized public keys of signers
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED]; // Serialized batch commitments

    unsigned char signature1[MUSIG2_BYTES];    // Final signature for the first state
    unsigned char signature2[MUSIG2_BYTES];    // Final signature for the second state

    int i, j, k, l;

    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", NR_SIGNERS);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t\t: %d \n", NR_MESSAGES);
    printf("--------------------------------------------------------------------------- \n\n");

    printf("___________________________ Setup signers _________________________________ \n");
    /**** Initialization ****/
    printf("\n______ Initialize Signers _________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        if (musig2_init_signer(&mcs_list[i], NR_MESSAGES)) {
            printf("  Signer %d: .........................................................[DONE]\n", i + 1);
        }
        else {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
        }
    }

    /**** Registration ****/
    printf("\n______ Registration _______________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        unsigned char serialized_comm_list[V * NR_MESSAGES][MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serialized_pubkey[MUSIG2_PUBKEY_BYTES_COMPRESSED];

        if (musig2_serialise_shareable_context(&mcs_list[i], serialized_pubkey, serialized_comm_list)){
            printf("  Signer %d: .........................................................[DONE]\n", i + 1);
            memcpy(&serialized_pubkey_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_pubkey, MUSIG2_PUBKEY_BYTES_COMPRESSED);
            l = 0; // the index of the signer's commitment list.
            for (k = 0; k < NR_MESSAGES; k++)
                for (j = 0; j < V; j++, l++)
                    memcpy(&serialized_batch_list[(k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_comm_list[l],
                           MUSIG2_PUBKEY_BYTES_COMPRESSED);

        }
        else {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer for all messages ****/
    printf("\n______ Precomputation _____________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        if (!musig2_signer_precomputation(&mcs_list[i].mc, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS, NR_MESSAGES)) {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
        printf("  Signer %d: .........................................................[DONE]\n", i + 1);
    }
    printf("--------------------------------------------------------------------------- \n\n");


    /************** STATE 1 **************/
    printf("__________________________ Signing: state 1 _______________________________ \n");

    /**** Signature ****/
    printf("\nState 1: Partial Signatures _______________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (musig2_sign(&mcs_list[i], &mps1[i], MSG_1, MSG_1_LEN)){
            printf("  Signer %d: .........................................................[DONE]\n  ", i + 1);
            print_hex(mps1[i].signature, MUSIG2_PARSIG_BYTES);
        }
        else {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
            musig2_context_sig_free(&mcs_list[k]);
            return -1;
        }
    }

    /**** Aggregation ****/
    printf("\nState 1: Aggregate ________________________________________________________ \n");
    if (musig2_aggregate_partial_sig(mps1, signature1, NR_SIGNERS)){
        printf("  Aggregate .........................................................[DONE]\n");
        printf("  S .... ");
        print_hex(&signature1[MUSIG2_AGGR_PUBKEY_BYTES], MUSIG2_PARSIG_BYTES);
        printf("  R .... ");
        print_hex(signature1, MUSIG2_AGGR_PUBKEY_BYTES);
    }
    else {
        printf("  Aggregate .........................................................[FAIL]\n");
        for (k = 0; k < NR_SIGNERS; k++) {
            musig2_context_sig_free(&mcs_list[k]);
        }
        return -1;
    }

    /**** Verification ****/
    printf("\nState 1: Verification _____________________________________________________ \n");
    if (musig2_prepare_verifier(&aggr_pubkey1, serialized_pubkey_list, NR_SIGNERS)) {
        printf("  Prepare   .........................................................[DONE]\n");
        /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
        if (musig2_verify(&aggr_pubkey1, signature1, MSG_1, MSG_1_LEN))
            printf("  Musig2 is VALID!\n");
        else
            printf("  Failed to verify Musig2!\n");
    }
    else{
        printf("  Prepare   .........................................................[FAIL]\n");
    }
    printf("--------------------------------------------------------------------------- \n\n");


    /************** STATE 2 **************/
    printf("__________________________ Signing: state 2 _______________________________ \n");

    /**** Signature ****/
    printf("\nState 2: Partial Signatures _______________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (musig2_sign(&mcs_list[i], &mps2[i], MSG_2, MSG_2_LEN)){
            printf("  Signer %d: .........................................................[DONE]\n  ", i + 1);
            print_hex(mps2[i].signature, MUSIG2_PARSIG_BYTES);
            musig2_context_sig_free(&mcs_list[i]);
        }
        else {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
            for (k = i; k < NR_SIGNERS; k++) {
                musig2_context_sig_free(&mcs_list[k]);
            }
            return -1;
        }
    }

    /**** Aggregation ****/
    printf("\nState 2: Aggregate ________________________________________________________ \n");
    if (musig2_aggregate_partial_sig(mps2, signature2, NR_SIGNERS)){
        printf("  Aggregate .........................................................[DONE]\n");
        printf("  S .... ");
        print_hex(&signature2[MUSIG2_AGGR_PUBKEY_BYTES], MUSIG2_PARSIG_BYTES);
        printf("  R .... ");
        print_hex(signature2, MUSIG2_AGGR_PUBKEY_BYTES);
    }
    else {
        printf("  Aggregate .........................................................[FAIL]\n");
        return -1;
    }

    /**** Verification ****/
    printf("\nState 2: Verification _____________________________________________________ \n");
    if (musig2_prepare_verifier(&aggr_pubkey2, serialized_pubkey_list, NR_SIGNERS)) {
        printf("  Prepare   .........................................................[DONE]\n");
        /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
        if (musig2_verify(&aggr_pubkey2, signature2, MSG_2, MSG_2_LEN))
            printf("  Musig2 is VALID!\n");
        else
            printf("  Failed to verify Musig2!\n");
    }
    else{
        printf("  Prepare   .........................................................[FAIL]\n");
    }
    printf("--------------------------------------------------------------------------- \n\n");

    return 0;
}
