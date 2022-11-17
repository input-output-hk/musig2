#include "../src/libmusig2.h"
#include "../tests/config.h"

int musig2_helper_setup(musig2_context_signer *mcs_list, unsigned char *serialized_pubkey_list, unsigned char *serialized_batch_list){

    int i, j, k, l;
    /**** Initialization ****/
    printf("\nInitialize Signers ________________________________________________________ \n");
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
    printf("\nRegistration ______________________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        unsigned char serialized_comm_list[V * NR_MESSAGES][MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serialized_pubkey[MUSIG2_PUBKEY_BYTES_COMPRESSED];

        if (musig2_serialise_shareable_context(&mcs_list[i], serialized_pubkey, serialized_comm_list)){
            printf("  Signer %d: .........................................................[DONE]\n", i + 1);
            memcpy(&serialized_pubkey_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_pubkey, MUSIG2_PUBKEY_BYTES_COMPRESSED);
            l = 0; // the index of the signer's commitment list.
            for (k = 0; k < NR_MESSAGES; k++) {
                for (j = 0; j < V; j++, l++) {
                    memcpy(&serialized_batch_list[(k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_comm_list[l],
                           MUSIG2_PUBKEY_BYTES_COMPRESSED);
                }
            }
        }
        else {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
        }
    }

    /**** Aggregate the public keys and batch commitments for each signer for all messages ****/
    printf("\nPrecomputation ____________________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        if (!musig2_signer_precomputation(&mcs_list[i].mc, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS, NR_MESSAGES)) {
            printf("  Signer %d: .........................................................[FAIL]\n", i + 1);
            return 0;
        }
        printf("  Signer %d: .........................................................[DONE]\n", i + 1);
    }
    printf("--------------------------------------------------------------------------- \n\n");

    return 1;
}

int musig2_helper_sign(musig2_context_signature *mps, musig2_context_signer *mcs_list, const unsigned char *msg, int msg_len) {

    printf("\nPartial Signatures ________________________________________________________ \n");
    int i;
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        if (!musig2_sign(&mcs_list[i], &mps[i], msg, msg_len)){
            printf("  Sig %d .............................................................[FAIL]\n", i + 1);
            return 0;
        }
        else {
            printf("  Sig %d: ", i + 1);
            print_hex(mps[i].signature, MUSIG2_PARSIG_BYTES);
        }
    }
    return 1;
}

int musig2_helper_aggregate(musig2_context_signature *mps, unsigned char *signature) {

    printf("\nAggregation _______________________________________________________________ \n");
    if (!musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS)){
        printf("  Aggregate .........................................................[FAIL]\n");
        return 0;
    }
    else {
        printf("  Aggregate .........................................................[DONE]\n");
        printf("  S .... ");
        print_hex(&signature[MUSIG2_AGGR_PUBKEY_BYTES], MUSIG2_PARSIG_BYTES);
        printf("  R .... ");
        print_hex(signature, MUSIG2_AGGR_PUBKEY_BYTES);
    }
    return 1;
}

int musig2_helper_verify(unsigned char *signature, unsigned char *serialized_pubkey_list, const unsigned char *msg, int msg_len){

    printf("\nVerification ______________________________________________________________ \n");

    musig2_aggr_pubkey aggr_pubkey;    // Aggregate public key of the first state
    if (!musig2_prepare_verifier(&aggr_pubkey, serialized_pubkey_list, NR_SIGNERS)) {
        printf("  Prepare   .........................................................[FAIL]\n");
        return 0;
    }
    else{
        printf("  Prepare   .........................................................[DONE]\n");
        /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
        if (musig2_verify(&aggr_pubkey, signature, msg, msg_len))
            printf("  Musig2 is VALID!\n");
        else
            printf("  Failed to verify Musig2!\n");
    }
    printf("--------------------------------------------------------------------------- \n\n");

    return 1;
}

void musig2_helper_destroy_context(musig2_context_signer *mcs_list){
    int i;
    for (i = 0; i < NR_SIGNERS; i++) {
        musig2_context_signer_free(&mcs_list[i]);
    }
}