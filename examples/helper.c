#include "../src/libmusig2.h"
#include "config.h"


const char* const MUSIG2_STR[] = {
        " ........................................................[DONE] \n",
        " (key generation) .......................................[FAIL] \n",
        " (batch commitment) .....................................[FAIL] \n",
        " (aggregate R) ..........................................[FAIL] \n",
        " (aggregate pubkey) .....................................[FAIL] \n",
        " (calculate R) ..........................................[FAIL] \n",
        " (set partial signature) ................................[FAIL] \n",
        " (check commitments) ....................................[FAIL] \n",
        " (combine partial signatures) ...........................[FAIL] \n",
        " (compare R) ............................................[FAIL] \n",
        " (ser/deser pubkey) .....................................[FAIL] \n",
        " (ser/deser commitments) ................................[FAIL] \n",
        " (operation) ............................................[FAIL] \n",

};
const char* musig2_error_str(MUSIG2_ERROR result)
{
    const char* err = MUSIG2_STR[result - 1];
    return err;
}

void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void musig2_helper_setup(musig2_context_signer *mcs_list, unsigned char *serialized_pubkey_list, unsigned char *serialized_batch_list){

    int i, j, k, l;
    MUSIG2_ERROR res;
    /**** Initialization ****/
    printf("\n______ Initialize Signers _________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate a keypair for the signer and get batch commitments. */
        res = musig2_init_signer(&mcs_list[i], NR_MESSAGES);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));
    }

    /**** Registration ****/
    printf("\n______ Registration _______________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        unsigned char serialized_comm_list[V * NR_MESSAGES][MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serialized_pubkey[MUSIG2_PUBKEY_BYTES_COMPRESSED];
        musig2_serialise_shareable_context(&mcs_list[i], serialized_pubkey, serialized_comm_list);
        memcpy(&serialized_pubkey_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_pubkey, MUSIG2_PUBKEY_BYTES_COMPRESSED);
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++)
            for (j = 0; j < V; j++, l++)
                memcpy(&serialized_batch_list[(k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_comm_list[l],
                       MUSIG2_PUBKEY_BYTES_COMPRESSED);
    }

    /**** Aggregate the public keys and batch commitments for each signer for all messages ****/
    printf("\n______ Precomputation _____________________________________________________ \n");
    for (i = 0; i < NR_SIGNERS; i++) {
        res = musig2_signer_precomputation(&mcs_list[i].mc, serialized_pubkey_list, serialized_batch_list, NR_SIGNERS);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));
    }
    printf("--------------------------------------------------------------------------- \n\n");
}

int musig2_helper_sign(musig2_context_signature *mps, musig2_context_signer *mcs_list, const unsigned char *msg, int msg_len) {
    int i;
    MUSIG2_ERROR res;
    for (i = 0; i < NR_SIGNERS; i++) {
        /* Generate the partial signatures */
        res = musig2_sign(&mcs_list[i], &mps[i], msg, msg_len);
        printf("  Signer %d: %s", i + 1, musig2_error_str(res));
        if (res != MUSIG2_OK){
            return res;
        }
    }
    return MUSIG2_OK;
}

int musig2_helper_aggregate(musig2_context_signature *mps, unsigned char *signature) {

    MUSIG2_ERROR  res;
    res = musig2_aggregate_partial_sig(mps, signature, NR_SIGNERS);
    printf("  Signature %s", musig2_error_str(res));
    if (res == MUSIG2_OK){
        printf("  Aggregate .........................................................[DONE]\n");
        printf("  S .... ");
        print_hex(&signature[MUSIG2_AGGR_PUBKEY_BYTES], MUSIG2_PARSIG_BYTES);
        printf("  R .... ");
        print_hex(signature, MUSIG2_AGGR_PUBKEY_BYTES);
    }
    else {
        return res;
    }
    return MUSIG2_OK;
}

void musig2_helper_verify(unsigned char *signature, musig2_aggr_pubkey *aggr_pubkey, unsigned char *serialized_pubkey_list, const unsigned char *msg, int msg_len){

    MUSIG2_ERROR res;
    res = musig2_prepare_verifier(aggr_pubkey, serialized_pubkey_list, NR_SIGNERS);
    printf("  Prepare   %s", musig2_error_str(res));

    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (musig2_verify(aggr_pubkey, signature, msg, msg_len)) {
        printf("\n* Musig2 is VALID!\n");
    }
    else {
        printf("\n* Failed to verify Musig2!\n");
        printf("--------------------------------------------------------------------------- \n\n");
    }
    printf("--------------------------------------------------------------------------- \n\n");
}
