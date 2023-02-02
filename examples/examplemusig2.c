#include "config.h"
#include "helper.c"

int main(void) {

    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps[NR_SIGNERS];  // Array of partial signatures for the first state
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Serialized public keys of signers
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED]; // Serialized batch commitments
    unsigned char signature[MUSIG2_BYTES];    // Final signature
    musig2_aggr_pubkey aggr_pubkey;    // Aggregate public key

    MUSIG2_ERROR res;
    int i, k;

    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", NR_SIGNERS);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t\t: %d \n", NR_MESSAGES);
    printf("--------------------------------------------------------------------------- \n\n");

    const unsigned char* msg_list[NR_MESSAGES] = {MSG_1, MSG_2, MSG_3, MSG_4, MSG_5};
    const int msg_len_list[NR_MESSAGES] = {MSG_1_LEN, MSG_2_LEN, MSG_3_LEN, MSG_4_LEN, MSG_5_LEN};

    printf("___________________________ Setup signers _________________________________ \n");
    musig2_helper_setup(mcs_list, serialized_pubkey_list, serialized_batch_list);
    printf("--------------------------------------------------------------------------- \n\n");

    for (i = 0; i < NR_MESSAGES; i++) {
        printf("__________________________ Signing: state %d _______________________________ \n", i + 1);
        printf("\nState %d: Partial Signatures _______________________________________________ \n", i + 1);
        res = musig2_helper_sign(mps, mcs_list, msg_list[i], msg_len_list[i]);
        if (res != MUSIG2_OK || i == NR_MESSAGES - 1){
            for (k = 0; k < NR_SIGNERS; k++) {
                musig2_context_sig_free(&mcs_list[k]);
            }
            if (res != MUSIG2_OK){
                return -1;
            }
        }
        printf("\nState %d: Aggregate ________________________________________________________ \n", i + 1);
        if (musig2_helper_aggregate(mps, signature) != MUSIG2_OK){
            for (k = 0; k < NR_SIGNERS; k++) {
                musig2_context_sig_free(&mcs_list[k]);
            }
            return -1;
        }
        printf("\nState %d: Verification _____________________________________________________ \n", i + 1);
        musig2_helper_verify(signature, &aggr_pubkey, serialized_pubkey_list, msg_list[i], msg_len_list[i]);
    }

    return 0;
}
