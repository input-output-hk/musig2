#include "helpermusig2.c"

int main(void) {

    musig2_context_signer mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_signer
    musig2_context_signature mps1[NR_SIGNERS];  // Array of partial signatures for the first state
    musig2_context_signature mps2[NR_SIGNERS];  // Array of partial signatures for the second state
    unsigned char serialized_pubkey_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Serialized public keys of signers
    unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED]; // Serialized batch commitments
    unsigned char signature1[MUSIG2_BYTES];    // Final signature for the first state
    unsigned char signature2[MUSIG2_BYTES];    // Final signature for the second state


    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", NR_SIGNERS);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t\t: %d \n", NR_MESSAGES);
    printf("--------------------------------------------------------------------------- \n\n");


    /*** Signer - Initialize, Serialize, Precompute ***/
    printf("___________________________ Setup signers _________________________________ \n");
    if (!musig2_setup(mcs_list, serialized_pubkey_list, serialized_batch_list)) {
        musig2_free(mcs_list);
        return -1;
    }/*************************************************/


    /*** STATE 1 - Partial signatures, Aggregation, Verification ***/
    printf("\n_________________________________ STATE_1 _________________________________ \n");
    /*** Generate partial signatures ***/
    if (!musig2_signing(mps1, mcs_list, MSG_1, MSG_1_LEN)) {
        musig2_free(mcs_list);
        return -1;
    }
    /*** Aggregate signatures ***/
    if (!musig2_aggregate(mps1, signature1)) {
        musig2_free(mcs_list);
        return -1;
    }
    /*** Verify MuSig2 for MSG_1 ***/
    if (!musig2_verify_signature(signature1, serialized_pubkey_list, MSG_1, MSG_1_LEN)) {
        musig2_free(mcs_list);
        return -1;
    }/**************************************************************/


    /*** STATE 2 - Partial signatures, Aggregation, Verification ***/
    printf("\n_________________________________ STATE_2 _________________________________ \n");
    /*** Generate partial signatures ***/
    int result = musig2_signing(mps2, mcs_list, MSG_2, MSG_2_LEN);
    musig2_free(mcs_list);
    if (!result) { return -1; }
    /*** Aggregate signatures ***/
    if (!musig2_aggregate(mps2, signature2)) { return -1; }
    /*** Verify MuSig2 for MSG_2 ***/
    if (!musig2_verify_signature(signature2, serialized_pubkey_list, MSG_2, MSG_2_LEN)) { return -1; }
    /***************************************************************/


    return 0;
}
