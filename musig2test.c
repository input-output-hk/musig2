#include "src/api_musig2.h"

int main(void) {
    unsigned char randomize[SCALAR_BYTES];

    int i, return_val;

    /* Initialize the secp256k1_context to operate on secp256k1 curve.
     * MuSig2 library generates a multi-signature in the form of the schnorr signature obtained by secp256k1_schnorrsig_sign32
     * with the library functions of libsecp256k1, however we do not use secp256k1_schnorrsig_sign32 function.
     * Thus, we create the context with only SECP256K1_CONTEXT_VERIFY flag instead of using
     * SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY. */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /* Initialize the MUSIG2 parameters. */
    MUSIG2_t param;
    param.R_LIST = malloc(sizeof(secp256k1_pubkey*) * N * V * NR_MSGS);
    param.xonly_X_ = malloc(sizeof(secp256k1_xonly_pubkey));
    param.r_LIST = malloc(sizeof(char*) * N * V * NR_MSGS);
    param.a_LIST = malloc(sizeof(char*) * N);
    param.ser_xonly_X_ = malloc(XONLY_BYTES);
    param.STATE = 0;

    /* Initialize a list of N signers. */
    SIGNER* signer_LIST = malloc(sizeof (SIGNER) * N);



    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", N);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t: %d \n", NR_MSGS);
    printf("--------------------------------------------------------------------------- \n");



    /* Create a keypair for each signer ******************************/
    printf("\n-------- Initialize Signers ----------------------------------------------- \n");
    for(i=0; i<N; i++){
        signer_LIST[i] = malloc(sizeof (SIGNER));
        signer_LIST[i]->keypair = malloc(sizeof (secp256k1_keypair));
        MuSig2_KeyGen(ctx, signer_LIST[i]->keypair);
    }
    printf("* %d Signers initialized.\n", N);
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Collect signers **********************************************/
    printf("\n-------- Collect Signers -------------------------------------------------- \n");
    secp256k1_pubkey X_LIST[N];         // Signers' public key list
    unsigned char* ser_xonly_XLIST[N];  // The list of signers' serialized public key list
    unsigned char L[XONLY_BYTES*N];     // Concatenated ser_xonly_XLIST

    /* Store full-size public keys of signers in X_LIST.
     * Get x_only version of public keys.
     * Store serialized x_only public keys in ser_xonly_XLIST (to compute L).
     * Concat the elements of ser_xonly_XLIST in L (to compute a). */
    for(i=0; i<N; i++){
        secp256k1_xonly_pubkey xonly_TEMP;
        ser_xonly_XLIST[i] = malloc(XONLY_BYTES);
        if (secp256k1_keypair_pub(ctx, &X_LIST[i], signer_LIST[i]->keypair) &&
            secp256k1_keypair_xonly_pub(ctx, &xonly_TEMP, NULL, signer_LIST[i]->keypair))
        {
            secp256k1_xonly_pubkey_serialize(ctx, ser_xonly_XLIST[i], &xonly_TEMP);
            printf("* X%d: ", i+1);
            print_hex(ser_xonly_XLIST[i], XONLY_BYTES);
            memcpy( &L[i*XONLY_BYTES], ser_xonly_XLIST[i], XONLY_BYTES);
        }
    }
    printf("* %d Signers collected.\n", N);
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Compute exponents of signers => a ****************************/
    printf("\n-------- Compute Exponents ------------------------------------------------ \n");
    MuSig2_KeyAggCoef(ctx, ser_xonly_XLIST, param.a_LIST, L, N);
    printf("* Exponents computed.\n");
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Aggregate public keys ****************************************/
    printf("\n-------- Aggregate Public Keys -------------------------------------------- \n");
    secp256k1_pubkey X_ ;   // Aggregated public key
    int parity_X_ = 0;      // The parity of xonly_X_
    MuSig2_KeyAgg(ctx, X_LIST, &X_, param.xonly_X_, param.ser_xonly_X_, param.a_LIST, &parity_X_, N);
    printf("* Public keys aggregated in X_.\n* X_: ");
    print_hex(param.ser_xonly_X_, XONLY_BYTES);
    param.parity_X_ = parity_X_;
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Batch commitments ********************************************/
    printf("\n-------- Generate Commitments --------------------------------------------- \n");
    for(i=0; i<N; i++){
        signer_LIST[i]->r_LIST = malloc(sizeof (char*) * V * NR_MSGS);
        MuSig2_BatchCommitment(ctx, param.R_LIST, signer_LIST[i]->r_LIST, i, N, NR_MSGS, V);
    }
    printf("* Commitments generated.\n");
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Signature for MSG_1 ******************************************/
    printf("\n*************************************************************************** \n");
    printf("--------- Signing Started ------------------------------------------------- \n");
    printf("* State\t\t: %d \n", param.STATE+1);
    printf("* Message\t: ");
    printf("%s\n", MSG_1);
    printf("--------------------------------------------------------------------------- \n");
    if (Gen_MuSig2(ctx, signer_LIST, &param, MSG_1, TAG_1))
        printf("* Musig2 is verified successfully!\n");
    else
        printf("* Verification failed!\n");
    param.STATE++; /* Update state after each signature. */
    printf("*************************************************************************** \n");
    /****************************************************************/



    /* Signature for MSG_2 ******************************************/
    printf("\n*************************************************************************** \n");
    printf("--------- Signing Started ------------------------------------------------- \n");
    printf("* State\t\t: %d \n", param.STATE+1);
    printf("* Message\t: ");
    printf("%s\n", MSG_2);
    printf("--------------------------------------------------------------------------- \n");
    if (Gen_MuSig2(ctx, signer_LIST, &param, MSG_2, TAG_2))
        printf("* Musig2 is verified successfully!\n");
    else
        printf("* Verification failed!\n");
    param.STATE++; /* Update state after each signature. */
    printf("*************************************************************************** \n");

    secp256k1_context_destroy(ctx);
    return 0;
}
