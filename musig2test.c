#include "api_musig2.h"

int main(void) {
    unsigned char randomize[SCALAR_BYTES];

    int return_val;
    int STATE = 0;
    int i;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    MUSIG2 param = malloc(N*V*NR_MSGS*(sizeof(secp256k1_pubkey)+SCALAR_BYTES)+sizeof (secp256k1_xonly_pubkey)+SCALAR_BYTES*N+XONLY_BYTES+sizeof (int)*2);
    param->COMM_LIST = malloc(sizeof(secp256k1_pubkey)*N*V*NR_MSGS);
    param->xo_X_ = malloc(sizeof (secp256k1_xonly_pubkey));
    param->nonce_LIST = malloc(SCALAR_BYTES*N*V*NR_MSGS);
    param->exp_LIST = malloc(SCALAR_BYTES*N);
    param->sxo_X_ = malloc(XONLY_BYTES);
    param->STATE = 0;

    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers: %d ---------------------------------------------------- \n", N);
    printf("* Number of nonces: %d ----------------------------------------------------- \n", V);
    printf("* Number of messages: %d --------------------------------------------------- \n", NR_MSGS);
    printf("--------------------------------------------------------------------------- \n");



    /* Create a keypair for each signer ******************************/
    printf("\n-------- Initialize Signers ----------------------------------------------- \n");
    secp256k1_keypair Signers[N];   /* Signers' Keypair List */
    for(i=0; i<N; i++)
        INIT_Signer(ctx, &Signers[i]);
    printf("* %d Signers initialized --------------------------------------------------- \n", N);
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Collect signers **********************************************/
    printf("\n-------- Collect Signers -------------------------------------------------- \n");

    secp256k1_pubkey PK_LIST[N];        /* Signers' PUBKEY List */
    unsigned char* sxo_PK_LIST[N];      /* Signers' PUBKEY List -> Serialized */
    unsigned char L[XONLY_BYTES*N];     /* Concatenated sxo_PK_LIST */
    int parity;

    for(i=0; i<N; i++){
        secp256k1_xonly_pubkey temp_xonly;
        sxo_PK_LIST[i] = malloc(XONLY_BYTES);
        secp256k1_keypair_pub(ctx, &PK_LIST[i], &Signers[i]);                   /* Store full-size PK of signer */
        secp256k1_keypair_xonly_pub(ctx, &temp_xonly, &parity, &Signers[i]);    /* Get x_only PK */
        secp256k1_xonly_pubkey_serialize(ctx, sxo_PK_LIST[i], &temp_xonly);     /* Store serialized x_only PK in s_PK_LIST (to compute L.) */
        printf("* PK%d: ", i+1);
        print_hex(sxo_PK_LIST[i], XONLY_BYTES);
        memcpy( &L[i*XONLY_BYTES], sxo_PK_LIST[i], XONLY_BYTES);                /* Concat s_PK_LIST elements in L. (to compute exp.) */
    }
    printf("--------------------------------------------------------------------------- \n");
    printf("* %d Signers collected ----------------------------------------------------- \n", N);
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Compute exponents ********************************************/
    printf("\n-------- Compute Exponents ------------------------------------------------ \n");
    CALC_Exponent(ctx, sxo_PK_LIST, param->exp_LIST, L, N);
    printf("* Exponents computed ------------------------------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Aggregate public keys ****************************************/
    printf("\n-------- Aggregate Public Keys -------------------------------------------- \n");
    secp256k1_pubkey X_ ;   /* Aggregated PUBKEY */
    int parity_X = 0;
    AGG_Key(ctx, PK_LIST, &X_, param->xo_X_, param->sxo_X_, param->exp_LIST, &parity_X, N);
    printf("* Public keys aggregated -------------------------------------------------- \n* X_: ");
    print_hex(param->sxo_X_, XONLY_BYTES);
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/


    /* Batch commitments ********************************************/
    printf("\n-------- Generate Commitments --------------------------------------------- \n");
    int cnt =0;
    for(i=0; i<N; i++)
        BATCH_Commitment(ctx, param->COMM_LIST, param->nonce_LIST, &cnt, NR_MSGS, V); /* NO single data type for secret nonces */
    printf("* Commitments generated --------------------------------------------------- \n");
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/

    /* Signature for MSG_1 ******************************************/
    printf("\n*************************************************************************** \n");
    printf("--------- Signing Started ------------------------------------------------- \n");
    printf("* State: %d \n", param->STATE+1);
    printf("* Message: ");
    printf("%s\n", MSG_1);
    param->parity_X = parity_X;
    if (GEN_Musig2(ctx, Signers, param, MSG_1, TAG_1))
        printf("Musig2 is verified successfully!\n");
    else
        printf("Verification failed!\n");
    param->STATE++; /* Update state after each signature. */
    printf("*************************************************************************** \n");
    /****************************************************************/



    /* Signature for MSG_2 ******************************************/
    printf("\n*************************************************************************** \n");
    printf("--------- Signing Started ------------------------------------------------- \n");
    printf("* State: %d \n", param->STATE+1);
    printf("* Message: ");
    printf("%s\n", MSG_2);
    printf("--------------------------------------------------------------------------- \n");
    if (GEN_Musig2(ctx, Signers, param, MSG_2, TAG_2))
        printf("Musig2 is verified successfully!\n");
    else
        printf("Verification failed!\n");
    param->STATE++; /* Update state after each signature. */
    printf("*************************************************************************** \n");

    secp256k1_context_destroy(ctx);
    return 0;
}
