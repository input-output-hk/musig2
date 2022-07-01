#include "libmusig2.h"


int main(void) { // user input N
    unsigned char msg_1_hash[32];
    unsigned char msg_2_hash[32];
    unsigned char randomize[32];
    int STATE = 0;

    int return_val;
    int parity = 0;
    int i, j;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);
    return_val = secp256k1_tagged_sha256(ctx, msg_1_hash, TAG_1, TAG_1_LEN, MSG_1, MSG_1_LEN);
    assert(return_val);
    return_val = secp256k1_tagged_sha256(ctx, msg_2_hash, TAG_2, TAG_2_LEN, MSG_2, MSG_2_LEN);
    assert(return_val);


    secp256k1_keypair Signers[N];                                                       // Signer Keypair List
    secp256k1_pubkey PK_LIST[N];                                                        // Signer PUBKEY List
    secp256k1_pubkey X_ ;                                                               // Aggregated PUBKEY
    secp256k1_pubkey* COMM_R[N*V*NR_MSGS];                                              // Commitment Batch -> R
    secp256k1_pubkey NONCE;                                                             // Second round aggregated R
    secp256k1_xonly_pubkey xonly_X;                                                     // x_only aggregated PK -> schnorr verify



    unsigned char* s_PK_LIST[N*SK_BYTES];                                               // Signer PUBKEY List -> Serialized
    unsigned char* exp_LIST[N*SK_BYTES];                                                // Signers' exponents list
    unsigned char* nonce_r[N*V*NR_MSGS*SK_BYTES];                                       // Nonce Batch -> r
    unsigned char* par_sig[N*SK_BYTES];                                                 // Partial signatures list
    unsigned char* s_nonce[V*SK_BYTES];                                                 // Signer's secret nonce list
    unsigned char sk[SK_BYTES];                                                         // Signer's secret key
    unsigned char L[SK_BYTES*N];                                                        // Concatenated s_PK_LIST
    unsigned char agg_sig[SK_BYTES];                                                    // Aggregated signatures of par_sig
    unsigned char sx_NONCE[SK_BYTES];                                                   // Serialized x_only aggregated R
    unsigned char signature[64];                                                        // Final Signature
    unsigned char SX[SK_BYTES];                                                         // Serialized x_only aggregated PK




    /* Create a keypair for each signer ******************************/
    for(i=0; i<N; i++)
        INIT_Signer(ctx, &Signers[i]);
    /****************************************************************/



    /* Collect signers **********************************************/
    secp256k1_xonly_pubkey temp_xonly;
    for(i=0; i<N; i++){
        s_PK_LIST[i] = malloc(SK_BYTES);
        secp256k1_keypair_pub(ctx, &PK_LIST[i], &Signers[i]);                   /* Store full-size PK of signer */
        secp256k1_keypair_xonly_pub(ctx, &temp_xonly, &parity, &Signers[i]);    /* Get x_only PK */
        secp256k1_xonly_pubkey_serialize(ctx, s_PK_LIST[i], &temp_xonly);       /* Store serialized x_only PK in s_PK_LIST (to compute L.) */
        memcpy( &L[i*SK_BYTES], s_PK_LIST[i], SK_BYTES);                        /* Concat s_PK_LIST elements in L. (to compute exp.) */

    }
    /****************************************************************/



    /* Compute exponents ********************************************/
    CALC_Exponent(ctx, (const unsigned char **) s_PK_LIST, L, exp_LIST);
    /****************************************************************/


    /* Aggregate public keys ****************************************/
    AGG_Key(ctx, PK_LIST, exp_LIST, &X_);
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_X, &parity, &X_);        /* Get x_only X -> schnorr sig verification param. */
    secp256k1_xonly_pubkey_serialize(ctx, SX, &xonly_X);                    /* Store serialized version for hashes. */
    /****************************************************************/



    /* Batch commitments ********************************************/
    int cnt =0;
    for(i=0; i<N; i++)
        BATCH_Commitment(ctx, COMM_R, nonce_r, &cnt); /* NO single data type for secret nonces */

    /****************************************************************/

    /* Partial signatures *******************************************/
    int index = N*V*STATE;
    for(i=0; i<N; i++){
        secp256k1_keypair_sec(ctx, sk, &Signers[i]);
        par_sig[i] = (unsigned char*) malloc(SK_SIZE);
        for(j = 0; j<V; j++){
            s_nonce[j] = nonce_r[index+j];
        }
        index = index+V;
        SIG_Partial(ctx, par_sig[i], sk, SX, COMM_R, s_nonce, sx_NONCE, &NONCE, exp_LIST[i], msg_1_hash, STATE);
    }
    STATE++;    /* Update the state */
    /****************************************************************/


    /* Aggregate partial signatures ********************************/
    AGG_SIG_SecondRound(ctx, par_sig, agg_sig);
    /****************************************************************/


    /* Set 64-Byte Signature ***************************************/
    memcpy(&signature[0], sx_NONCE, SK_BYTES);
    memcpy(&signature[SK_BYTES], agg_sig, SK_BYTES);
    /****************************************************************/



    /* Verify MuSig2 with library function ************************/
    if (secp256k1_schnorrsig_verify(ctx, signature, msg_1_hash, 32, &xonly_X))
        printf("Schnorrsig verification: Musig2 is valid!\n");
    else
        printf("Schnorrsig verification: Musig2 is INVALID!\n");
    /****************************************************************/


    /***********************************************************************************************/
    /****************************************** TESTS **********************************************/
    /***********************************************************************************************/

    /* VERIFY MUSIG2 MANUALLY ***************************************/
    if (MAN_VER_SIG(ctx, agg_sig, &NONCE, &X_, msg_1_hash) == 0)
        printf("Manual verification: Musig2 is valid!\n");
    else
        printf("Manual verification: Musig2 is INVALID\n!");
    /****************************************************************/


    secp256k1_context_destroy(ctx);
    return 0;
}
