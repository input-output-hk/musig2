
#include "api_musig2.h"

int GEN_Musig2(secp256k1_context* ctx, secp256k1_keypair* Signers, MUSIG2 param, const unsigned char* msg, const unsigned char* tag){

    int i, j;
    int return_val;
    unsigned char msg_hash[SCALAR_BYTES];

    return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);

    /* Partial signatures *******************************************/
    printf("-------- Partial Signatures ----------------------------------------------- \n");
    unsigned char* par_sig_LIST[N];         /* Partial signatures list */
    unsigned char* sec_nonce_LIST[V];       /* Signer's secret nonce list */
    unsigned char seckey[SCALAR_BYTES];     /* Signer's secret key */
    unsigned char sxo_R[XONLY_BYTES];       /* Serialized x_only aggregated R */
    int parity_XR = 0;

    int index = N*V* param->STATE;
    for(i=0; i<N; i++){
        secp256k1_keypair_sec(ctx, seckey, &Signers[i]);
        par_sig_LIST[i] = malloc(SCALAR_BYTES);
        for(j = 0; j<V; j++){
            sec_nonce_LIST[j] = param->nonce_LIST[index+j];
        }
        index = index+V;
        if (SIG_Partial(ctx, param->COMM_LIST, sec_nonce_LIST, sxo_R, par_sig_LIST[i], seckey, param->sxo_X_, param->exp_LIST[i], msg_hash, param->parity_X , &parity_XR, param->STATE, N, V)){
            printf("* Sig%d: ", i+1);
            print_hex(par_sig_LIST[i], SCALAR_BYTES);
        }
    }
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/


    /* Aggregate partial signatures ********************************/
    printf("-------- Aggregate Partial Signatures ------------------------------------- \n");
    unsigned char agg_sig[SCALAR_BYTES];        /* Aggregated signatures of par_sig */
    AGG_SIG_SecondRound(ctx, par_sig_LIST, agg_sig, N);
    printf("* Sig: ");
    print_hex(agg_sig, SCALAR_BYTES);
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/

    /* If the parity_XR is 1, negate agg_sig. */
    if (parity_XR == 1)
        secp256k1_ec_seckey_negate(ctx, agg_sig);


    /* Set 64-Byte Signature ***************************************/
    unsigned char signature[PK_BYTES];      // Final Signature
    memcpy(&signature[0], sxo_R, XONLY_BYTES);
    memcpy(&signature[XONLY_BYTES], agg_sig, SCALAR_BYTES);
    /****************************************************************/


    /* Verify MuSig2 with library function ************************/
    printf("-------- Verify Signature ------------------------------------------------- \n");
    if (secp256k1_schnorrsig_verify(ctx, signature, msg_hash, XONLY_BYTES, param->xo_X_))
        return 1;
    else
        return 0;
    /****************************************************************/

}