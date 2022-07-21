#include "api_musig2.h"

int Gen_MuSig2(secp256k1_context *ctx, SIGNER *Signers, MUSIG2 param, const unsigned char *msg, const unsigned char *tag){

    int i;
    int return_val;
    unsigned char msg_hash[SCALAR_BYTES];

    /* Compute the tagged hash of the given message with given tag.
     * It is recommended to generate a schnorr signature on an input of 32-bytes which is the
     * tagged sha256 of message. See secp25k1 library for more information. */
    return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);



    /* Partial signatures *******************************************/
    printf("* Partial signatures:\n");
    unsigned char* parsig_LIST[N];          // Partial signatures list
    unsigned char x[SCALAR_BYTES];          // Signer's secret key
    unsigned char ser_xonly_R[XONLY_BYTES]; // Serialized x_only aggregated R
    int parity_RX_ = 0;

    for(i=0; i<N; i++){
        if (secp256k1_keypair_sec(ctx, x, Signers[i]->keypair)) {
            parsig_LIST[i] = malloc(SCALAR_BYTES);
            if (MuSig2_SignPartial(ctx,
                                    param->R_LIST, Signers[i]->r_LIST, ser_xonly_R, parsig_LIST[i], x, param->ser_xonly_X_, param->a_LIST[i], msg_hash,
                                    param->parity_X_, &parity_RX_, param->STATE, N, V)) {
                printf("* Sig%d: ", i + 1);
                print_hex(parsig_LIST[i], SCALAR_BYTES);
            }
        }
    }
    printf("--------------------------------------------------------------------------- \n");
    /****************************************************************/



    /* Aggregate partial signatures ********************************/
    printf("* Aggregated signature:\n");
    unsigned char aggsig[SCALAR_BYTES];    // Aggregated signature of parsig_LIST
    MuSig2_AggSignatures(ctx, parsig_LIST, aggsig, N);
    printf("* Sig: ");
    print_hex(aggsig, SCALAR_BYTES);
    printf("--------------------------------------------------------------------------- \n");
    /* If the parity_XR is 1, negate agg_sig. */
    if (parity_RX_ == 1)
        if (!secp256k1_ec_seckey_negate(ctx, aggsig))
            return 0;
    /****************************************************************/



    /* Set 64-Byte Signature ***************************************/
    unsigned char signature[PK_BYTES];  // Final Signature
    memcpy(&signature[0], ser_xonly_R, XONLY_BYTES);
    memcpy(&signature[XONLY_BYTES], aggsig, SCALAR_BYTES);
    /****************************************************************/



    /* Verify MuSig2 with library function ************************/
    printf("* Verification:\n");
    if (secp256k1_schnorrsig_verify(ctx, signature, msg_hash, XONLY_BYTES, param->xonly_X_))
        return 1;
    else
        return 0;
    /****************************************************************/

}