#include "api_musig2.h"


void musig2_init(musig2_context_sig *mc){

    musig2_key_gen(mc);
    musig2_batch_commitment(mc, NR_MSGS);
}


void musig2_agg_R(musig2_context *mc, secp256k1_pubkey *batch_list, int n){

    int i,j;
    int ind = mc->state*(V*n);
    secp256k1_pubkey* temp_R_LIST[n];

    for (j=0; j<V; j++){
        i=0;
        while (i<n){
            temp_R_LIST[i] = malloc(sizeof (secp256k1_pubkey));
            memcpy( &temp_R_LIST[i++][0], batch_list[ind++].data, PK_BYTES);
        }
        secp256k1_ec_pubkey_combine(mc->ctx, &mc->agg_R_list[j], (const secp256k1_pubkey *const *) temp_R_LIST, n);
    }
}


void musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, const unsigned char *tag, int n)
{
    int return_val;

    unsigned char sx_pk[XONLY_BYTES];

    secp256k1_xonly_pubkey x_pk;

    musig_param *param = malloc(sizeof (musig_param));

    secp256k1_keypair_xonly_pub(mcs->mc->ctx, &x_pk, NULL, &mcs->keypair);
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, sx_pk, &x_pk);
    musig2_key_agg_coef(mcs->mc, sx_pk, mcs->a, mcs->mc->L, n);
    return_val = secp256k1_tagged_sha256(mcs->mc->ctx, param->msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);


    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param->sx_X, &mcs->mc->x_agg_X);

    musig2_sign_partial(mcs, param, n);
}


void musig2_init_aggregator(musig2_context_agg *mca, secp256k1_pubkey *pk_list, secp256k1_pubkey *batch_list, int n){

    musig2_aggregate_pubkey(mca->mc, pk_list, n);
    musig2_agg_R(mca->mc, batch_list, n);

}


void musig2_aggregate_parsig(musig2_context_agg *mca, unsigned char **parsig_list, const unsigned char *msg, const unsigned char *tag, int n){

    int return_val;
    musig_param *param = malloc(sizeof (musig_param));

    return_val = secp256k1_tagged_sha256(mca->mc->ctx, param->msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);

    secp256k1_xonly_pubkey_serialize(mca->mc->ctx, param->sx_X, &mca->mc->x_agg_X);

    return_val += !musig2_calc_b(mca->mc,param);
    param->par_R = musig2_calc_R(mca->mc,param);

    if (param->par_R == 1 && mca->mc->par_X == 1)
        mca->par_XR = 1;

    /* If parity_R is 1, then negate b and call Calc_R again. */
    if (param->par_R == 1 && mca->mc->par_X == 0){
        return_val += !secp256k1_ec_seckey_negate(mca->mc->ctx, param->b);
        return_val += !musig2_calc_R(mca->mc,param);
    }

    unsigned char aggsig[SCALAR_BYTES];

    memcpy(&aggsig[0], parsig_list[0], SCALAR_BYTES);
    int i;
    for(i=1; i<n; i++)
        secp256k1_ec_seckey_tweak_add(mca->mc->ctx, aggsig, parsig_list[i]);

    if (mca->par_XR == 1)
        secp256k1_ec_seckey_negate(mca->mc->ctx, aggsig);

    memcpy(&mca->signature[0], param->sx_R, SCALAR_BYTES);
    memcpy(&mca->signature[SCALAR_BYTES], aggsig, SCALAR_BYTES);

}

void musig2_verify_musig(musig2_context_agg *mca,const unsigned char *msg, const unsigned char *tag ){

    int return_val = 0;
    unsigned char msg_hash[SCALAR_BYTES];

    return_val = secp256k1_tagged_sha256(mca->mc->ctx, msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);

    printf("%d\n", secp256k1_schnorrsig_verify(mca->mc->ctx, mca->signature, msg_hash, SCALAR_BYTES, &mca->mc->x_agg_X));
}
