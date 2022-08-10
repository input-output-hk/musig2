#include "libmusig2.h"
#include "config.h"

void musig2_key_gen(musig2_context_sig *mcs) {
    unsigned char x[SCALAR_BYTES];

    while (1) {
        if (!fill_random(x, sizeof(x))) {
            printf("Failed to generate randomness\n");
            return;
        }
        /* Try to create a keypair with a valid context, it should only fail if
         * the secret key is zero or out of range. */
        if (secp256k1_keypair_create(mcs->mc->ctx, &mcs->keypair, x))
            break;
    }
}

void musig2_batch_commitment(musig2_context_sig *mcs) {

    unsigned char x[SCALAR_BYTES];
    mcs->commlist = malloc(sizeof (secp256k1_keypair)* NR_MSGS *V);

    int i,j,k;
    i=0;
    /* Create NR_MSGS * V batch commitments for signer */
    for (k = 0; k < NR_MSGS; k++){
        for (j = 0; j < V; j++) {
            mcs->commlist[i] = malloc(sizeof(secp256k1_keypair));
            while (1) {
                if (!fill_random(x, SCALAR_BYTES)) {
                    printf("Failed to generate randomness\n");
                    return;
                }
                if (secp256k1_keypair_create(mcs->mc->ctx, mcs->commlist[i], x))
                    break;
            }
            i++;
        }
    }
}

int musig2_key_agg_coef(musig2_context *mc, unsigned char *ser_xonly_X, unsigned char *a, unsigned char *L, int n) {

    unsigned char tag[13] = "BIP0340/nonce";    // Tag of hash to generate the exponents
    unsigned char concat[(n+1)*XONLY_BYTES];    // Temp to store (L||ser_xonly_X[i])

    memcpy(&concat[0], L, n*XONLY_BYTES );      // Copy L into concat
    memcpy(&concat[n*XONLY_BYTES], ser_xonly_X, XONLY_BYTES );  /* Copy ser_xonly_X_LIST besides L */
    return secp256k1_tagged_sha256(mc->ctx, a, tag, sizeof (tag), concat, sizeof (concat));
}

int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list, int n ){

    int i;
    int return_val = 0;
    unsigned char temp_a[SCALAR_BYTES];
    unsigned char *xonly_pk_list[n];
    secp256k1_pubkey* temp_X_LIST[n];
    secp256k1_xonly_pubkey temp_X;

    /* Allocate memory for L */
    mc->L = malloc(XONLY_BYTES*n);

    /* Multiply X_i with a_i. Store in temp_X_LIST[i]. */
    for(i=0; i<n;i++) {
        xonly_pk_list[i] = malloc(XONLY_BYTES);
        temp_X_LIST[i] = malloc(sizeof(secp256k1_pubkey));

        /* Copy the current public key into temp_X_LIST */
        memcpy(&temp_X_LIST[i]->data[0], pk_list[i].data, PK_BYTES);
        return_val += !secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_X, NULL, temp_X_LIST[i]);
        secp256k1_xonly_pubkey_serialize(mc->ctx, xonly_pk_list[i], &temp_X);

        /* Update L */
        memcpy(&mc->L[i * XONLY_BYTES], xonly_pk_list[i], XONLY_BYTES);
    }
    for(i=0; i<n;i++) {
        /* Get the exponent `a` of current public key */
        musig2_key_agg_coef(mc, xonly_pk_list[i], temp_a, mc->L, n);

        /* Compute `X_i * a_1` */
        return_val += !secp256k1_ec_pubkey_tweak_mul(mc->ctx, temp_X_LIST[i], temp_a);
    }
    /* Aggregate the public keys */
    return_val += !secp256k1_ec_pubkey_combine(mc->ctx, &mc->X_, (const secp256k1_pubkey *const *)temp_X_LIST, n);
    return return_val;
}

int musig2_sign_partial(musig2_context_sig *mcs, musig2_param *param){

    int return_val = 0;

    /* Compute `b`, `R`, and `c` */
    return_val += !musig2_calc_b(mcs,param);
    param->par_R = musig2_calc_R(mcs,param);
    musig2_calc_c(mcs->mc, param);

    /* If parity_R is 1, then negate b, call Calc_R again, and compute parsig */
    if (param->par_R == 1 && param->par_X == 0){
        return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, param->b);
        return_val += !musig2_calc_R(mcs,param);
        param->par_R = -1;
        return_val += !musig2_set_parsig(mcs, param);
    }
    /* If parity_X_ is 1, negate c and compute parsig */
    else if (param->par_R == 0 && param->par_X == 1){
        return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, param->c);
        return_val += !musig2_set_parsig(mcs, param);
    }
    /* If parity_X_ == parity_R compute parsig */
    else{
        return_val += !musig2_set_parsig(mcs, param);
    }

    if (return_val != 0) return 0;
    else return 1;
}

int musig2_calc_b(musig2_context_sig *mcs, musig2_param *param) {

    int j;
    int return_val = 0;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag of the hash to compute b
    unsigned char temp_X[XONLY_BYTES];
    unsigned char catXR[(2+V)*XONLY_BYTES]; // Temp value to store (ser_xonly_X_ || R_1 || ... || R_V || msg)
    secp256k1_xonly_pubkey xonly_temp;

    /* Copy ser_xonly_X_ into catXR */
    memcpy(&catXR[0], param->sx_X, XONLY_BYTES);

    /* Get x_only R_j, Serialize x_only R_j, and Concatenate. */
    for (j=0; j<V; j++){
        return_val += !secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &xonly_temp, NULL, &mcs->agg_R_list[j]);
        secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, temp_X, &xonly_temp);
        memcpy(&catXR[XONLY_BYTES*(j+1)], temp_X, XONLY_BYTES);
    }

    /* Concatenate msg to end */
    memcpy(&catXR[(1+V)*XONLY_BYTES], param->msg_hash, XONLY_BYTES);

    /* Compute b */
    return_val += !secp256k1_tagged_sha256(mcs->mc->ctx, param->b, tag, sizeof (tag), catXR, sizeof(catXR));


    if (return_val != 0)    return 0;
    else                    return 1;
}

int musig2_calc_R(musig2_context_sig *mcs, musig2_param *param) {

    int j;
    int return_val = 0;
    secp256k1_pubkey *Rb_LIST[V];
    secp256k1_xonly_pubkey xonly_temp;
    int par = param->par_R;

    /* Compute b_LIST = { b^(j-1) } and
     * Rb_LIST = { R_j * b^(j-1) } */
    for (j=0; j<V; j++){
        Rb_LIST[j] = malloc(sizeof (secp256k1_pubkey));
        param->b_LIST[j] = malloc(SCALAR_BYTES);
        memcpy(&Rb_LIST[j]->data[0], mcs->agg_R_list[j].data, PK_BYTES);
        if (j == 0 && par == 0) {
        }
        else if (j == 0 && par == 1) {
            return_val += !secp256k1_ec_pubkey_negate(mcs->mc->ctx, Rb_LIST[j]);
        }
        else {
            if (j == 1){
                /* If j = 1 => b_LIST[j] = b .*/
                memcpy(&param->b_LIST[j][0], param->b, SCALAR_BYTES);
                return_val += !secp256k1_ec_pubkey_tweak_mul(mcs->mc->ctx, Rb_LIST[j], param->b_LIST[j]);
            }
            else{
                memcpy(&param->b_LIST[j][0], param->b_LIST[j-1], SCALAR_BYTES);
                /* Compute b * b^(j-1) */
                return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, param->b_LIST[j], param->b) ;
                return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, param->b_LIST[j]);
                return_val += !secp256k1_ec_pubkey_tweak_mul(mcs->mc->ctx, Rb_LIST[j], param->b_LIST[j]);
            }
        }
    }

    /* R = SUM ({ R_j * b^(j-1) })
     * Get x_only R, store in xonly_temp
     * Get parity R to check whether b is needed to be negated.
     * Serialize x_only R into ser_xonly_R */
    return_val += !secp256k1_ec_pubkey_combine(mcs->mc->ctx, &mcs->mc->R, (const secp256k1_pubkey *const *)Rb_LIST, V) ;
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &xonly_temp, &par, &mcs->mc->R);
    return_val += !secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param->sx_R, &xonly_temp);

    if (return_val != 0) return -1;
    else                 return par;

}

void musig2_calc_c(musig2_context *mc, musig2_param *param){
    unsigned char tag[17] = "BIP0340/challenge";        // Tag of the hash to compute challenge.
    unsigned char catXRM[XONLY_BYTES*2+SCALAR_BYTES];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )

    memcpy(&catXRM[0], param->sx_R, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES], param->sx_X, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES*2], param->msg_hash, SCALAR_BYTES);

    assert(secp256k1_tagged_sha256(mc->ctx, param->c, tag , sizeof (tag), catXRM, SCALAR_BYTES * 3));
}

int musig2_set_parsig(musig2_context_sig *mcs, musig2_param *param){
    int j;
    int return_val = 0;
    unsigned char temp_rb[SCALAR_BYTES];
    unsigned char sum_rb[SCALAR_BYTES];
    unsigned char x[SCALAR_BYTES];
    unsigned char** sr_list = malloc(SCALAR_BYTES*V);

    /* Extract the secret key of the signer */
    return_val += !secp256k1_keypair_sec(mcs->mc->ctx, x, &mcs->keypair);

    /* Extract the nonces of the signer for current state and message */
    int index = V*mcs->mc->state;
    for(j = 0; j<V; j++){
        sr_list[j] = malloc(SCALAR_BYTES);
        return_val += !secp256k1_keypair_sec(mcs->mc->ctx, sr_list[j], mcs->commlist[index+j]);
        mcs->commlist[index+j] = NULL;
    }

    /* Compute (a * x * c) */
    memcpy(&mcs->parsig[0], param->c, SCALAR_BYTES);
    return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, mcs->parsig, x);
    return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, mcs->parsig, param->a);

    /* If j = 0 => b = -1. So, r_0 * b_LIST[0] = - sec_r_LIST[0].
     * If j = 0 => b = 1.
     * Else, Copy r_j to temp_rb, compute r_j * b_LIST[j], and add temp_rb to sum_rb. */
    for (j = 0; j < V; j++) {
        /* If the parity of R is -1 negate `b` (b=1) or equivalently negate sr_list[j] */
        if (j == 0 && param->par_R == -1) {
            return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, sr_list[j]);
            memcpy(&sum_rb[0], sr_list[j], SCALAR_BYTES);
        }
        else if (j == 0) memcpy(&sum_rb[0], sr_list[j], SCALAR_BYTES);
        else {
            memcpy(&temp_rb[0], sr_list[j], SCALAR_BYTES);
            return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, temp_rb, param->b_LIST[j]);
            return_val += !secp256k1_ec_seckey_tweak_add(mcs->mc->ctx, sum_rb, temp_rb);
        }
    }

    /* Finalize response */
    return_val += !secp256k1_ec_seckey_tweak_add(mcs->mc->ctx, mcs->parsig, sum_rb);

    if (return_val != 0) return 0;
    else                 return 1;
}








