#include "libmusig2.h"

static void musig2_key_gen(musig2_context_sig *mcs) {
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

static void musig2_batch_commitment(musig2_context_sig *mcs, int nr_msgs) {

    unsigned char x[SCALAR_BYTES];
    mcs->commlist = malloc(sizeof (secp256k1_keypair*)* nr_msgs * V);

    int i, j, k;
    i=0;
    /* Create NR_MSGS * V batch commitments for signer */
    for (k = 0; k < nr_msgs; k++){
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

static int musig2_key_agg_coef(musig2_context *mc, unsigned char *ser_xonly_X, unsigned char *a, unsigned char *L, int n) {

    unsigned char tag[13] = "BIP0340/nonce";    // Tag of hash to generate the exponents
    unsigned char concat[(n + 1) * XONLY_BYTES];    // Temp to store (L||ser_xonly_X[i])

    memcpy(concat, L, n * XONLY_BYTES );      // Copy L into concat
    memcpy(&concat[n * XONLY_BYTES], ser_xonly_X, XONLY_BYTES );  /* Copy ser_xonly_X_LIST besides L */
    return secp256k1_tagged_sha256(mc->ctx, a, tag, sizeof (tag), concat, sizeof (concat));
}

static int musig2_calc_b(musig2_context_sig *mcs, musig2_param *param) {

    int j;
    int return_val = 0;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag of the hash to compute b
    unsigned char temp_X[XONLY_BYTES];
    secp256k1_xonly_pubkey xonly_temp;
    int size_msg = sizeof (*param->msg);

    unsigned char catXR[(1 + V) * XONLY_BYTES + size_msg]; // Temp value to store (ser_xonly_X_ || R_1 || ... || R_V || msg)


    /* Copy ser_xonly_X_ into catXR */
    memcpy(catXR, param->sx_X, XONLY_BYTES);

    /* Get x_only R_j, Serialize x_only R_j, and Concatenate. */
    for (j=0; j<V; j++){
        return_val += !secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &xonly_temp, NULL, &mcs->agg_R_list[j]);
        secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, temp_X, &xonly_temp);
        memcpy(&catXR[XONLY_BYTES * (j + 1)], temp_X, XONLY_BYTES);
    }

    /* Concatenate msg to end */
    memcpy(&catXR[(1 + V) * XONLY_BYTES], param->msg, size_msg);

    /* Compute b */
    return_val += !secp256k1_tagged_sha256(mcs->mc->ctx, param->b, tag, sizeof (tag), catXR, sizeof(catXR));


    if (return_val != 0)    return 0;
    else                    return 1;
}

static int musig2_calc_R(musig2_context_sig *mcs, musig2_param *param) {

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
        memcpy(Rb_LIST[j]->data, mcs->agg_R_list[j].data, PK_BYTES);
        if (j == 0 && par == 0) {
        }
        else if (j == 0 && par == 1) {
            return_val += !secp256k1_ec_pubkey_negate(mcs->mc->ctx, Rb_LIST[j]);
        }
        else {
            if (j == 1){
                /* If j = 1 => b_LIST[j] = b .*/
                memcpy(param->b_LIST[j], param->b, SCALAR_BYTES);
                return_val += !secp256k1_ec_pubkey_tweak_mul(mcs->mc->ctx, Rb_LIST[j], param->b_LIST[j]);
            }
            else{
                memcpy(param->b_LIST[j], param->b_LIST[j-1], SCALAR_BYTES);
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

static void musig2_calc_c(musig2_context *mc, musig2_param *param){
    unsigned char tag[17] = "BIP0340/challenge";        // Tag of the hash to compute challenge.

    unsigned char catXRM[XONLY_BYTES * 2 + param->msg_size];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )

    memcpy(catXRM, param->sx_R, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES], param->sx_X, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES * 2], param->msg, param->msg_size);

    assert(secp256k1_tagged_sha256(mc->ctx, param->c, tag , sizeof (tag), catXRM, sizeof (catXRM)));
}

static int musig2_set_parsig(musig2_context_sig *mcs, musig2_param *param){
    int j;
    int return_val = 0;
    unsigned char temp_rb[SCALAR_BYTES];
    unsigned char sum_rb[SCALAR_BYTES];
    unsigned char x[SCALAR_BYTES];
    unsigned char** sr_list = malloc(SCALAR_BYTES * V);

    /* Extract the secret key of the signer */
    return_val += !secp256k1_keypair_sec(mcs->mc->ctx, x, &mcs->keypair);

    /* Extract the nonces of the signer for current state and message */
    int index = V * mcs->mc->state;
    for(j = 0; j<V; j++){
        sr_list[j] = malloc(SCALAR_BYTES);
        return_val += !secp256k1_keypair_sec(mcs->mc->ctx, sr_list[j], mcs->commlist[index+j]);
        mcs->commlist[index + j] = NULL;
    }

    /* Compute (a * x * c) */
    memcpy(mcs->parsig, param->c, SCALAR_BYTES);
    return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, mcs->parsig, x);
    return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, mcs->parsig, param->a);

    /* If j = 0 => b = -1. So, r_0 * b_LIST[0] = - sec_r_LIST[0].
     * If j = 0 => b = 1.
     * Else, Copy r_j to temp_rb, compute r_j * b_LIST[j], and add temp_rb to sum_rb. */
    for (j=0; j<V; j++) {
        /* If the parity of R is -1 negate `b` (b=1) or equivalently negate sr_list[j] */
        if (j == 0 && param->par_R == -1) {
            return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, sr_list[j]);
            memcpy(sum_rb, sr_list[j], SCALAR_BYTES);
        }
        else if (j == 0) memcpy(sum_rb, sr_list[j], SCALAR_BYTES);
        else {
            memcpy(temp_rb, sr_list[j], SCALAR_BYTES);
            return_val += !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, temp_rb, param->b_LIST[j]);
            return_val += !secp256k1_ec_seckey_tweak_add(mcs->mc->ctx, sum_rb, temp_rb);
        }
    }

    /* Finalize response */
    return_val += !secp256k1_ec_seckey_tweak_add(mcs->mc->ctx, mcs->parsig, sum_rb);

    if (return_val != 0) return 0;
    else                 return 1;
}


/**** Signer ****/
void musig2_init_signer(musig2_context_sig *mcs, secp256k1_context *ctx){

    mcs->mc = malloc(sizeof (musig2_context));
    mcs->mc->ctx = secp256k1_context_clone(ctx);

    /* Generate a key pair for given signer */
    musig2_key_gen(mcs);

    /* Generate the batch commitments for given signer */
    musig2_batch_commitment(mcs, NR_MSGS);
    mcs->mc->state = 0;

}

int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list){

    int i;
    int return_val = 0;
    unsigned char temp_a[SCALAR_BYTES];
    unsigned char *xonly_pk_list[N];
    secp256k1_pubkey* temp_X_LIST[N];
    secp256k1_xonly_pubkey temp_X;

    /* Allocate memory for L */
    mc->L = malloc(XONLY_BYTES * N);

    /* Multiply X_i with a_i. Store in temp_X_LIST[i]. */
    for(i=0; i<N; i++) {
        xonly_pk_list[i] = malloc(XONLY_BYTES);
        temp_X_LIST[i] = malloc(sizeof(secp256k1_pubkey));

        /* Copy the current public key into temp_X_LIST */
        memcpy(temp_X_LIST[i]->data, pk_list[i].data, PK_BYTES);
        return_val += !secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_X, NULL, temp_X_LIST[i]);
        secp256k1_xonly_pubkey_serialize(mc->ctx, xonly_pk_list[i], &temp_X);

        /* Update L */
        memcpy(&mc->L[i * XONLY_BYTES], xonly_pk_list[i], XONLY_BYTES);
    }
    for(i=0; i<N;i++) {
        /* Get the exponent `a` of current public key */
        musig2_key_agg_coef(mc, xonly_pk_list[i], temp_a, mc->L, N);

        /* Compute `X_i * a_1` */
        return_val += !secp256k1_ec_pubkey_tweak_mul(mc->ctx, temp_X_LIST[i], temp_a);
    }
    /* Aggregate the public keys */
    return_val += !secp256k1_ec_pubkey_combine(mc->ctx, &mc->X_, (const secp256k1_pubkey *const *)temp_X_LIST, N);
    return return_val;
}

int musig2_agg_R(musig2_context_sig *mcs, secp256k1_pubkey *batch_list){

    int i,j;
    int return_val = 0;
    int ind = mcs->mc->state*(V * N);
    secp256k1_pubkey* temp_R_LIST[N];

    /* Aggregate the batch commitments for current state and message */
    for (j=0; j<V; j++){
        i=0;
        while (i<N){
            temp_R_LIST[i] = malloc(sizeof (secp256k1_pubkey));
            memcpy( temp_R_LIST[i++], batch_list[ind++].data, PK_BYTES);
        }
        return_val += !secp256k1_ec_pubkey_combine(mcs->mc->ctx, &mcs->agg_R_list[j], (const secp256k1_pubkey *const *) temp_R_LIST, N);
    }

    if (return_val != 0) return 0;
    else                 return 1;
}

int musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, int size)
{
    int return_val = 0;
    unsigned char sx_pk[XONLY_BYTES];   // Serialized x_only public key of signer
    secp256k1_xonly_pubkey x_pk;    // x_only public key of signer
    secp256k1_xonly_pubkey x_X_;    // x_only aggregated public key
    musig2_param param;  // Parameters used to generate partial signature

//    /* Compute the hash of given message with given tag */
//    return_val = secp256k1_tagged_sha256(mcs->mc->ctx, param->msg_hash, tag, sizeof (tag), msg, sizeof (msg));
//    assert(return_val);

    param.msg = malloc(size);
    memcpy(param.msg, msg, size);
    param.msg_size = size;


    /* Get the exponent `a` of current signer */
    return_val += !secp256k1_keypair_xonly_pub(mcs->mc->ctx, &x_pk, NULL, &mcs->keypair);
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, sx_pk, &x_pk);
    musig2_key_agg_coef(mcs->mc, sx_pk, param.a, mcs->mc->L, N);


    /* Get x_only version of aggregated public key and its parity */
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &x_X_, &param.par_X, &mcs->mc->X_);
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param.sx_X, &x_X_);

    /* Generate partial signature */

    /* Compute `b`, `R`, and `c` */
    return_val += !musig2_calc_b(mcs,&param);
    param.par_R = musig2_calc_R(mcs,&param);
    musig2_calc_c(mcs->mc, &param);

    /* If parity_R is 1, then negate b, call Calc_R again, and compute parsig */
    if (param.par_R == 1 && param.par_X == 0){
        return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, param.b);
        return_val += !musig2_calc_R(mcs, &param);
        param.par_R = -1;
        return_val += !musig2_set_parsig(mcs, &param);
    }
        /* If parity_X_ is 1, negate c and compute parsig */
    else if (param.par_R == 0 && param.par_X == 1){
        return_val += !secp256k1_ec_seckey_negate(mcs->mc->ctx, param.c);
        return_val += !musig2_set_parsig(mcs, &param);
    }
        /* If parity_X_ == parity_R compute parsig */
    else{
        return_val += !musig2_set_parsig(mcs, &param);
    }

    mcs->mc->state++;


    if (return_val != 0) return 0;
    else                 return 1;
}

/**** Aggregator ****/
int musig2_aggregate_partial_sig(secp256k1_context *ctx, musig2_context *mca, musig2_parsig *mpl, secp256k1_pubkey *pk_list, unsigned char *signature){


    int i, j;
    mca->ctx = secp256k1_context_clone(ctx);

    /* Aggregate the given list of public keys */
    musig2_aggregate_pubkey(mca, pk_list);

    /* Check whether all aggregated R is same */
    for (i=0; i<N; i++){
        for (j=0; j<i; j++){
            if (secp256k1_ec_pubkey_cmp(ctx, &mpl[i].R, &mpl[j].R )  != 0){
                return -1 ;
            }
        }
    }
    /* Set given R */
    memcpy(&mca->R, mpl[0].R.data, PK_BYTES);

    int return_val = 0;
    int par_X = 0;  // Parity of X
    int par_R = 0;  // Parity of R
    unsigned char aggsig[SCALAR_BYTES]; // Aggregated signature
    unsigned char sx_R[SCALAR_BYTES];   // Serialized x_only R
    secp256k1_xonly_pubkey x_X; // x_only X
    secp256k1_xonly_pubkey x_R; // x_only R

    /* Get x_only X and its parity*/
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mca->ctx, &x_X, &par_X, &mca->X_);

    /* Get x_only R and its parity*/
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mca->ctx, &x_R, &par_R, &mca->R);

    /* Serialize x_only R to store in signature */
    secp256k1_xonly_pubkey_serialize(mca->ctx, sx_R, &x_R);

    /* Aggregate the partial signatures */
    memcpy(aggsig, mpl[0].sig, SCALAR_BYTES);
    for(i=1; i<N; i++){
        return_val += !secp256k1_ec_seckey_tweak_add(mca->ctx, aggsig, mpl[i].sig);
    }

    /* Negate the aggregated signature if both par_X and par_R */
    if (par_X == 1 && par_R == 1)
        return_val += !secp256k1_ec_seckey_negate(mca->ctx, aggsig);

    /* Set the signature of type schnorr signature */
    memcpy(signature, sx_R, SCALAR_BYTES);
    memcpy(&signature[SCALAR_BYTES], aggsig, SCALAR_BYTES);

    if (return_val != 0) return 0;
    else                 return 1;
}

/**** Verifier ****/
int musig2_ver_musig(secp256k1_context *ctx, const unsigned char *signature, secp256k1_pubkey X, const unsigned char *msg, int size ){

    secp256k1_xonly_pubkey x_X;

    assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &x_X, NULL, &X));

//    /* Compute the hash of given message with given tag */
//    unsigned char msg_hash[SCALAR_BYTES];
//    return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof (tag), msg, sizeof (msg));
//    assert(return_val);


    /* Verify musig2 with secp256k1_schnorrsig_verify */
    return secp256k1_schnorrsig_verify(ctx, signature, msg, size, &x_X);
}