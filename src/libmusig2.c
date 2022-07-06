#include "libmusig2.h"


void INIT_Signer(secp256k1_context* ctx, secp256k1_keypair* signer){
    unsigned char seckey[SCALAR_BYTES];
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return;
        }
        /* Try to create a keypair with a valid context, it should only fail if
         * the secret key is zero or out of range. */
        if (secp256k1_keypair_create(ctx, signer, seckey))
            break;
    }
}


int AGG_Key(const secp256k1_context* ctx, secp256k1_pubkey* PK_LIST, secp256k1_pubkey* X_, secp256k1_xonly_pubkey* xo_X_, unsigned char* sxo_X_, unsigned char** exp_LIST, int* parity_X, int N){

    int i;
    int return_val = 0;
    secp256k1_pubkey* temp_PK[N];

    for(i=0; i<N;i++){
        temp_PK[i] = malloc(sizeof (secp256k1_pubkey));
        memcpy(&temp_PK[i]->data[0], PK_LIST[i].data, PK_BYTES);

        /* Multiply PK with corresponding exp. */
        return_val += !secp256k1_ec_pubkey_tweak_mul(ctx, temp_PK[i], exp_LIST[i]);
    }
    /* Compute X = SUM(temp_PK[i] * exp_LIST[i])
     * Get x_only X -> schnorr sig verification param.*/
    return_val += !secp256k1_ec_pubkey_combine(ctx, X_, (const secp256k1_pubkey *const *)temp_PK, N);
    return_val += !secp256k1_xonly_pubkey_from_pubkey(ctx, xo_X_, parity_X, X_);
    return_val += !secp256k1_xonly_pubkey_serialize(ctx, sxo_X_, xo_X_);

    if (return_val != 0) return 0;
    else return 1;

}


int CALC_Exponent(const secp256k1_context* ctx, unsigned char** sxo_PK_LIST, unsigned char** exp_LIST, unsigned char* L, int N ) {

    int i;
    int return_val = 0;
    unsigned char tag[13] = "BIP0340/nonce";   /* Tag of hash to generate the exponents */
    unsigned char cat_temp[XONLY_BYTES*(N+1)]; /* Temp to store (L||sX_i) */

    memcpy(&cat_temp[0], L, XONLY_BYTES*N );   /* Copy L into cat_temp */

    for(i=0; i<N;i++){
        exp_LIST[i] = malloc(SCALAR_BYTES);
        memcpy(&cat_temp[XONLY_BYTES*N], sxo_PK_LIST[i], XONLY_BYTES );  /* Copy sxo_PK_LIST[i] besides L */
        return_val += !secp256k1_tagged_sha256(ctx, exp_LIST[i], tag, sizeof (tag), cat_temp, sizeof (cat_temp));
    }
    if (return_val != 0) return 0;
    else return 1;

}


void BATCH_Commitment(const secp256k1_context* ctx, secp256k1_pubkey** COMM_LIST, unsigned char** nonce_LIST, int* cnt, int NR_MSGS, int V){

    int j,k;
    for (k = 0; k < NR_MSGS; k++){
        for (j = 0; j < V; j++) {
            nonce_LIST[*cnt] = malloc(SCALAR_BYTES);
            COMM_LIST[*cnt] = malloc(sizeof(secp256k1_pubkey));
            while (1) {
                if (!fill_random(nonce_LIST[*cnt], SCALAR_BYTES)) {
                    printf("Failed to generate randomness\n");
                    return;
                }
                if (secp256k1_ec_pubkey_create(ctx, COMM_LIST[*cnt], nonce_LIST[*cnt]))
                    break;
            }
            (*cnt)++;
        }
    }
}


int SIG_Partial(const secp256k1_context* ctx, secp256k1_pubkey** COMM_LIST, unsigned char** sec_nonce_LIST, unsigned char* sxo_R, unsigned char* par_sig, unsigned char* seckey, unsigned char* sxo_X_, unsigned char* exp, unsigned char* msg_hash, int parity_X, int* parity_XR, int STATE, int N, int V){

    int i, j, k;
    int return_val = 0;
    int parity_R = 0;
    unsigned char b[SCALAR_BYTES];                      /* b = H (aggr_COMMS, sxo_X_, msg_hash) */
    unsigned char c[SCALAR_BYTES];                      /* Challenge */
    unsigned char** b_LIST = malloc(SCALAR_BYTES*V);    /* The list of b values, b_LIST = {b^(j-1)} */
    secp256k1_pubkey* aggr_COMMS[V];
    secp256k1_pubkey* temp_COMMS[N];


    int ind = STATE*(V*N);
    for (j=0; j<V; j++){
        k = j+ind;
        i=0;
        while (i<N){
            temp_COMMS[i] = malloc(sizeof (secp256k1_pubkey));
            temp_COMMS[i] = COMM_LIST[k];
            i++; k = k+V;
        }
        aggr_COMMS[j] = malloc(sizeof (secp256k1_pubkey));
        return_val += !secp256k1_ec_pubkey_combine(ctx, aggr_COMMS[j], (const secp256k1_pubkey *const *) temp_COMMS, N);
    }
    return_val += !CALC_b(ctx, aggr_COMMS, sxo_X_, b, msg_hash, V);
    return_val += !CALC_Nonce(ctx, aggr_COMMS, b_LIST, sxo_R, b, &parity_R, V);
    return_val += !CALC_Challenge(ctx, sxo_X_, sxo_R, msg_hash, c);

    /* If both parity_R and parity_X are 1, then set parity_XR to 1 to negate
     * aggregated signature at the end of Musig process. */
    if (parity_R == 1 && parity_X == 1 ){
        return_val += !SET_Response(ctx, b_LIST, sec_nonce_LIST, par_sig, c, exp, seckey, parity_R, V);
        *parity_XR = 1;
    }
    /* If parity_R is 1, then negate b and call CALC_Nonce again. */
    else if (parity_R == 1 && parity_X == 0){
        return_val += !secp256k1_ec_seckey_negate(ctx, b);
        return_val += !CALC_Nonce(ctx, aggr_COMMS, b_LIST, sxo_R, b, &parity_R, V);
        parity_R = -1;
        return_val += !SET_Response(ctx, b_LIST, sec_nonce_LIST, par_sig, c, exp, seckey, parity_R, V);
    }
    /* If parity_X is 1, negate c. */
    else if (parity_R == 0 && parity_X == 1){
        return_val += !secp256k1_ec_seckey_negate(ctx, c);
        return_val += !SET_Response(ctx, b_LIST, sec_nonce_LIST, par_sig, c, exp, seckey, parity_R, V);
    }
    /* If both parity_R and parity_X are 0, set response with existing parameters. */
    else{
        return_val += !SET_Response(ctx, b_LIST, sec_nonce_LIST, par_sig, c, exp, seckey, parity_R, V);
    }

    if (return_val != 0) return 0;
    else return 1;

}


int CALC_b(const secp256k1_context* ctx, secp256k1_pubkey** aggr_COMMS, unsigned char* sxo_X_, unsigned char* b, unsigned char* msg_hash, int V) {

    int j;
    int return_val = 0;
    unsigned char tag[13] = "BIP0340/nonce";    /* Tag of the hash to compute b */
    unsigned char temp_X[XONLY_BYTES];
    unsigned char catXR[(2+V)*XONLY_BYTES];     /* Temp value to store (sxo_X_ || R_1 || ... || R_V || msg) */
    secp256k1_xonly_pubkey xonly_temp;

    memcpy(&catXR[0], sxo_X_, XONLY_BYTES);     /* Copy sxo_X_ into catXR */

    for (j=0; j<V; j++){
        /* Get x_only R_j, Serialize x_only R_j, and Concatenate. */
        return_val += !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_temp, NULL, aggr_COMMS[j]);
        secp256k1_xonly_pubkey_serialize(ctx, temp_X, &xonly_temp);
        memcpy(&catXR[XONLY_BYTES*(j+1)], temp_X, XONLY_BYTES);
    }
    /* Concatenate msg to end */
    memcpy(&catXR[(1+V)*XONLY_BYTES], msg_hash, XONLY_BYTES);

    /* Compute b */
    return_val += !secp256k1_tagged_sha256(ctx, b, tag, sizeof (tag), catXR, sizeof(catXR));

    if (return_val != 0)    return 0;
    else                    return 1;

}


int CALC_Nonce(const secp256k1_context *ctx, secp256k1_pubkey **aggr_COMMS, unsigned char **b_LIST, unsigned char *sxo_R, unsigned char *b, int* parity_R, int V) {

    int j;
    int loop_flag = 0;
    int combine_flag = 0;
    secp256k1_pubkey* Rb_LIST[V];
    secp256k1_pubkey R;
    secp256k1_xonly_pubkey xonly_temp;

    /* Compute b_LIST = { b^(j-1) } and Rb_LIST = { R_j * b^(j-1) } */
    for (j=0; j<V; j++){
        Rb_LIST[j] = malloc(sizeof (secp256k1_pubkey));
        b_LIST[j] = malloc(SCALAR_BYTES);
        memcpy(&Rb_LIST[j]->data[0], aggr_COMMS[j]->data, PK_BYTES);
        if (j == 0 && *parity_R == 0){
            continue;
        }
        else if (j == 0 && *parity_R == 1){
            loop_flag += !secp256k1_ec_pubkey_negate(ctx,Rb_LIST[j]);
        }
        else {
            if (j == 1){
                memcpy(&b_LIST[j][0], b, SCALAR_BYTES); /* If j = 1 -> b_LIST[j] = b .*/
                loop_flag += !secp256k1_ec_pubkey_tweak_mul(ctx, Rb_LIST[j], b_LIST[j]);
            }
            else{
                memcpy(&b_LIST[j][0], b_LIST[j-1], SCALAR_BYTES);   /* Copy b^(j-1) to b_LIST[j]*/
                /* Compute b * b^(j-1) */
                loop_flag += !secp256k1_ec_seckey_tweak_mul(ctx, b_LIST[j], b) ;
                loop_flag += !secp256k1_ec_seckey_negate(ctx, b_LIST[j]);
                loop_flag += !secp256k1_ec_pubkey_tweak_mul(ctx, Rb_LIST[j], b_LIST[j]);
            }
        }
    }
    /* R = SUM ({ R_j * b^(j-1) }) */
    /* Get x_only R */
    /* Serialize x_only R into sxo_R */
    combine_flag += !secp256k1_ec_pubkey_combine(ctx, &R, (const secp256k1_pubkey *const *)Rb_LIST, V) ;
    combine_flag += !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_temp, parity_R, &R);
    combine_flag += !secp256k1_xonly_pubkey_serialize(ctx, sxo_R, &xonly_temp);

    if (loop_flag != 0 || combine_flag != 0) return 0;
    else                                     return 1;

}


int CALC_Challenge(const secp256k1_context* ctx, const unsigned char* sxo_X_, unsigned char* sxo_R, unsigned char* msg_hash, unsigned char* c){

    unsigned char tag[17] = "BIP0340/challenge";        /* Tag of the hash to compute challenge. */
    unsigned char catXRM[XONLY_BYTES*2+SCALAR_BYTES];   /* Temp to store ( sxo_R || sxo_X_ || msg_hash ) */

    memcpy(&catXRM[0], sxo_R, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES], sxo_X_, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES*2], msg_hash, SCALAR_BYTES);

    if (!secp256k1_tagged_sha256(ctx, c, tag , sizeof (tag), catXRM, SCALAR_BYTES * 3))
        return  0;
    else
        return 1;

}


int SET_Response(const secp256k1_context* ctx, unsigned char** b_LIST, unsigned char** sec_nonce_LIST, unsigned char* par_sig, unsigned char* c, unsigned char* exp, unsigned char* seckey, int parity_R, int V){

    int j;
    int return_val = 0;
    unsigned char temp_rb[SCALAR_BYTES];
    unsigned char sum_rb[SCALAR_BYTES];

    /* Compute (exp * sk * c) */
    memcpy(&par_sig[0], c, SCALAR_BYTES);
    return_val += !secp256k1_ec_seckey_tweak_mul(ctx, par_sig, seckey);
    return_val += !secp256k1_ec_seckey_tweak_mul(ctx, par_sig, exp);


    for (j = 0; j < V; j++) {
        if (j == 0 && parity_R == -1) {
            /* If j = 0, b = -1 */
            return_val += !secp256k1_ec_seckey_negate(ctx, sec_nonce_LIST[j]);
            memcpy(&sum_rb[0], sec_nonce_LIST[j], SCALAR_BYTES);
        }
        else if (j == 0) {
            /* If j = 0, b = 1 */
            memcpy(&sum_rb[0], sec_nonce_LIST[j], SCALAR_BYTES);
        }
        else {
            /* Copy nonce to temp_rb, r_j * b_LIST[j], Add to temp_rb to sum_rb. */
            memcpy(&temp_rb[0], sec_nonce_LIST[j], SCALAR_BYTES);
            return_val += !secp256k1_ec_seckey_tweak_mul(ctx, temp_rb, b_LIST[j]);
            return_val += !secp256k1_ec_seckey_tweak_add(ctx, sum_rb, temp_rb);
        }
    }
    /* Finalize response */
    return_val += !secp256k1_ec_seckey_tweak_add(ctx, par_sig, sum_rb);

    if (return_val != 0) return 0;
    else                 return 1;
}


void AGG_SIG_SecondRound(const secp256k1_context* ctx, unsigned char** par_sig_LIST, unsigned char* agg_sig, int N)  {

    int i;

    /* Copy the content of first signature in agg_sig. */
    memcpy(&agg_sig[0], par_sig_LIST[0], SCALAR_BYTES);

    /* Add all signatures and store it in agg_sig. */
    for (i=1; i<N; i++){
        if(!secp256k1_ec_seckey_tweak_add(ctx, agg_sig, par_sig_LIST[i])){
            printf("Failed to aggregate signature!\n");
            return;
        }
    }
}



