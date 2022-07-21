#include "libmusig2.h"


void MuSig2_KeyGen(secp256k1_context *ctx,
                   secp256k1_keypair *signer_keypair) {

    unsigned char x[SCALAR_BYTES];
    while (1) {
        if (!fill_random(x, sizeof(x))) {
            printf("Failed to generate randomness\n");
            return;
        }
        /* Try to create a keypair with a valid context, it should only fail if
         * the secret key is zero or out of range. */
        if (secp256k1_keypair_create(ctx, signer_keypair, x))
            break;
    }
}


int MuSig2_KeyAgg(const secp256k1_context *ctx,
                  secp256k1_pubkey *X_LIST, secp256k1_pubkey *X_,
                  secp256k1_xonly_pubkey *xonly_X_,
                  unsigned char *ser_xonly_X_, unsigned char **a_LIST,
                  int *parity_X_, int N)  {

    int i;
    int return_val = 0;
    secp256k1_pubkey* temp_X_LIST[N];

    /* Multiply X_i with a_i. Store in temp_X_LIST[i]. */
    for(i=0; i<N;i++){
        temp_X_LIST[i] = malloc(sizeof (secp256k1_pubkey));
        memcpy(&temp_X_LIST[i]->data[0], X_LIST[i].data, PK_BYTES);
        return_val += !secp256k1_ec_pubkey_tweak_mul(ctx, temp_X_LIST[i], a_LIST[i]);
    }

    /* Compute X = SUM(temp_X_LIST[i] * a_LIST[i]) for i = 1,..., n.
     * Get x_only X => schnorr sig verification param. */
    return_val += !secp256k1_ec_pubkey_combine(ctx, X_, (const secp256k1_pubkey *const *)temp_X_LIST, N);
    return_val += !secp256k1_xonly_pubkey_from_pubkey(ctx, xonly_X_, parity_X_, X_);
    return_val += !secp256k1_xonly_pubkey_serialize(ctx, ser_xonly_X_, xonly_X_);

    if (return_val != 0) return 0;
    else return 1;

}


int MuSig2_KeyAggCoef(const secp256k1_context *ctx,
                      unsigned char **ser_xonly_X_LIST, unsigned char **a_LIST, unsigned char *L,
                      int N ) {

    int i;
    int return_val = 0;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag of hash to generate the exponents
    unsigned char concat[XONLY_BYTES*(N+1)];    // Temp to store (L||ser_xonly_X[i])

    memcpy(&concat[0], L, XONLY_BYTES*N );      // Copy L into concat

    for(i=0; i<N;i++){
        a_LIST[i] = malloc(SCALAR_BYTES);
        memcpy(&concat[XONLY_BYTES*N], ser_xonly_X_LIST[i], XONLY_BYTES );  /* Copy ser_xonly_X_LIST[i] besides L */
        return_val += !secp256k1_tagged_sha256(ctx, a_LIST[i], tag, sizeof (tag), concat, sizeof (concat));
    }
    if (return_val != 0) return 0;
    else return 1;

}


void MuSig2_BatchCommitment(const secp256k1_context *ctx,
                            secp256k1_pubkey **R_LIST,
                            unsigned char **r_LIST,
                            int i, int N, int NR_MSGS, int V) {

    int j,k;
    int R_index;
    int r_index = 0;

    for (k = 0; k < NR_MSGS; k++){
        for (j = 0; j < V; j++) {
            R_index = N*V*k + i*V + j;
            r_LIST[r_index] = malloc(SCALAR_BYTES);
            R_LIST[R_index] = malloc(sizeof(secp256k1_pubkey));
            while (1) {
                if (!fill_random(r_LIST[r_index], SCALAR_BYTES)) {
                    printf("Failed to generate randomness\n");
                    return;
                }
                if (secp256k1_ec_pubkey_create(ctx, R_LIST[R_index], r_LIST[r_index]))
                    break;
            }
            r_index++;
        }
    }
}


int MuSig2_SignPartial(const secp256k1_context *ctx,
                        secp256k1_pubkey **R_LIST,
                        unsigned char **r_LIST, unsigned char *ser_xonly_R, unsigned char *parsig, unsigned char *x, unsigned char *ser_xonly_X_, unsigned char *a, unsigned char *msg_hash,
                        int parity_X_, int *parity_RX_, int STATE, int N, int V) {

    int i, j, k;
    int return_val = 0;
    int parity_R = 0;

    secp256k1_pubkey* aggr_R_LIST[V];                   // aggr_R_LIST[j] = SUM (R_LIST[i]) for i = 1..n
    secp256k1_pubkey* temp_R_LIST[N];

    unsigned char b[SCALAR_BYTES];                      // b = H (aggr_R_LIST, ser_xonly_X_, msg_hash)
    unsigned char c[SCALAR_BYTES];                      // Challenge
    unsigned char** b_LIST = malloc(SCALAR_BYTES*V);    // The list of b values, b_LIST = {b^(j-1)}

    unsigned char* sr_list[V];

    int index = V*STATE;
    for(j = 0; j<V; j++)
        sr_list[j] = r_LIST[index+j];

    int ind = STATE*(V*N);
    for (j=0; j<V; j++){
        k = j+ind;
        i=0;
        while (i<N){
            temp_R_LIST[i] = malloc(sizeof (secp256k1_pubkey));
            temp_R_LIST[i] = R_LIST[k];
            i++; k = k+V;
        }
        aggr_R_LIST[j] = malloc(sizeof (secp256k1_pubkey));
        return_val += !secp256k1_ec_pubkey_combine(ctx, aggr_R_LIST[j], (const secp256k1_pubkey *const *) temp_R_LIST, N);
    }
    return_val += !Calc_b(ctx, aggr_R_LIST, ser_xonly_X_, b, msg_hash, V);
    return_val += !Calc_R(ctx, aggr_R_LIST, b_LIST, ser_xonly_R, b, &parity_R, V);
    return_val += !Calc_c(ctx, ser_xonly_X_, ser_xonly_R, msg_hash, c);

    /* If both parity_R and parity_X_ are 1, then set parity_RX_ to 1 to negate
     * aggregated signature at the end of Musig process. */
    if (parity_R == 1 && parity_X_ == 1 ){
        return_val += !Set_parsig(ctx, b_LIST, sr_list, parsig, c, a, x, parity_R, V);
        *parity_RX_ = 1;
    }
    /* If parity_R is 1, then negate b and call Calc_R again. */
    else if (parity_R == 1 && parity_X_ == 0){
        return_val += !secp256k1_ec_seckey_negate(ctx, b);
        return_val += !Calc_R(ctx, aggr_R_LIST, b_LIST, ser_xonly_R, b, &parity_R, V);
        parity_R = -1;
        return_val += !Set_parsig(ctx, b_LIST, sr_list, parsig, c, a, x, parity_R, V);
    }
    /* If parity_X_ is 1, negate c. */
    else if (parity_R == 0 && parity_X_ == 1){
        return_val += !secp256k1_ec_seckey_negate(ctx, c);
        return_val += !Set_parsig(ctx, b_LIST, sr_list, parsig, c, a, x, parity_R, V);
    }
    /* If both parity_R and parity_X_ are 0, set partial signature with existing parameters. */
    else{
        return_val += !Set_parsig(ctx, b_LIST, sr_list, parsig, c, a, x, parity_R, V);
    }

    /* Consume the used r values to prevent reuse.*/
    for(j = 0; j<V; j++)
        r_LIST[index+j] = NULL;

    if (return_val != 0) return 0;
    else return 1;

}


void MuSig2_AggSignatures(const secp256k1_context *ctx,
                          unsigned char **parsig_LIST, unsigned char *aggsig,
                          int N)  {

    int i;

    /* Copy the content of first signature in aggsig. */
    memcpy(&aggsig[0], parsig_LIST[0], SCALAR_BYTES);

    /* Add all signatures and store it in aggsig. */
    for (i=1; i<N; i++)
        if(!secp256k1_ec_seckey_tweak_add(ctx, aggsig, parsig_LIST[i])){
            printf("Failed to aggregate signature!\n");
            return;
        }
}




int Calc_b(const secp256k1_context *ctx,
           secp256k1_pubkey **aggr_R_LIST,
           unsigned char *ser_xonly_X_, unsigned char *b, unsigned char *msg_hash,
           int V) {

    int j;
    int return_val = 0;
    unsigned char tag[13] = "BIP0340/nonce";        // Tag of the hash to compute b
    unsigned char temp_X[XONLY_BYTES];
    unsigned char catXR[(2+V)*XONLY_BYTES];         // Temp value to store (ser_xonly_X_ || R_1 || ... || R_V || msg)
    secp256k1_xonly_pubkey xonly_temp;

    /* Copy ser_xonly_X_ into catXR */
    memcpy(&catXR[0], ser_xonly_X_, XONLY_BYTES);

    /* Get x_only R_j, Serialize x_only R_j, and Concatenate. */
    for (j=0; j<V; j++){
        return_val += !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_temp, NULL, aggr_R_LIST[j]);
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


int Calc_R(const secp256k1_context *ctx,
           secp256k1_pubkey **aggr_R_LIST,
           unsigned char **b_LIST, unsigned char *ser_xonly_R, unsigned char *b,
           int* parity_R, int V) {

    int j;
    int loop_flag = 0;
    int combine_flag = 0;
    secp256k1_pubkey* Rb_LIST[V];
    secp256k1_pubkey R;
    secp256k1_xonly_pubkey xonly_temp;

    /* Compute b_LIST = { b^(j-1) } and
     * Rb_LIST = { R_j * b^(j-1) } */
    for (j=0; j<V; j++){
        Rb_LIST[j] = malloc(sizeof (secp256k1_pubkey));
        b_LIST[j] = malloc(SCALAR_BYTES);
        memcpy(&Rb_LIST[j]->data[0], aggr_R_LIST[j]->data, PK_BYTES);

        if (j == 0 && *parity_R == 0) continue;
        else if (j == 0 && *parity_R == 1)
            loop_flag += !secp256k1_ec_pubkey_negate(ctx,Rb_LIST[j]);
        else {
            if (j == 1){
                /* If j = 1 => b_LIST[j] = b .*/
                memcpy(&b_LIST[j][0], b, SCALAR_BYTES);
                loop_flag += !secp256k1_ec_pubkey_tweak_mul(ctx, Rb_LIST[j], b_LIST[j]);
            }
            else{
                memcpy(&b_LIST[j][0], b_LIST[j-1], SCALAR_BYTES);
                /* Compute b * b^(j-1) */
                loop_flag += !secp256k1_ec_seckey_tweak_mul(ctx, b_LIST[j], b) ;
                loop_flag += !secp256k1_ec_seckey_negate(ctx, b_LIST[j]);
                loop_flag += !secp256k1_ec_pubkey_tweak_mul(ctx, Rb_LIST[j], b_LIST[j]);
            }
        }
    }

    /* R = SUM ({ R_j * b^(j-1) })
     * Get x_only R, store in xonly_temp
     * Get parity R to check whether b is needed to be negated.
     * Serialize x_only R into ser_xonly_R */
    combine_flag += !secp256k1_ec_pubkey_combine(ctx, &R, (const secp256k1_pubkey *const *)Rb_LIST, V) ;
    combine_flag += !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_temp, parity_R, &R);
    combine_flag += !secp256k1_xonly_pubkey_serialize(ctx, ser_xonly_R, &xonly_temp);

    if (loop_flag != 0 || combine_flag != 0) return 0;
    else                                     return 1;

}


int Calc_c(const secp256k1_context *ctx,
           const unsigned char *ser_xonly_X_, unsigned char *ser_xonly_R, unsigned char *msg_hash, unsigned char *c) {

    unsigned char tag[17] = "BIP0340/challenge";        // Tag of the hash to compute challenge.
    unsigned char catXRM[XONLY_BYTES*2+SCALAR_BYTES];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )

    memcpy(&catXRM[0], ser_xonly_R, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES], ser_xonly_X_, XONLY_BYTES);
    memcpy(&catXRM[XONLY_BYTES*2], msg_hash, SCALAR_BYTES);

    if (!secp256k1_tagged_sha256(ctx, c, tag , sizeof (tag), catXRM, SCALAR_BYTES * 3))
        return 0;
    else
        return 1;

}


int Set_parsig(const secp256k1_context* ctx,
               unsigned char **b_LIST, unsigned char **sr_LIST, unsigned char *parsig, unsigned char *c, unsigned char *a, unsigned char *x,
               int parity_R, int V)  {

    int j;
    int return_val = 0;
    unsigned char temp_rb[SCALAR_BYTES];
    unsigned char sum_rb[SCALAR_BYTES];

    /* Compute (a * x * c) */
    memcpy(&parsig[0], c, SCALAR_BYTES);
    return_val += !secp256k1_ec_seckey_tweak_mul(ctx, parsig, x);
    return_val += !secp256k1_ec_seckey_tweak_mul(ctx, parsig, a);

    /* If j = 0 => b = -1. So, r_0 * b_LIST[0] = - sec_r_LIST[0].
     * If j = 0 => b = 1.
     * Else, Copy r_j to temp_rb, compute r_j * b_LIST[j], and add temp_rb to sum_rb. */
    for (j = 0; j < V; j++) {
        if (j == 0 && parity_R == -1) {
            return_val += !secp256k1_ec_seckey_negate(ctx, sr_LIST[j]);
            memcpy(&sum_rb[0], sr_LIST[j], SCALAR_BYTES);
        }
        else if (j == 0) memcpy(&sum_rb[0], sr_LIST[j], SCALAR_BYTES);
        else {
            memcpy(&temp_rb[0], sr_LIST[j], SCALAR_BYTES);
            return_val += !secp256k1_ec_seckey_tweak_mul(ctx, temp_rb, b_LIST[j]);
            return_val += !secp256k1_ec_seckey_tweak_add(ctx, sum_rb, temp_rb);
        }
    }

    /* Finalize response */
    return_val += !secp256k1_ec_seckey_tweak_add(ctx, parsig, sum_rb);

    if (return_val != 0) return 0;
    else                 return 1;
}






