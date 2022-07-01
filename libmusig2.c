#include "libmusig2.h"


void INIT_Signer(secp256k1_context* ctx, secp256k1_keypair* signer){
    unsigned char seckey[SK_BYTES];
    secp256k1_xonly_pubkey pubkey;
    int parity = 0;
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return;
        }
        /* Try to create a keypair with a valid context, it should only fail if
         * the secret key is zero or out of range. */
        if (secp256k1_keypair_create(ctx, signer, seckey)){
            secp256k1_keypair_xonly_pub(ctx, &pubkey, &parity, signer);
            if (parity == 0)
                break;
        }
    }
}

void AGG_Key(const secp256k1_context* ctx, secp256k1_pubkey* PK_LIST, unsigned char** exp_LIST, secp256k1_pubkey* X_){
    int i;
    secp256k1_pubkey* temp_PK[N];
    for(i=0; i<N;i++){
        temp_PK[i] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
        memcpy(&temp_PK[i]->data[0], PK_LIST[i].data, 64);
        secp256k1_ec_pubkey_tweak_mul(ctx, temp_PK[i], exp_LIST[i]); /* Multiply PK with corresponding exp. */
    }
    secp256k1_ec_pubkey_combine(ctx, X_, (const secp256k1_pubkey *const *)temp_PK, N); /* Compute X = SUM(X_i * exp_i) */
}

void CALC_Exponent(const secp256k1_context* ctx, const unsigned char** s_PK_LIST, unsigned char* L, unsigned char** exp_LIST){
    int i;
    unsigned char tag[13] = "BIP0340/nonce";   /* Tag of hash to generate the exponents */
    unsigned char cat_temp[SK_BYTES*(N+1)]; /* Temp to store (L||sX_i) */
    memcpy(&cat_temp[0], L, SK_BYTES*N );   /* Copy L into cat_temp */
    for(i=0; i<N;i++){
        exp_LIST[i] = (unsigned char*) malloc(SK_BYTES);
        memcpy(&cat_temp[SK_BYTES*N],s_PK_LIST[i], SK_BYTES );  /* Concatenate sX_i besides L */
        secp256k1_tagged_sha256(ctx, exp_LIST[i], tag, sizeof (tag), cat_temp, sizeof (cat_temp));
    }
}

void BATCH_Commitment(const secp256k1_context* ctx, secp256k1_pubkey** COMM_R , unsigned char** nonce_r, int* cnt){
    int i,j,k;
    for (k = 0; k < NR_MSGS; k++){
//        for(i=0; i<N;i++) {
            for (j = 0; j < V; j++) {
                nonce_r[*cnt] = (unsigned char *) malloc(SK_BYTES);
                COMM_R[*cnt] = (secp256k1_pubkey *) malloc(sizeof(secp256k1_pubkey));
                while (1) {
                    if (!fill_random(nonce_r[*cnt], SK_BYTES)) {
                        printf("Failed to generate randomness\n");
                        return;
                    }
                    if (secp256k1_ec_pubkey_create(ctx, COMM_R[*cnt], nonce_r[*cnt]))
                        break;
                }
                (*cnt)++;
            }
//        }
    }
}

void SIG_Partial(const secp256k1_context* ctx, unsigned char* par_sig, unsigned char* sk, unsigned char* SX, secp256k1_pubkey** COMM_R, unsigned char** s_nonce, unsigned char* sx_NONCE, secp256k1_pubkey* NONCE, unsigned char* exp, unsigned char* msg, int STATE)
{
    unsigned char c[SK_BYTES];

    int i, j, k;
    secp256k1_pubkey* aggr_COMMS[V];
    secp256k1_pubkey* temp_COMMS[N];
    int ind = STATE*(V*N);
    for ( j=0; j<V; j++){
        k = j+ind;
        i=0;
        while (i<N){
            temp_COMMS[i] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
            temp_COMMS[i] = COMM_R[k];
            k = k+V;
            i++;
        }
        aggr_COMMS[j] =(secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
        secp256k1_ec_pubkey_combine(ctx, aggr_COMMS[j], (const secp256k1_pubkey *const *) temp_COMMS, N);
    }
    unsigned char** b_LIST = (unsigned char**) malloc(SK_SIZE*V);
    CALC_Nonce(ctx, sx_NONCE, NONCE, b_LIST, SX, aggr_COMMS, msg);
    CALC_Challenge(ctx, SX, sx_NONCE, msg, c);
    SET_Response(ctx, par_sig, c, exp, sk, b_LIST, s_nonce);
}

void CALC_Nonce(const secp256k1_context* ctx, unsigned char* sx_NONCE, secp256k1_pubkey* NONCE, unsigned char** b_LIST, unsigned char* SX,  secp256k1_pubkey** aggr_COMMS, unsigned char* msg){
    int j;
    unsigned char tag[13] = "BIP0340/nonce"; /* Tag of the hash to compute b */
    unsigned char b[SK_BYTES];

    secp256k1_xonly_pubkey xonly_temp;
    unsigned char temp_X[SK_BYTES];
    unsigned char catXR[(2+V)*SK_BYTES];    /* Temp value to store (SX || R_0 || ... || R_V || msg) */
    memcpy(&catXR[0], SX, SK_BYTES);        /* Copy SX into catXR */

    for (j=0; j<V; j++){
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_temp, NULL, aggr_COMMS[j]);  /* Get x_only R_j*/
        secp256k1_xonly_pubkey_serialize(ctx, temp_X, &xonly_temp);                 /* Serialize x_only R_j */
        memcpy(&catXR[SK_BYTES*(j+1)], temp_X, SK_BYTES);                           /* Concatenate */
    }
    memcpy(&catXR[(1+V)*SK_BYTES], msg, SK_BYTES);  /* Concatenate msg to end */

    if (!secp256k1_tagged_sha256(ctx, b, tag, sizeof (tag), catXR, sizeof(catXR))){     /* Compute b */
        printf("Failed to generate b!\n");
        return;
    }

    /* Compute b_LIST = { b^(j-1) } */
    /* Compute Rb_LIST = { R_j * b^(j-1) } */
    secp256k1_pubkey* Rb_LIST[V];
    for (j=0; j<V; j++){
        Rb_LIST[j] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
        b_LIST[j] = (unsigned char*) malloc(SK_BYTES);
        memcpy(&Rb_LIST[j]->data[0], aggr_COMMS[j]->data, 64);
        if (j == 0){    /*  NOTE!!!!!! Cannot assign 1 as a group element. !!!!! */
            /* Skip to assign for j = 0 -> b = 1. */
        }
        else {
            if (j == 1){
                memcpy(&b_LIST[j][0], b, SK_BYTES); /* If j = 1 -> b_LIST[j] = b .*/
                secp256k1_ec_pubkey_tweak_mul(ctx, Rb_LIST[j], b_LIST[j]);
            }
            else{
                memcpy(&b_LIST[j][0], b_LIST[j-1], SK_BYTES);   /* Copy b^(j-1) to b_LIST[j]*/
                secp256k1_ec_seckey_tweak_mul(ctx, b_LIST[j], b);   /* Compute b * b^(j-1) */
                secp256k1_ec_pubkey_tweak_mul(ctx, Rb_LIST[j], b_LIST[j]);
            }
        }
    }
    int parity = 0;
    secp256k1_ec_pubkey_combine(ctx, NONCE, (const secp256k1_pubkey *const *)Rb_LIST, V);   /* NONCE = SUM ({ R_j * b^(j-1) }) */
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_temp, &parity, NONCE);                      /* Get x_only NONCE */
    secp256k1_xonly_pubkey_serialize(ctx, sx_NONCE, &xonly_temp);                           /* Serialize x_only NONCE into sx_NONCE */
}

void CALC_Challenge(const secp256k1_context* ctx,  const unsigned char* SX,  unsigned char* sx_NONCE,  unsigned char* msg,  unsigned char* c){

    unsigned char tag[17] = "BIP0340/challenge";    /* Tag of the hash to compute challenge. */
    unsigned char catXRM[SK_BYTES*3];               /* Temp to store ( sx_NONCE || SX || msg ) */

    memcpy(&catXRM[0], sx_NONCE, SK_BYTES);
    memcpy(&catXRM[SK_BYTES], SX, SK_BYTES);
    memcpy(&catXRM[SK_BYTES*2], msg, SK_BYTES);

    secp256k1_tagged_sha256(ctx, c, tag , sizeof (tag), catXRM, SK_BYTES * 3);

}

void SET_Response(const secp256k1_context* ctx,  unsigned char* resp, unsigned char* c, unsigned char* exp, unsigned char* sk, unsigned char** b_LIST,  unsigned char** s_nonce){
    int j;

    /* Compute (exp * sk * c) */
    memcpy(&resp[0], c, SK_BYTES);
    secp256k1_ec_seckey_tweak_mul(ctx, resp, sk);
    secp256k1_ec_seckey_tweak_mul(ctx, resp, exp);

    unsigned char temp_rb[SK_BYTES];
    unsigned char sum_rb[SK_BYTES];

    for (j = 0; j < V; j++) {
        if (j == 0)
            memcpy(&sum_rb[0], s_nonce[j], SK_BYTES);   /* If j = 0, b = 1 */
        else{
            memcpy(&temp_rb[0], s_nonce[j], SK_BYTES);  /* Copy nonce to temp */
            secp256k1_ec_seckey_tweak_mul(ctx, temp_rb, b_LIST[j]); /* r_j * b_LIST[j] */
            secp256k1_ec_seckey_tweak_add(ctx, sum_rb, temp_rb);    /* Add to summation */
        }
    }
    secp256k1_ec_seckey_tweak_add(ctx, resp, sum_rb);   /* Finalize response */
}

void AGG_SIG_SecondRound(const secp256k1_context* ctx, unsigned char** SIG_LIST, unsigned char* AGGSIG2){

    int i;
    /* Copy the content of first signature in AGGSIG2. */
    memcpy(&AGGSIG2[0], SIG_LIST[0], SK_BYTES);

    /* Add all signatures and store it in AGGSIG2. */
    for (i=1; i<N; i++){
        if(!secp256k1_ec_seckey_tweak_add(ctx, AGGSIG2, SIG_LIST[i])){
            printf("Failed to aggregate signature!\n");
            return;
        }
    }
}

int MAN_VER_SIG(const secp256k1_context* ctx, unsigned char* AGGSIG2, secp256k1_pubkey* NONCE, secp256k1_pubkey* X_, unsigned char* msg){

    secp256k1_xonly_pubkey xonlyX;
    secp256k1_xonly_pubkey xonlyNONCE;
    secp256k1_pubkey* temp_Xc[2];


    unsigned char ser_xonlyX[SK_BYTES];
    unsigned char ser_xonlyNONCE[SK_BYTES];
    unsigned char c[SK_BYTES];

    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlyX, NULL, X_);
    secp256k1_xonly_pubkey_serialize(ctx, ser_xonlyX, &xonlyX);

    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlyNONCE, NULL, NONCE);
    secp256k1_xonly_pubkey_serialize(ctx, ser_xonlyNONCE, &xonlyNONCE);

    CALC_Challenge(ctx, ser_xonlyX, ser_xonlyNONCE, msg, c);

    secp256k1_pubkey* RXc = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
    secp256k1_pubkey* Gs = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));

    temp_Xc[0] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
    temp_Xc[1] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
    memcpy(&temp_Xc[0]->data[0], X_->data, 64);
    memcpy(&temp_Xc[1]->data[0], NONCE->data, 64);

    secp256k1_ec_pubkey_tweak_mul(ctx, temp_Xc[0], c);
    secp256k1_ec_pubkey_combine(ctx, RXc,(const secp256k1_pubkey *const *)temp_Xc,2);

    secp256k1_ec_pubkey_create(ctx, Gs, AGGSIG2);

    return secp256k1_ec_pubkey_cmp(ctx, Gs, RXc);
}





