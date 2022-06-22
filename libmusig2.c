#include "libmusig2.h"


void INIT_Signer(secp256k1_context* ctx, SIGNER signer){

    size_t point_ser_len = PK_SIZE;
    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey));

	signer->sk = (unsigned char*)malloc(SK_SIZE);
	signer->PK = (unsigned char*)malloc(PK_SIZE);

	while (1){
        /* Generate a random secret key. */
		if (!fill_random(signer->sk, SK_SIZE)){
            printf("Failed to generate secret key!\n");
            return;
		}
        /* Generate the corresponding public key and serialize it in signer->PK. */
		if (secp256k1_ec_pubkey_create(ctx, pubkey, signer->sk) &&
                secp256k1_ec_pubkey_serialize(ctx, signer->PK, &point_ser_len, pubkey, SECP256K1_EC_COMPRESSED))
            break;
	}
}

void SIGN_FirstRound(const secp256k1_context* ctx, SIGNER signer){

    int j;
    size_t point_ser_len = PK_SIZE;
    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey));

    signer->r = (unsigned char**)malloc(SK_SIZE*V);
    signer->R = (unsigned char**)malloc(PK_SIZE*V);

    for(j=0; j<V;j++){
		signer->r[j] = (unsigned char*)malloc(SK_SIZE);
        signer->R[j] = (unsigned char*)malloc(PK_SIZE);

		while (1) {
            /* Generate a random r[j]. */
			if (!fill_random(signer->r[j], SK_SIZE)) {
                printf("Failed to generate randomness!\n");
                return;
			}
            /* Generate the corresponding nonce R and serialize it in R[j]. */
            if (secp256k1_ec_pubkey_create(ctx, pubkey, signer->r[j]) &&
                    secp256k1_ec_pubkey_serialize(ctx, signer->R[j], &point_ser_len, pubkey, SECP256K1_EC_COMPRESSED))
                break;
		}
    }
}

void COLLECT_Signers(AGG_ROUND1 aggRound1, const unsigned char* pk, unsigned char** R, int i)
{
    int k, j;
    aggRound1->PK_LIST[i] = (unsigned char*)malloc(PK_SIZE);

    /* Copy the content of signers public key into public key list. */
    for (k = 0; k < PK_SIZE; k++)
        aggRound1->PK_LIST[i][k] = pk[k];

    for (j = 0;  j<V ;j++) {
        aggRound1->R_LIST[j]->R[i] = (unsigned char*)malloc(PK_SIZE);

        /* Copy the content of signers nonce into nonce list. */
        for (k = 0; k < PK_SIZE; k++)
            aggRound1->R_LIST[j]->R[i][k]= R[j][k];
    }
}

void AGG_SIG_FirstRound(const secp256k1_context* ctx, AGG_ROUND1 aggRound1){

    int i, j, k = 0;
    size_t point_ser_len = PK_SIZE;

    secp256k1_pubkey* temp_OUT = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
    secp256k1_pubkey** temp_Rj = (secp256k1_pubkey**) malloc(sizeof (secp256k1_pubkey*)*N);

    for(j=0;j<V;j++){
        aggRound1->OUT_R_LIST[j] = (unsigned char*) malloc(PK_SIZE);
        for(i=0;i<N;i++){
            temp_Rj[i] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));

            /* Parse the nonce in a secp256k1_pubkey object. */
            if(!secp256k1_ec_pubkey_parse(ctx, temp_Rj[i], aggRound1->R_LIST[j]->R[i], point_ser_len))
            {
                printf("Failed to parse nonce!\n");
                return;
            }
        }
        /* Combine the nonce values in R_LIST[j] and serialize the sum in aggRound1->OUT_R_LIST[j]. */
        if( !(secp256k1_ec_pubkey_combine(ctx, temp_OUT, (const secp256k1_pubkey *const *)temp_Rj, N) &&
                secp256k1_ec_pubkey_serialize(ctx, aggRound1->OUT_R_LIST[j], &point_ser_len, temp_OUT, SECP256K1_EC_COMPRESSED)))
        {
            printf("Failed to aggregate signature!\n");
            return;
        }

        /* Copy the content of aggRound1->OUT_R_LIST into aggRound1->OUT.
         * This is done to generate a hash of output of first round signature.
         * See SET_Param(). */
        for(i=0;i<PK_SIZE;i++,k++){
            aggRound1->OUT[k] = aggRound1->OUT_R_LIST[j][i];
        }
    }
}

void AGG_Key(const secp256k1_context* ctx, AGG_ROUND1 aggRound1, PARAM_ROUND2 paramRound2){

    int i;
    size_t point_ser_len = PK_SIZE;
    unsigned char a[32];

    secp256k1_pubkey** temp_Xi = (secp256k1_pubkey**)malloc(sizeof(secp256k1_pubkey*)*N);
    secp256k1_pubkey* temp_X_ = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey));

    for(i=0;i<N;i++){
        temp_Xi[i] = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey));

        /* Parse the public key in secp256k1_pubkey object.
         * Compute the key aggregate coefficient (a) of signer i.
         * Multiply the public key of signer i with a, store it in secp256k1_pubkey array. */
        if (!(secp256k1_ec_pubkey_parse(ctx, temp_Xi[i], aggRound1->PK_LIST[i], point_ser_len) &&
                secp256k1_tagged_sha256(ctx, a, aggRound1->PK_LIST[i], PK_SIZE, paramRound2->L, PK_SIZE*N) &&
                secp256k1_ec_pubkey_tweak_mul(ctx, temp_Xi[i], a)))
        {
            printf("Failed to generate key aggregation coefficients!\n");
            return;
        }
    }
    /* Combine the temp_Xi values and serialize the sum in paramRound2->X_. */
    if (!(secp256k1_ec_pubkey_combine(ctx, temp_X_,(const secp256k1_pubkey *const *)temp_Xi,N) &&
            secp256k1_ec_pubkey_serialize(ctx, paramRound2->X_, &point_ser_len, temp_X_, SECP256K1_EC_COMPRESSED)))
    {
        printf("Failed to generate aggregate key!\n");
        return;
    }
}

void SET_Param(const secp256k1_context* ctx, PARAM_ROUND2 paramRound2, AGG_ROUND1 round1, unsigned char* msg){

    int i, j, k = 0;
    size_t point_ser_len = PK_SIZE;

    /******************** Compute b ********************/
    /* Concatenate paramRound2->X_ and round1->OUT[i] in a temp char array.
     * This is done to get a tagged hash of msg with the tag paramRound2->X_ and round1->OUT[i]. */
    unsigned char catXR[(V+1)*PK_BYTES];
    for (i = 0; i < PK_SIZE; i++,k++)
        catXR[k] = paramRound2->X_[i];
    for (i = 0; i < PK_SIZE*V; i++,k++)
        catXR[k] = round1->OUT[i];

    /* Generate b.*/
    if(!secp256k1_tagged_sha256(ctx, paramRound2->b, catXR, sizeof(catXR), msg, sizeof(msg))){
        printf("Failed to generate b!\n");
        return;
    }

    /****************** Compute STATE ******************/
    secp256k1_pubkey* state = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey));
    secp256k1_pubkey** Rj_list = (secp256k1_pubkey**)malloc(sizeof(secp256k1_pubkey*)*V);

    for(j=0;j<V;j++){
        Rj_list[j] = (secp256k1_pubkey*)malloc(sizeof(secp256k1_pubkey));
        if(j==0){

            /* Parse the output of first round signature into secp256k1_pubkey object.
             * If j is 0, then the first element of the sum will be round1->OUT_R_LIST[j] itself. */
            if(!secp256k1_ec_pubkey_parse(ctx, Rj_list[j], round1->OUT_R_LIST[j], point_ser_len))
            {
                printf("Failed to parse first round aggregate!\n");
                return;
            }
        }
        if(j==1){
            /* Parse the output of first round signature into secp256k1_pubkey object.
             * If j is 1, then the second element of the sum will be (round1->OUT_R_LIST[j]) * b . */
            if (!(secp256k1_ec_pubkey_parse(ctx, Rj_list[j], round1->OUT_R_LIST[j], point_ser_len) &&
                    secp256k1_ec_pubkey_tweak_mul(ctx, Rj_list[j], paramRound2->b)))
            {
                printf("Failed to parse first round aggregate!\n");
                return;
            }
        }
        /* Consider the case for j > 1. */
    }

    /* Combine the elements of Rj_list and serialize the sum into paramRound2->R_state. */
    if (!( secp256k1_ec_pubkey_combine(ctx, state, (const secp256k1_pubkey *const *)Rj_list, V) &&
            secp256k1_ec_pubkey_serialize(ctx, paramRound2->R_state, &point_ser_len, state, SECP256K1_EC_COMPRESSED)))
    {
        printf("Failed to generate state!\n");
        return;
    }
    /***************************************************/
}

void SIG_SecondRound(const secp256k1_context* ctx, PARAM_ROUND2 paramRound2, SIGNER signer, unsigned char* SIGNATURE, unsigned char* msg){

    int i,j;
    unsigned char* rb = (unsigned char*) malloc(SK_SIZE);
    unsigned char* sum_rb = (unsigned char*) malloc(SK_SIZE);
    unsigned char a[32];
    unsigned char c[32];


    /* Compute the key aggregate coefficient (a) of signer. */
    if(!secp256k1_tagged_sha256(ctx, a, signer->PK, PK_SIZE, paramRound2->L, PK_SIZE*N)){
        printf("Failed to generate key aggregation coefficient!\n");
        return;
    }

    /* Compute c. */
    CALC_C(ctx,paramRound2->X_,paramRound2->R_state,msg,c);

    /* Copy the signer's secret key into signature. */
    for (i = 0; i < SK_SIZE; i++)
        SIGNATURE[i] = signer->sk[i];

    /* Calculate a*c*sk. */
    if(!(secp256k1_ec_seckey_tweak_mul(ctx,SIGNATURE,a) &&
            secp256k1_ec_seckey_tweak_mul(ctx,SIGNATURE,c)))
    {
        printf("Failed to calculate signature!\n");
        return;
    }

    for (j = 0; j < V; j++){
        if(j==0){
            /* If j is 0, then the first entry of sum list will be signers r[j] itself.
             * So, copy the content of r[j] into sum_rb. */
            for (i = 0; i < SK_SIZE; i++)
                sum_rb[i] = signer->r[j][i];
        }
        if(j==1){
            /* If j = 1, then the second entry of sum list will be (r[j]) * b. */
            /* So, copy the content of r[j] into rb. */
            for (i = 0; i < SK_SIZE; i++)
                rb[i] = signer->r[j][i];
            /* Multiply r with b. */
            if(!secp256k1_ec_seckey_tweak_mul(ctx,rb,paramRound2->b)){
                printf("Failed to generate signature!\n");
                return;
            }
        }
    }
    /* Combine the values of c*a*sk and sum_rb and store it in SIGNATURE. */
    if(!(secp256k1_ec_seckey_tweak_add(ctx,sum_rb,rb) &&
            secp256k1_ec_seckey_tweak_add(ctx,SIGNATURE,sum_rb)))
    {
        printf("Failed to generate signature!\n");
        return;
    }
}

void AGG_SIG_SecondRound(const secp256k1_context* ctx, unsigned char** SIG_LIST, unsigned char* MUSIG2){

    int i;

    /* Copy the content of first signature in MUSIG2. */
    for (i = 0; i < SK_SIZE; i++)
        MUSIG2[i] = SIG_LIST[0][i];

    /* Add all signatures and store it in MUSIG2. */
    for (i = 1; i < N; i++){
        if(!secp256k1_ec_seckey_tweak_add(ctx,MUSIG2,SIG_LIST[i])){
            printf("Failed to aggregate signature!\n");
            return;
        }
    }
}

int VER_Musig2(const secp256k1_context* ctx, VER_MUSIG2 verMusig2, unsigned char* msg){

    size_t point_ser_len = PK_SIZE;

    unsigned char c[32];

    secp256k1_pubkey** temp_Xc = (secp256k1_pubkey**) malloc(sizeof (secp256k1_pubkey*)*2);
    temp_Xc[0] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
    temp_Xc[1] = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));

    secp256k1_pubkey* RXc = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));
    secp256k1_pubkey* Gs = (secp256k1_pubkey*) malloc(sizeof (secp256k1_pubkey));

    /* Calculate c. */
    CALC_C(ctx,verMusig2->X,verMusig2->STATE,msg,c);

    int return_val = 0;

    /* Parse the aggregated public key in secp256k1_pubkey object temp_Xc[0]. */
    return_val += secp256k1_ec_pubkey_parse(ctx, temp_Xc[0], verMusig2->X, point_ser_len);

    /* Parse the aggregated state in secp256k1_pubkey object temp_Xc[1]. */
    return_val += secp256k1_ec_pubkey_parse(ctx, temp_Xc[1], verMusig2->STATE, point_ser_len);

    /* Compute X*c. */
    return_val += secp256k1_ec_pubkey_tweak_mul(ctx, temp_Xc[0], c);

    /* Compute R + (X*c). */
    return_val += secp256k1_ec_pubkey_combine(ctx, RXc,(const secp256k1_pubkey *const *)temp_Xc,2);

    if(return_val!=4){
        printf("Failed to generate verification parameters!\n");
        return -1;
    }

    /* Compute G*s to verify signature. */
    if(!secp256k1_ec_pubkey_create(ctx, Gs, verMusig2->out)){
        printf("Failed to verify signature!\n");
        return -1;
    }

    // PRINT VERIFICATION *****
    /*
    unsigned char gs[33];
    unsigned char rxc[33];
    secp256k1_ec_pubkey_serialize(ctx, rxc, &point_ser_len, RXc, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, gs, &point_ser_len, Gs, SECP256K1_EC_COMPRESSED);
    printf("RXC\n");
    print_hex(rxc,PK_SIZE);
    printf("MUSIG\n");
    print_hex(gs,PK_SIZE); */


    if(secp256k1_ec_pubkey_cmp(ctx, Gs, RXc)== 0)
        return 1;
    else
        return 0;
}


/***************************************************/
/*************** HELPER FUNCTIONS ******************/
/***************************************************/

void GEN_L(const unsigned char** PKLIST, unsigned char* L){
    int i,j,k=0;
    for (i = 0; i < N; i++) {
        for(j=0; j<PK_SIZE;j++){
            L[k] = PKLIST[i][j];
            k++;
        }
    }
}

void CALC_C(const secp256k1_context* ctx,  const unsigned char* X,  const unsigned char* STATE,  unsigned char* msg,  unsigned char* c){

    int i,k;
    unsigned char catXState[2*PK_BYTES];

    /******************** Compute c ********************/
    k=0;
    for (i = 0; i < PK_SIZE; i++,k++)
        catXState[k] = X[i];
    for (i = 0; i < PK_SIZE; i++,k++)
        catXState[k] = STATE[i];
    secp256k1_tagged_sha256(ctx, c, catXState, sizeof(catXState), msg, sizeof(msg));
}
