#include "libmusig2.h"


int main(void) {
	unsigned char msg[12] = "Hello World!";
	unsigned char randomize[SK_BYTES];
	int return_val;
	int i, j;

	secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	if (!fill_random(randomize, sizeof(randomize))) {
		printf("Failed to generate randomness\n");
		return 1;
	}
	return_val = secp256k1_context_randomize(ctx, randomize);
	assert(return_val);

    printf("******************************************************************************\n");
    printf("********************************* MUSIG2 *************************************\n");
    printf("******************************************************************************\n");



    printf("\n**** INIT_SIGNER *************************************************************\n");
    SIGNER* signers = (SIGNER*) malloc(sizeof (SIGNER)*N);
    for(i=0;i<N;i++){
        signers[i] = (SIGNER) malloc(sizeof (SIGNER));
        INIT_Signer(ctx,signers[i]);
    }
    printf("  %d Signers initialized successfully.\n", N);
    printf("******************************************************************************\n");


    printf("\n**** SIGN_FirstRound *********************************************************\n");
    for(i=0;i<N;i++)
        SIGN_FirstRound(ctx,signers[i]);
    printf("  %d Signers generated round-1 signatures.\n", N);
    printf("******************************************************************************\n");


    printf("\n**** AGG_SIG_FirstRound ******************************************************\n");
    AGG_ROUND1 round1 = (AGG_ROUND1) malloc(sizeof (AGG_ROUND1));
    round1->PK_LIST = (unsigned char**) malloc(PK_SIZE*N);
    round1->OUT_R_LIST = (unsigned char**) malloc(PK_SIZE*V);
    round1->R_LIST = (struct NONCE**) malloc(sizeof (struct NONCE*)*V);
    for(j=0;j<V;j++){
        round1->R_LIST[j] = (struct NONCE*) malloc(sizeof (struct NONCE)*N);
        round1->R_LIST[j]->R = (unsigned char**) malloc(PK_SIZE*N);
    }
    round1->OUT = (unsigned char*) malloc(PK_SIZE*V);
    for(i=0;i<N;i++){
        COLLECT_Signers(round1,signers[i]->PK, signers[i]->R,i);
    }
    AGG_SIG_FirstRound(ctx, round1);
    printf("  First round signatures aggregated successfully.\n");
    for(j=0;j<V;j++){
        printf("R%d: ",j);
        print_hex(round1->OUT_R_LIST[j], PK_SIZE);
    }
    printf("******************************************************************************\n");


    printf("\n**** AGG_Key *****************************************************************\n");
    PARAM_ROUND2 paramRound2 = (PARAM_ROUND2) malloc(sizeof (PARAM_ROUND2));
    paramRound2->X_ = (unsigned char*) malloc(PK_SIZE);
    paramRound2->L = (unsigned char*) malloc(PK_SIZE*N);
    paramRound2->b = (unsigned char*) malloc(SK_SIZE);
    paramRound2->R_state = (unsigned char*) malloc(PK_SIZE);

    GEN_L((const unsigned char **) round1->PK_LIST, paramRound2->L);
    AGG_Key(ctx,round1,paramRound2);
    printf("  Key aggregation is done.\n");
    printf("X_: ");
    print_hex(paramRound2->X_, PK_SIZE);
    printf("******************************************************************************\n");


    printf("\n**** SET_Param ***************************************************************\n");
    SET_Param(ctx,paramRound2,round1,msg);
    printf("  Second round parameters are set.\n");
    printf("******************************************************************************\n");


    printf("\n**** SIG_SecondRound *********************************************************\n");
    unsigned char** SIG_LIST = (unsigned char **) malloc(SK_SIZE*N);
    for(i=0;i<N;i++){
        SIG_LIST[i] = (unsigned char *) malloc(SK_SIZE);
        SIG_SecondRound(ctx,paramRound2,signers[i], SIG_LIST[i], msg);
    }
    printf("  Second round signatures generated successfully.\n");
    for(i=0;i<N;i++){
        printf("s%d: ",i+1);
        print_hex(SIG_LIST[i], SK_SIZE);
    }
    printf("******************************************************************************\n");


    printf("\n**** AGG_SIG_SecondRound *****************************************************\n");
    unsigned char* MUSIG2 = (unsigned char *) malloc(SK_SIZE);
    AGG_SIG_SecondRound(ctx,SIG_LIST,MUSIG2);
    printf("  Second round signatures aggregated successfully.\n");
    printf("MuSig2: ");
    print_hex(MUSIG2, SK_SIZE);
    printf("******************************************************************************\n");


    printf("\n**** VER_Musig2 **************************************************************\n");
    VER_MUSIG2 verMusig2 = (VER_MUSIG2) malloc(sizeof (VER_MUSIG2));
    verMusig2->out = (unsigned char*) malloc(SK_SIZE);
    verMusig2->STATE = (unsigned char*) malloc(PK_SIZE);
    verMusig2->X = (unsigned char*) malloc(PK_SIZE);

    for (i = 0; i < SK_SIZE; i++)
        verMusig2->out[i] = MUSIG2[i];

    for (i = 0; i < PK_SIZE; i++){
        verMusig2->STATE[i] = paramRound2->R_state[i];
        verMusig2->X[i] = paramRound2->X_[i];
    }

    if(VER_Musig2(ctx, verMusig2, msg)){
        printf("    MuSig2 is VALID!\n");
    }
    else
        printf("    Failed to verify MuSig2!\n");
    printf("******************************************************************************\n");



    return 0;
}
