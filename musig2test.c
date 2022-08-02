#include "src/api_musig2.h"

int main(void) {
    unsigned char randomize[SCALAR_BYTES];

    int i, return_val;

    /* Initialize the secp256k1_context to operate on secp256k1 curve.
     * MuSig2 library generates a multi-signature in the form of the schnorr signature obtained by secp256k1_schnorrsig_sign32
     * with the library functions of libsecp256k1, however we do not use secp256k1_schnorrsig_sign32 function.
     * Thus, we create the context with only SECP256K1_CONTEXT_VERIFY flag instead of using
     * SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY. */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    secp256k1_pubkey pk_list[N];

    /****** Init Signer 1 ******/
    musig2_context_sig *mcs1 = malloc(sizeof (musig2_context_sig));
    mcs1->mc = malloc(sizeof (musig2_context));
    mcs1->mc->ctx = secp256k1_context_clone(ctx);
    musig2_init(mcs1);
    secp256k1_keypair_pub(ctx, &pk_list[0], &mcs1->keypair);

    /****** Init Signer 2 ******/
    musig2_context_sig *mcs2 = malloc(sizeof (musig2_context_sig));
    mcs2->mc = malloc(sizeof (musig2_context));
    mcs2->mc->ctx = secp256k1_context_clone(ctx);
    musig2_init(mcs2);
    secp256k1_keypair_pub(ctx, &pk_list[1], &mcs2->keypair);

    /****** Init Signer 3 ******/
    musig2_context_sig *mcs3 = malloc(sizeof (musig2_context_sig));
    mcs3->mc = malloc(sizeof (musig2_context));
    mcs3->mc->ctx = secp256k1_context_clone(ctx);
    musig2_init(mcs3);
    secp256k1_keypair_pub(ctx, &pk_list[2], &mcs3->keypair);



    /**************************************************************************************/
    /**************************************************************************************/
    /* Collect batch commitments **********************************************************/
    secp256k1_pubkey batch_list[N*V*NR_MSGS];
    int j,k,l;
    int ind;

    i = 0, l=0;
    for(k=0; k<NR_MSGS; k++){
        for(j=0; j<V; j++,l++) {
            ind = N*V*k + j*N + i;
            secp256k1_keypair_pub(ctx, &batch_list[ind], mcs1->commlist[l]);
        }
    }
    i = 1, l=0;
    for(k=0; k<NR_MSGS; k++){
        for(j=0; j<V; j++,l++) {
            ind = N*V*k + j*N + i;
            secp256k1_keypair_pub(ctx, &batch_list[ind], mcs2->commlist[l]);
        }
    }
    i = 2, l=0;
    for(k=0; k<NR_MSGS; k++){
        for(j=0; j<V; j++,l++) {
            ind = N*V*k + j*N + i;
            secp256k1_keypair_pub(ctx, &batch_list[ind], mcs3->commlist[l]);
        }
    }

    mcs1->mc->state = 0;
    musig2_aggregate_pubkey(mcs1->mc, pk_list, N);
    musig2_agg_R(mcs1->mc, batch_list, N);

    mcs2->mc->state = 0;
    musig2_aggregate_pubkey(mcs2->mc, pk_list, N);
    musig2_agg_R(mcs2->mc, batch_list, N);

    mcs3->mc->state = 0;
    musig2_aggregate_pubkey(mcs3->mc, pk_list, N);
    musig2_agg_R(mcs3->mc, batch_list, N);




    musig2_sign(mcs1,MSG_1, TAG_1,N);
    musig2_sign(mcs2,MSG_1, TAG_1,N);
    musig2_sign(mcs3,MSG_1, TAG_1,N);

    unsigned char *parsig_list[N];
    parsig_list[0] = malloc(SCALAR_BYTES);
    parsig_list[1] = malloc(SCALAR_BYTES);
    parsig_list[2] = malloc(SCALAR_BYTES);

    memcpy(&parsig_list[0][0], mcs1->parsig, SCALAR_BYTES);
    memcpy(&parsig_list[1][0], mcs2->parsig, SCALAR_BYTES);
    memcpy(&parsig_list[2][0], mcs3->parsig, SCALAR_BYTES);

    musig2_context_agg *mca = malloc(sizeof (musig2_context_agg));
    mca->mc = malloc(sizeof (musig2_context));
    mca->mc->ctx = secp256k1_context_clone(ctx);
    musig2_init_aggregator(mca, pk_list, batch_list, N);
    musig2_aggregate_parsig(mca, parsig_list, MSG_1, TAG_1, N);

    musig2_verify_musig(mca, MSG_1, TAG_1);


//    musig2_set_final_sig(mc1, parsig_list, N);

//    print_hex(mcs1->mc->x_agg_X.data,64);
//    print_hex(mcs2->mc->x_agg_X.data,64);
//    print_hex(mcs3->mc->x_agg_X.data,64);




    return 0;
}
