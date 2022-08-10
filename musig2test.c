#include "src/api_musig2.h"
#include "src/config.h"
int main(void) {

    unsigned char randomize[SCALAR_BYTES];
    int return_val;

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

    /* musig2test parameters. */
    int i,j,k,l;
    int ind;
    secp256k1_pubkey pk_list[N];    // Signers' public key list
    secp256k1_pubkey batch_list[N*V*NR_MSGS];   // Stores the batches of signers
    unsigned char *parsig_list[N];  // The list of partial signatures


    musig2_context_sig *mcs_list[N]; // Array that holds N musig2_context_sig

    /**** Initialization ****/
    for (i=0; i<N; i++){
        mcs_list[i] = malloc(sizeof (musig2_context_sig));
        mcs_list[i]->mc = malloc(sizeof (musig2_context));
        mcs_list[i]->mc->ctx = secp256k1_context_clone(ctx);

        /* Generate a keypair for the signer and get batch commitments. */
        musig2_init_signer(mcs_list[i]);

        /* Store the public key of the signer in pk_list */
        assert (secp256k1_keypair_pub(ctx, &pk_list[i], &mcs_list[i]->keypair));
        l=0;

        /* Store the batch commitments of the signer in batch_list */
        for(k=0; k<NR_MSGS; k++){
            for(j=0; j<V; j++,l++) {
                ind = N*V*k + j*N + i;
                assert(secp256k1_keypair_pub(ctx, &batch_list[ind], mcs_list[i]->commlist[l]));
            }
        }
    }

    /**** Aggregate the public key and batch commitments for each signer ****/
    for (i=0; i<N; i++) {
        mcs_list[i]->mc->state = 0;
        musig2_aggregate_pubkey(mcs_list[i]->mc, pk_list, N);
        musig2_agg_R(mcs_list[i], batch_list, N);
    }

    /**** Signature ****/
    for (i=0; i<N; i++) {
        /* Generate the partial signatures */
        musig2_sign(mcs_list[i], MSG_1, TAG_1,N);
        parsig_list[i] = malloc(SCALAR_BYTES);

        /* Collect the partial signatures in parsig_list */
        memcpy(&parsig_list[i][0], mcs_list[i]->parsig, SCALAR_BYTES);

        /* Check whether all aggregated R is same */
        for (j=0; j<i; j++){
            if (secp256k1_ec_pubkey_cmp(ctx, &mcs_list[i]->mc->R, &mcs_list[j]->mc->R )  != 0){
                return -1;
            }
        }
    }


    /**** Aggregation ****/
    musig2_context_agg *mca = malloc(sizeof (musig2_context_agg));
    mca->mc = malloc(sizeof (musig2_context));
    mca->mc->ctx = secp256k1_context_clone(ctx);

    /* Initialize the aggregator */
    musig2_init_aggregator(mca, pk_list,mcs_list[N-1]->mc->R, N);
    /* Aggregate the partial signatures */
    musig2_aggregate_parsig(mca, parsig_list, N);


    /**** Verification ****/
    musig2_context_ver *mcv = malloc(sizeof (musig2_context_ver));
    mcv->ctx = secp256k1_context_clone(ctx);

    /* Initialize the verifier */
    musig2_init_verifier(mcv, mca->signature, mca->mc->X_);

    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    if (musig2_verify_musig(mcv, MSG_1, TAG_1))
        printf("Musig2 is VALID!\n");
    else
        printf("Failed to verify Musig2!\n");


    return 0;
}