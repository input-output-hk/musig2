#include "src/api_musig2.h"

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

    printf("--------------------------------------------------------------------------- \n");
    printf("----------------------------- MuSig2 started ------------------------------ \n");
    printf("--------------------------------------------------------------------------- \n");
    printf("* Number of signers\t\t: %d\n", N);
    printf("* Number of nonces\t\t: %d \n", V);
    printf("* Number of messages\t: %d \n", NR_MSGS);
    printf("--------------------------------------------------------------------------- \n");

    /* musig2test parameters. */
    int i,j,k,l;
    int ind;
    secp256k1_pubkey pk_list[N];    // Signers' public key list
    secp256k1_pubkey batch_list[N*V*NR_MSGS];   // Stores the batches of signers
    unsigned char *parsig_list[N];  // The list of partial signatures


    musig2_context_sig *mcs_list[N]; // Array that holds N musig2_context_sig

    /**** Initialization ****/
    printf("\n-------- Initialize Signers ----------------------------------------------- \n");
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
    printf("* %d Signers initialized.\n", N);
    printf("--------------------------------------------------------------------------- \n");


    printf("\n*************************************************************************** \n");
    printf("* STATE 1  \n");
    printf("*************************************************************************** \n");

    /**** Aggregate the public keys and batch commitments for each signer ****/
    printf("\n-------- Aggregate PK and R ----------------------------------------------- \n");
    for (i=0; i<N; i++) {
        mcs_list[i]->mc->state = 0;
        musig2_aggregate_pubkey(mcs_list[i]->mc, pk_list);
        musig2_agg_R(mcs_list[i], batch_list);
    }
    printf("* Public key aggregated.\n");
    printf("* Commitments aggregated.\n");
    printf("--------------------------------------------------------------------------- \n");


    /**** Signature ****/
    printf("\n-------- Partial Signatures ----------------------------------------------- \n");
    for (i=0; i<N; i++) {
        /* Generate the partial signatures */
        musig2_sign(mcs_list[i], MSG_1, TAG_1);
        mcs_list[i]->mc->state++;

        printf(" S%d: ", i+1);
        print_hex(mcs_list[i]->parsig, SCALAR_BYTES);

        /* Collect the partial signatures in parsig_list */
        parsig_list[i] = malloc(SCALAR_BYTES);
        memcpy(&parsig_list[i][0], mcs_list[i]->parsig, SCALAR_BYTES);

        /* Check whether all aggregated R is same */
        for (j=0; j<i; j++){
            if (secp256k1_ec_pubkey_cmp(ctx, &mcs_list[i]->mc->R, &mcs_list[j]->mc->R )  != 0){
                return -1;
            }
        }
    }
    printf("--------------------------------------------------------------------------- \n");


    /**** Aggregation ****/
    printf("\n-------- Initialize Aggregator -------------------------------------------- \n");
    musig2_context_agg *mca1 = malloc(sizeof (musig2_context_agg));
    mca1->mc = malloc(sizeof (musig2_context));
    mca1->mc->ctx = secp256k1_context_clone(ctx);

    /* Initialize the aggregator */
    musig2_init_aggregator(mca1, pk_list,mcs_list[N-1]->mc->R);
    printf("* Aggregator initialized.\n");
    /* Aggregate the partial signatures */
    musig2_aggregate_parsig(mca1, parsig_list);
    printf("* Partial signatures aggregated.\n");
    printf("--------------------------------------------------------------------------- \n");


    /**** Verification ****/
    printf("\n-------- Initialize Verifier ---------------------------------------------- \n");
    musig2_context_ver *mcv1 = malloc(sizeof (musig2_context_ver));
    mcv1->ctx = secp256k1_context_clone(ctx);

    /* Initialize the verifier */
    musig2_init_verifier(mcv1, mca1->signature, mca1->mc->X_);
    printf("* Verifier initialized.\n");
    printf("--------------------------------------------------------------------------- \n");

    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    printf("\n-------- Verify MuSig2 ---------------------------------------------------- \n");
    if (musig2_verify_musig(mcv1, MSG_1, TAG_1))
        printf("* Musig2 is VALID!\n");
    else
        printf("* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n");

    secp256k1_context_destroy(mca1->mc->ctx);
    secp256k1_context_destroy(mcv1->ctx);
    mca1 = NULL;
    mcv1 = NULL;



    printf("\n*************************************************************************** \n");
    printf("* STATE 2  \n");
    printf("*************************************************************************** \n");


    /**** Aggregate the public keys and batch commitments for each signer ****/
    printf("\n-------- Aggregate PK and R ----------------------------------------------- \n");
    for (i=0; i<N; i++) {
        musig2_aggregate_pubkey(mcs_list[i]->mc, pk_list);
        musig2_agg_R(mcs_list[i], batch_list);
    }
    printf("* Public key aggregated.\n");
    printf("* Commitments aggregated.\n");
    printf("--------------------------------------------------------------------------- \n");


    /**** Signature ****/
    printf("\n-------- Partial Signatures ----------------------------------------------- \n");
    for (i=0; i<N; i++) {
        /* Generate the partial signatures */
        musig2_sign(mcs_list[i], MSG_2, TAG_2);
        mcs_list[i]->mc->state++;
        printf(" S%d: ", i+1);
        print_hex(mcs_list[i]->parsig, SCALAR_BYTES);

        /* Collect the partial signatures in parsig_list */
        parsig_list[i] = malloc(SCALAR_BYTES);
        memcpy(&parsig_list[i][0], mcs_list[i]->parsig, SCALAR_BYTES);

        /* Check whether all aggregated R is same */
        for (j=0; j<i; j++){
            if (secp256k1_ec_pubkey_cmp(ctx, &mcs_list[i]->mc->R, &mcs_list[j]->mc->R )  != 0){
                return -1;
            }
        }
    }
    printf("--------------------------------------------------------------------------- \n");


    /**** Aggregation ****/
    printf("\n-------- Initialize Aggregator -------------------------------------------- \n");
    musig2_context_agg *mca2 = malloc(sizeof (musig2_context_agg));
    mca2->mc = malloc(sizeof (musig2_context));
    mca2->mc->ctx = secp256k1_context_clone(ctx);

    /* Initialize the aggregator */
    musig2_init_aggregator(mca2, pk_list,mcs_list[N-1]->mc->R);
    printf("* Aggregator initialized.\n");
    /* Aggregate the partial signatures */
    musig2_aggregate_parsig(mca2, parsig_list);
    printf("* Partial signatures aggregated.\n");
    printf("--------------------------------------------------------------------------- \n");


    /**** Verification ****/
    printf("\n-------- Initialize Verifier ---------------------------------------------- \n");
    musig2_context_ver *mcv2 = malloc(sizeof (musig2_context_ver));
    mcv2->ctx = secp256k1_context_clone(ctx);

    /* Initialize the verifier */
    musig2_init_verifier(mcv2, mca2->signature, mca2->mc->X_);
    printf("* Verifier initialized.\n");
    printf("--------------------------------------------------------------------------- \n");

    /* Verify the aggregated signature with secp256k1_schnorrsig_verify */
    printf("\n-------- Verify MuSig2 ---------------------------------------------------- \n");
    if (musig2_verify_musig(mcv2, MSG_2, TAG_2))
        printf("* Musig2 is VALID!\n");
    else
        printf("* Failed to verify Musig2!\n");
    printf("--------------------------------------------------------------------------- \n");


    secp256k1_context_destroy(mca2->mc->ctx);
    secp256k1_context_destroy(mcv2->ctx);
    mca2 = NULL;
    mcv2 = NULL;

    for (i = 0; i < N; i++)
        mcs_list[i] = NULL;

    secp256k1_context_destroy(ctx);

    return 0;
}
