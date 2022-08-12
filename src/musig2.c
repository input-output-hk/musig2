#include "api_musig2.h"

/**** Signer ****/
void musig2_init_signer(musig2_context_sig *mc){

    /* Generate a key pair for given signer */
    musig2_key_gen(mc);

    /* Generate the batch commitments for given signer */
    musig2_batch_commitment(mc, NR_MSGS);
}

int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list){

    int i;
    int return_val = 0;
    unsigned char temp_a[SCALAR_BYTES];
    unsigned char *xonly_pk_list[N];
    secp256k1_pubkey* temp_X_LIST[N];
    secp256k1_xonly_pubkey temp_X;

    /* Allocate memory for L */
    mc->L = malloc(XONLY_BYTES*N);

    /* Multiply X_i with a_i. Store in temp_X_LIST[i]. */
    for(i=0; i<N;i++) {
        xonly_pk_list[i] = malloc(XONLY_BYTES);
        temp_X_LIST[i] = malloc(sizeof(secp256k1_pubkey));

        /* Copy the current public key into temp_X_LIST */
        memcpy(&temp_X_LIST[i]->data[0], pk_list[i].data, PK_BYTES);
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
    int ind = mcs->mc->state*(V*N);
    secp256k1_pubkey* temp_R_LIST[N];

    /* Aggregate the batch commitments for current state and message */
    for (j=0; j<V; j++){
        i=0;
        while (i<N){
            temp_R_LIST[i] = malloc(sizeof (secp256k1_pubkey));
            memcpy( &temp_R_LIST[i++][0], batch_list[ind++].data, PK_BYTES);
        }
        return_val += !secp256k1_ec_pubkey_combine(mcs->mc->ctx, &mcs->agg_R_list[j], (const secp256k1_pubkey *const
        *) temp_R_LIST, N);
    }

    if (return_val != 0) return 0;
    else                 return 1;
}

int musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, const unsigned char *tag)
{
    int return_val;
    unsigned char sx_pk[XONLY_BYTES];   // Serialized x_only public key of signer
    secp256k1_xonly_pubkey x_pk;    // x_only public key of signer
    secp256k1_xonly_pubkey x_X_;    // x_only aggregated public key
    musig2_param *param = malloc(sizeof (musig2_param));  // Parameters used to generate partial signature

    /* Compute the hash of given message with given tag */
    return_val = secp256k1_tagged_sha256(mcs->mc->ctx, param->msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);

    /* Get the exponent `a` of current signer */
    return_val += !secp256k1_keypair_xonly_pub(mcs->mc->ctx, &x_pk, NULL, &mcs->keypair);
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, sx_pk, &x_pk);
    musig2_key_agg_coef(mcs->mc, sx_pk, param->a, mcs->mc->L, N);


    /* Get x_only version of aggregated public key and its parity */
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &x_X_, &param->par_X, &mcs->mc->X_);
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param->sx_X, &x_X_);

    /* Generate partial signature */
    musig2_sign_partial(mcs, param);

    if (return_val != 0) return 0;
    else                 return 1;
}


/**** Aggregator ****/
void musig2_init_aggregator(musig2_context_agg *mca, secp256k1_pubkey *pk_list, secp256k1_pubkey R){

    /* Aggregate the given list of public keys */
    musig2_aggregate_pubkey(mca->mc, pk_list);

    /* Set given R */
    memcpy(&mca->mc->R, R.data, PK_BYTES);

}

int musig2_aggregate_parsig(musig2_context_agg *mca, unsigned char **parsig_list){

    int i;
    int return_val = 0;
    int par_X = 0;  // Parity of X
    int par_R = 0;  // Parity of R
    unsigned char aggsig[SCALAR_BYTES]; // Aggregated signature
    unsigned char sx_R[SCALAR_BYTES];   // Serialized x_only R
    secp256k1_xonly_pubkey x_X; // x_only X
    secp256k1_xonly_pubkey x_R; // x_only R

    /* Get x_only X and its parity*/
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mca->mc->ctx, &x_X, &par_X, &mca->mc->X_);

    /* Get x_only R and its parity*/
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mca->mc->ctx, &x_R, &par_R, &mca->mc->R);

    /* Serialize x_only R to store in signature */
    secp256k1_xonly_pubkey_serialize(mca->mc->ctx, sx_R, &x_R);

    /* Aggregate the partial signatures */
    memcpy(&aggsig[0], parsig_list[0], SCALAR_BYTES);
    for(i=1; i<N; i++)
        return_val += !secp256k1_ec_seckey_tweak_add(mca->mc->ctx, aggsig, parsig_list[i]);

    /* Negate the aggregated signature if both par_X and par_R */
    if (par_X == 1 && par_R == 1)
        return_val += !secp256k1_ec_seckey_negate(mca->mc->ctx, aggsig);

    /* Set the signature of type schnorr signature */
    memcpy(&mca->signature[0], sx_R, SCALAR_BYTES);
    memcpy(&mca->signature[SCALAR_BYTES], aggsig, SCALAR_BYTES);

    if (return_val != 0) return 0;
    else                 return 1;
}


/**** Verifier ****/
void musig2_init_verifier(musig2_context_ver *mcv, unsigned char *signature, secp256k1_pubkey X){

    /* Initialize verifier */
    assert(secp256k1_xonly_pubkey_from_pubkey(mcv->ctx, &mcv->x_X, NULL, &X));
    memcpy(&mcv->signature, signature, SCH_SIG_BYTES);

}

int musig2_verify_musig(musig2_context_ver *mcv,const unsigned char *msg, const unsigned char *tag ){

    int return_val;
    unsigned char msg_hash[SCALAR_BYTES];

    /* Compute the hash of given message with given tag */
    return_val = secp256k1_tagged_sha256(mcv->ctx, msg_hash, tag, sizeof (tag), msg, sizeof (msg));
    assert(return_val);

    /* Verify musig2 with secp256k1_schnorrsig_verify */
    return secp256k1_schnorrsig_verify(mcv->ctx, mcv->signature, msg_hash, SCALAR_BYTES, &mcv->x_X);
}