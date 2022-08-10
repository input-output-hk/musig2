#include "api_musig2.h"
#include "config.h"


/**** Signer ****/
void musig2_init_signer(musig2_context_sig *mc){

    /* Generate a key pair for given signer */
    musig2_key_gen(mc);

    /* Generate the batch commitments for given signer */
    musig2_batch_commitment(mc);
}

int musig2_agg_R(musig2_context_sig *mcs, secp256k1_pubkey *batch_list, int n){

    int i,j;
    int return_val = 0;
    int ind = mcs->mc->state*(V*n);
    secp256k1_pubkey* temp_R_LIST[n];

    /* Aggregate the batch commitments for current state and message */
    for (j=0; j<V; j++){
        i=0;
        while (i<n){
            temp_R_LIST[i] = malloc(sizeof (secp256k1_pubkey));
            memcpy( &temp_R_LIST[i++][0], batch_list[ind++].data, PK_BYTES);
        }
        return_val += !secp256k1_ec_pubkey_combine(mcs->mc->ctx, &mcs->agg_R_list[j], (const secp256k1_pubkey *const *) temp_R_LIST, n);
    }

    if (return_val != 0) return 0;
    else                 return 1;
}

int musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, const unsigned char *tag, int n)
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
    musig2_key_agg_coef(mcs->mc, sx_pk, param->a, mcs->mc->L, n);


    /* Get x_only version of aggregated public key and its parity */
    return_val += !secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &x_X_, &param->par_X, &mcs->mc->X_);
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param->sx_X, &x_X_);

    /* Generate partial signature */
    musig2_sign_partial(mcs, param);

    if (return_val != 0) return 0;
    else                 return 1;
}


/**** Aggregator ****/
void musig2_init_aggregator(musig2_context_agg *mca, secp256k1_pubkey *pk_list, secp256k1_pubkey R, int n){

    /* Aggregate the given list of public keys */
    musig2_aggregate_pubkey(mca->mc, pk_list, n);

    /* Set given R */
    memcpy(&mca->mc->R, R.data, PK_BYTES);

}

int musig2_aggregate_parsig(musig2_context_agg *mca, unsigned char **parsig_list, int n){

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
    for(i=1; i<n; i++)
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