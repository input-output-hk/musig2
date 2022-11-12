#include "libmusig2.h"

static int musig2_key_gen(musig2_context_sig *mcs) {
    unsigned char x[MUSIG2_SCALAR_BYTES];

    while (1) {
        if (!fill_random(x, sizeof(x))) {
            return 0;
        }
        /* Try to create a keypair with a valid context, it should only fail if
         * the secret key is zero or out of range. */
        if (secp256k1_keypair_create(mcs->mc.ctx, &mcs->keypair, x))
            return 1;
    }
}

static int musig2_batch_commitment(musig2_context_sig *mcs) {

    unsigned char x[MUSIG2_SCALAR_BYTES];
    mcs->comm_list = malloc(sizeof (secp256k1_keypair*) * mcs->mc.nr_messages * V);

    int i, j, k;
    i = 0;
    /* Create nr_msgs * V batch commitments for signer */
    for (k = 0; k < mcs->mc.nr_messages; k++) {
        for (j = 0; j < V; j++, i++) {
            mcs->comm_list[i] = malloc(sizeof(secp256k1_keypair));
            while (1) {
                if (!fill_random(x, MUSIG2_SCALAR_BYTES)) {
                    return 0;
                }
                if (secp256k1_keypair_create(mcs->mc.ctx, mcs->comm_list[i], x))
                    break;
            }
        }
    }
    return 1;
}

static void musig2_key_agg_coef(musig2_context *mc, unsigned char *ser_pk, unsigned char *a) {

    unsigned char tag[13] = "BIP0340/nonce";    // Tag of hash to generate the exponents
    unsigned char temp_concat[(mc->nr_signers + 1) * MUSIG2_PUBKEY_BYTES];    // Temp to store the concatenation of public keys

    memcpy(temp_concat, mc->L, mc->nr_signers * MUSIG2_PUBKEY_BYTES );      // Copy L into temp_concat
    memcpy(&temp_concat[mc->nr_signers * MUSIG2_PUBKEY_BYTES], ser_pk, MUSIG2_PUBKEY_BYTES );  /* Copy given pk besides L */
    assert(secp256k1_tagged_sha256(mc->ctx, a, tag, sizeof (tag), temp_concat, sizeof (temp_concat)));
}

static void musig2_calc_b(musig2_context *mc, const unsigned char *ser_aggr_pk, unsigned char *b, const unsigned char *msg, int msg_len, int state) {

    int j;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag for the hash to compute b
    unsigned char ser_R[MUSIG2_PUBKEY_BYTES];
    unsigned char temp_concat[(1 + V) * MUSIG2_PUBKEY_BYTES + msg_len]; // Temp value to store the concatenation of aggr_pk, aggr_R_list and the message.
    secp256k1_xonly_pubkey xonly_R;

    /* Copy ser_aggr_pk into temp_concat */
    memcpy(temp_concat, ser_aggr_pk, MUSIG2_PUBKEY_BYTES);

    /* Get x_only R_j, serialize and concatenate. */
    for (j = 0; j < V; j++) {
        assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &xonly_R, NULL, mc->aggr_R_list[state * V + j]));
        secp256k1_xonly_pubkey_serialize(mc->ctx, ser_R, &xonly_R);
        memcpy(&temp_concat[MUSIG2_PUBKEY_BYTES * (j + 1)], ser_R, MUSIG2_PUBKEY_BYTES);
    }

    /* Concatenate msg to end */
    memcpy(&temp_concat[(1 + V) * MUSIG2_PUBKEY_BYTES], msg, msg_len);

    /* Compute b */
    assert(secp256k1_tagged_sha256(mc->ctx, b, tag, sizeof (tag), temp_concat, sizeof(temp_concat)));

}

static int musig2_calc_R(musig2_context *mc, secp256k1_xonly_pubkey *aggr_R, int *par_R, unsigned char *b, unsigned char b_LIST[V][MUSIG2_SCALAR_BYTES], int state) {

    int j;
    secp256k1_pubkey tweakable_Rb_list[V];
    secp256k1_pubkey *Rb_list[V];
    secp256k1_pubkey temp_aggr_R;
    secp256k1_xonly_pubkey xonly_temp;   // temp value to store xonly point

    for (j = 0; j < V; j++)
        memcpy(tweakable_Rb_list[j].data, mc->aggr_R_list[state * V + j]->data, MUSIG2_PUBKEY_BYTES_FULL);
    /* Compute b_LIST = { b^(j-1) } and Rb_LIST = { R_j * b^(j-1) } */
    b_LIST[0][31] = 1; // first element of b_LIST = 1;
    Rb_list[0] = &tweakable_Rb_list[0];

    for (j = 1; j < V; j++) {
        Rb_list[j] = &tweakable_Rb_list[j];
        memcpy(b_LIST[j], b_LIST[j-1], MUSIG2_SCALAR_BYTES);
        if (!secp256k1_ec_seckey_tweak_mul(mc->ctx, b_LIST[j], b))
            return 0;

        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, Rb_list[j], b_LIST[j]))
            return 0;
    }

    /* R = SUM ({ R_j * b^(j-1) }) */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &temp_aggr_R, (const secp256k1_pubkey *const *)Rb_list, V))
        return 0;

    /* Get x_only version of aggregated public key and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &xonly_temp, &mc->par_pk, &mc->aggr_pk));

    /* Get x_only version of aggregated R and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, aggr_R, par_R, &temp_aggr_R));

    if (*par_R == 1 && mc->par_pk == 0){
        // we negate b_LIST
        for (j = 0; j < V; j++) {
            if (!secp256k1_ec_seckey_negate(mc->ctx, b_LIST[j])) {
                return 0;
            }
        }
        // we negate R
        *par_R = 0;
    }

    return 1;
}

static int musig2_set_parsig(musig2_context_sig *mcs, unsigned char *a, unsigned char *c, unsigned char b_LIST[V][MUSIG2_SCALAR_BYTES], int par_R, unsigned char *parsig) {
    int j;
    unsigned char temp_rb[MUSIG2_SCALAR_BYTES];
    unsigned char x[MUSIG2_SCALAR_BYTES];
    unsigned char sr_list[V][MUSIG2_SCALAR_BYTES];

    /* Extract the secret key of the signer */
    assert(secp256k1_keypair_sec(mcs->mc.ctx, x, &mcs->keypair));

    /* Extract the nonces of the signer for current state */
    for (j = 0; j < V; j++){
        assert(secp256k1_keypair_sec(mcs->mc.ctx, sr_list[j], mcs->comm_list[V * mcs->state + j]));
        free(mcs->comm_list[V * mcs->state + j]);
        mcs->comm_list[V * mcs->state + j] = NULL;
    }

    /* Update the state everytime we free the memory of a nonce */
    mcs->state++;

    // Condition where R is even and PK is odd. We negate the challenge
    if (par_R == 0 && mcs->mc.par_pk == 1){
        if (!secp256k1_ec_seckey_negate(mcs->mc.ctx, c)){
            return 0;
        }
    }

    /* Compute (a * x * c) */
    memcpy(parsig, c, MUSIG2_SCALAR_BYTES);
    if (!secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, parsig, x) || !secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, parsig, a))
        return 0;

    /* Finalise the computation of a * x * c + \sum_{i=0}^V r_i * b_i */
    for (j = 0; j < V; j++) {
        memcpy(temp_rb, sr_list[j], MUSIG2_SCALAR_BYTES);
        if (!secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, temp_rb, b_LIST[j]) || !secp256k1_ec_seckey_tweak_add(mcs->mc.ctx, parsig, temp_rb))
            return 0;
    }

    // The third condition, if both R and pk are odd, we negate the partial signature.
    if (par_R == 1 && mcs->mc.par_pk == 1){
        if (!secp256k1_ec_seckey_negate(mcs->mc.ctx, parsig)){
            return 0;
        }
    }

    return 1;
}

/*** Free memory allocated in MuSig2 context ***/
void musig2_context_free(musig2_context *mc) {
    if (mc->ctx != NULL) {
        secp256k1_context_destroy(mc->ctx);
    }
    if (mc->L != NULL) {
        free(mc->L);
    }
    if (mc->aggr_R_list != NULL) {
        for (int l = 0; l < V * mc->nr_messages; l++) {
            if (mc->aggr_R_list != NULL){
                free(mc->aggr_R_list[l]);
            }
        }
        free(mc->aggr_R_list);
    }
}

/*** Free memory allocated in MuSig2 Sig context ***/
void musig2_context_sig_free(musig2_context_sig *mcs) {
    for (int l = mcs->state * V; l < mcs->mc.nr_messages * V; l++) {
        free(mcs->comm_list[l]);
    }
    free(mcs->comm_list);
    musig2_context_free(&mcs->mc);
}

int musig2_prepare_signer_to_register(musig2_context_sig *mcs, unsigned char *serialized_pubkey, unsigned char serialized_batch_list[][MUSIG2_PUBKEY_BYTES_COMPRESSED]){
    secp256k1_pubkey temp_pk;
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i;

    if (secp256k1_keypair_pub(mcs->mc.ctx, &temp_pk, &mcs->keypair))
        secp256k1_ec_pubkey_serialize(mcs->mc.ctx, serialized_pubkey, &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED );
    else {
        musig2_context_sig_free(mcs);
        return 0;
    }

    for (i = 0; i < mcs->mc.nr_messages * V; i++) {
        if (secp256k1_keypair_pub(mcs->mc.ctx, &temp_pk, mcs->comm_list[i]))
            secp256k1_ec_pubkey_serialize(mcs->mc.ctx, serialized_batch_list[i], &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED );
        else {
            musig2_context_sig_free(mcs);
            return 0;
        }
    }

    return 1;
}

/**** Signer ****/
int musig2_init_signer(musig2_context_sig *mcs, int nr_messages) {

    /* Initialize the secp256k1_context to operate on secp256k1 curve.
     * MuSig2 library generates a multi-signature in the form of the schnorr signature obtained by secp256k1_schnorrsig_sign32
     * with the library functions of libsecp256k1, however we do not use secp256k1_schnorrsig_sign32 function.
     * Thus, we create the context with only SECP256K1_CONTEXT_VERIFY flag instead of using
     * SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY. */
//    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    mcs->mc.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    mcs->state = 0;
    mcs->mc.nr_messages = nr_messages;

    /* Generate a key pair for given signer */
    if (!musig2_key_gen(mcs)) {
        musig2_context_sig_free(mcs);
        return 0;
    }

    /* Generate the batch commitments for given signer */
    if (!musig2_batch_commitment(mcs)) {
        musig2_context_sig_free(mcs);
        return 0;
    }

    return 1;
}

int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list) {

    int i;
    unsigned char temp_a[MUSIG2_SCALAR_BYTES];
    unsigned char ser_pk_list[mc->nr_signers][MUSIG2_PUBKEY_BYTES];
    secp256k1_pubkey tweakable_pk_list[mc->nr_signers];
    const secp256k1_pubkey* pk_pointer_list[mc->nr_signers];
    secp256k1_xonly_pubkey temp_xonly_pk;

    /* Allocate memory for L */
    mc->L = malloc(MUSIG2_PUBKEY_BYTES * mc->nr_signers);

    /* Multiply pk_i with a_i. Store in temp_pk_list[i]. */
    for (i = 0; i < mc->nr_signers; i++) {
        /* Copy the current public key into temp_pk_list */
        memcpy(tweakable_pk_list[i].data, pk_list[i].data, MUSIG2_PUBKEY_BYTES_FULL);
        pk_pointer_list[i] = &tweakable_pk_list[i];
        assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_xonly_pk, NULL, pk_pointer_list[i]));
        secp256k1_xonly_pubkey_serialize(mc->ctx, ser_pk_list[i], &temp_xonly_pk);

        /* Update L */
        memcpy(&mc->L[i * MUSIG2_PUBKEY_BYTES], ser_pk_list[i], MUSIG2_PUBKEY_BYTES);
    }

    for (i = 0; i < mc->nr_signers; i++) {
        /* Get the exponent `a` of current public key */
        musig2_key_agg_coef(mc, ser_pk_list[i], temp_a);

        /* Compute `pk_i * a_i` */
        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, (secp256k1_pubkey*)pk_pointer_list[i], temp_a))
            return 0;
    }

    /* Aggregate the public keys */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &mc->aggr_pk, pk_pointer_list, mc->nr_signers))
        return 0;

    return 1;
}

int musig2_aggregate_R(musig2_context *mc, secp256k1_pubkey batch_list[][V], int state) {

    int i, j;
    secp256k1_pubkey* temp_R_list[mc->nr_signers];

    /* Aggregate the batch commitments for current message */
    for (j = 0; j < V; j++) {
        mc->aggr_R_list[state * V + j] = malloc(sizeof (secp256k1_pubkey));
        for (i = 0; i < mc->nr_signers; i++)
            temp_R_list[i] = &batch_list[i][j];

        if (!secp256k1_ec_pubkey_combine(mc->ctx, mc->aggr_R_list[state * V + j], (const secp256k1_pubkey *const *) temp_R_list, mc->nr_signers))
            return 0;
    }
    return 1;
}

int musig2_signer_precomputation(musig2_context *mc, unsigned char *serialized_pk_list, unsigned char *serialized_batch_list, int nr_signers, int nr_messages){
    int i, j, k, ind;
    mc->nr_signers = nr_signers;
    mc->aggr_R_list = malloc(sizeof (secp256k1_pubkey*) * nr_messages * V);
    secp256k1_pubkey batch_list[nr_messages][nr_signers][V];   // Stores the batches of signers
    secp256k1_pubkey pk_list[nr_signers];

    // Parse the batch commitments of the signers
    for (i = 0; i < nr_signers; i++) {
        assert(secp256k1_ec_pubkey_parse(mc->ctx, &pk_list[i], &serialized_pk_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], MUSIG2_PUBKEY_BYTES_COMPRESSED));
        for (k = 0; k < nr_messages; k++) {
            for (j = 0; j < V; j++) {
                ind = (k * nr_signers * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
                assert(secp256k1_ec_pubkey_parse(mc->ctx, &batch_list[k][i][j], &serialized_batch_list[ind], MUSIG2_PUBKEY_BYTES_COMPRESSED));
            }
        }
    }

    // Aggregate R for each message to be signed.
    for (k = 0; k < nr_messages; k++)
        if (!musig2_aggregate_R(mc, batch_list[k], k))
            return 0;

    if (!musig2_aggregate_pubkey(mc, pk_list))
        return 0;

    return 1;
}

int musig2_sign(musig2_context_sig *mcs, musig2_partial_signature *mps, const unsigned char *msg, int msg_len) {

    unsigned char ser_aggr_pk[MUSIG2_PUBKEY_BYTES];
    unsigned char ser_aggr_R[MUSIG2_PUBKEY_BYTES];
    unsigned char bytes_to_hash[MUSIG2_PUBKEY_BYTES * 2 + msg_len];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )
    unsigned char a[MUSIG2_SCALAR_BYTES], b[MUSIG2_SCALAR_BYTES], c[MUSIG2_SCALAR_BYTES];
    unsigned char b_LIST[V][MUSIG2_SCALAR_BYTES] = {0};

    unsigned char ser_pk[MUSIG2_PUBKEY_BYTES];  // Serialized public key of signer
    secp256k1_xonly_pubkey xonly_temp;
    int par_R;

    int j;
    int index = V * mcs->state;
    for (j = 0; j < V; j++)
        if (mcs->comm_list[index + j] == NULL){
        return -1;
    }

    assert(secp256k1_keypair_xonly_pub(mcs->mc.ctx, &xonly_temp, NULL, &mcs->keypair));
    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, ser_pk, &xonly_temp);

    /* Get the exponent `a` of signer */
    musig2_key_agg_coef(&mcs->mc, ser_pk, a);

    assert(secp256k1_xonly_pubkey_from_pubkey(mcs->mc.ctx, &xonly_temp, NULL, &mcs->mc.aggr_pk));
    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, ser_aggr_pk, &xonly_temp);

    musig2_calc_b(&mcs->mc, ser_aggr_pk, b, msg, msg_len, mcs->state);
    /* Compute `R` */
    if (!musig2_calc_R(&mcs->mc, (secp256k1_xonly_pubkey *) &mps->R, &par_R, b, b_LIST, mcs->state))
        return 0;


    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, ser_aggr_R, &mps->R);

    memcpy(bytes_to_hash, &ser_aggr_R, MUSIG2_PUBKEY_BYTES);
    memcpy(&bytes_to_hash[MUSIG2_PUBKEY_BYTES], &ser_aggr_pk, MUSIG2_PUBKEY_BYTES);
    memcpy(&bytes_to_hash[MUSIG2_PUBKEY_BYTES * 2], msg, msg_len);

    assert(secp256k1_tagged_sha256(mcs->mc.ctx, c, (const unsigned char *)"BIP0340/challenge" , 17, bytes_to_hash, sizeof (bytes_to_hash)));

    if (!musig2_set_parsig(mcs, a, c, b_LIST, par_R, mps->sig))
        return 0;


    return 1;
}

/**** Aggregator ****/
int musig2_aggregate_partial_sig(musig2_partial_signature *mps, unsigned char *signature, int nr_signatures) {
    int i;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    /* Check whether all aggregated R are equal */
    for (i = 1; i < nr_signatures; i++) {
        if (secp256k1_xonly_pubkey_cmp(ctx, &mps[i].R, &mps[i - 1].R) != 0){
            secp256k1_context_destroy(ctx);
            return -1 ;
        }
    }

    /* Serialize R to store in signature */
    secp256k1_xonly_pubkey_serialize(ctx, signature, &mps[0].R);

    /* Aggregate the partial signatures */
    memcpy(signature + MUSIG2_PUBKEY_BYTES, mps[0].sig, MUSIG2_SCALAR_BYTES);
    for (i = 1; i < nr_signatures; i++) {
        if (!secp256k1_ec_seckey_tweak_add(ctx, signature + MUSIG2_PUBKEY_BYTES, mps[i].sig)) {
            secp256k1_context_destroy(ctx);
            return 0;
        }

    }
    secp256k1_context_destroy(ctx);

    return 1;
}

void musig2_prepare_verifier(musig2_pubkey *aggr_pk, unsigned char *serialized_pk_list, int nr_signers) {
    musig2_context verifier_context;
    verifier_context.aggr_R_list = NULL;
    verifier_context.nr_signers = nr_signers;
    secp256k1_pubkey pk_list[nr_signers];
    verifier_context.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    int i;
    for (i = 0; i < nr_signers; i++)
        assert(secp256k1_ec_pubkey_parse(verifier_context.ctx, &pk_list[i], &serialized_pk_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], MUSIG2_PUBKEY_BYTES_COMPRESSED));

    musig2_aggregate_pubkey(&verifier_context, pk_list);

    /* Get the xonly public key */
    assert(secp256k1_xonly_pubkey_from_pubkey(verifier_context.ctx, aggr_pk, NULL, &verifier_context.aggr_pk));

    musig2_context_free(&verifier_context);
}
