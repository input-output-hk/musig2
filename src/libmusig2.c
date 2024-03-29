#include "libmusig2.h"


static MUSIG2_ERROR musig2_key_gen(musig2_context_signer *mcs) {
    unsigned char x[MUSIG2_SCALAR_BYTES];

    while (1) {
        if (!fill_random(x, sizeof(x))) {
            return MUSIG2_ERR_KEY_GEN;
        }
        if (secp256k1_keypair_create(mcs->mc.ctx, &mcs->keypair, x)) {
            return MUSIG2_OK;
        }
    }
}

static MUSIG2_ERROR musig2_batch_commitment(musig2_context_signer *mcs) {

    unsigned char x[MUSIG2_SCALAR_BYTES];
    int i, j, k;

    mcs->comm_list = malloc(sizeof (secp256k1_keypair*) * mcs->mc.nr_messages * V);

    /* Create nr_messages * V batch commitments for signer */
    for (k = 0, i = 0; k < mcs->mc.nr_messages; k++) {
        for (j = 0; j < V; j++, i++) {
            mcs->comm_list[i] = malloc(sizeof(secp256k1_keypair));
            while (1) {
                if (!fill_random(x, MUSIG2_SCALAR_BYTES)) {
                    return MUSIG2_ERR_BATCH_COMM;
                }
                if (secp256k1_keypair_create(mcs->mc.ctx, mcs->comm_list[i], x)) {
                    break;
                }
            }
        }
    }
    return MUSIG2_OK;
}

static void musig2_key_agg_coef(musig2_context *mc, unsigned char *a, unsigned char *serialized_pubkey) {

    unsigned char tag[13] = "BIP0340/nonce";    // Tag of hash to generate the exponents
    unsigned char temp_concat[(mc->nr_signers + 1) * MUSIG2_AGGR_PUBKEY_BYTES]; // Temp to store the concatenation of public keys

    memcpy(temp_concat, mc->L, mc->nr_signers * MUSIG2_AGGR_PUBKEY_BYTES ); /* Copy L into temp_concat */
    memcpy(&temp_concat[mc->nr_signers * MUSIG2_AGGR_PUBKEY_BYTES], serialized_pubkey, MUSIG2_AGGR_PUBKEY_BYTES );  /* Copy given pk besides L */
    assert(secp256k1_tagged_sha256(mc->ctx, a, tag, sizeof (tag), temp_concat, sizeof (temp_concat)));

}

static void musig2_calc_b(musig2_context *mc, unsigned char *b, const unsigned char *serialized_aggr_pubkey, const unsigned char *msg, int msg_len, int state) {

    secp256k1_xonly_pubkey temp_xonly_R;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag for the hash to compute b
    unsigned char serialized_aggr_R[MUSIG2_AGGR_PUBKEY_BYTES];
    unsigned char temp_concat[(1 + V) * MUSIG2_AGGR_PUBKEY_BYTES + msg_len]; // Temp value to store the concatenation of aggr_pubkey, aggr_R_list and the message.
    int j;

    /* Copy serialized_aggr_pubkey into temp_concat */
    memcpy(temp_concat, serialized_aggr_pubkey, MUSIG2_AGGR_PUBKEY_BYTES);

    /* Get x_only R_j, serialize and concatenate. */
    for (j = 0; j < V; j++) {
        assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_xonly_R, NULL, mc->aggr_R_list[state * V + j]));
        secp256k1_xonly_pubkey_serialize(mc->ctx, serialized_aggr_R, &temp_xonly_R);
        memcpy(&temp_concat[MUSIG2_AGGR_PUBKEY_BYTES * (j + 1)], serialized_aggr_R, MUSIG2_AGGR_PUBKEY_BYTES);
    }

    /* Concatenate msg to end */
    memcpy(&temp_concat[(1 + V) * MUSIG2_AGGR_PUBKEY_BYTES], msg, msg_len);

    /* Compute b */
    assert(secp256k1_tagged_sha256(mc->ctx, b, tag, sizeof (tag), temp_concat, sizeof(temp_concat)));

}

static MUSIG2_ERROR musig2_calc_R(musig2_context *mc, secp256k1_xonly_pubkey *aggr_R, int *R_parity, unsigned char b_LIST[V][MUSIG2_SCALAR_BYTES], unsigned char *b, int state) {

    secp256k1_pubkey tweakable_Rb_list[V];
    secp256k1_pubkey *Rb_list[V];
    secp256k1_pubkey temp_R;
    secp256k1_xonly_pubkey temp_xonly_pubkey;   // temp value to store xonly point
    int j;

    for (j = 0; j < V; j++)
        memcpy(tweakable_Rb_list[j].data, mc->aggr_R_list[state * V + j]->data, MUSIG2_PUBKEY_BYTES_FULL);

    /* Compute b_LIST = { b^(j-1) } and Rb_LIST = { R_j * b^(j-1) } */
    b_LIST[0][31] = 1; // first element of b_LIST = 1;
    Rb_list[0] = &tweakable_Rb_list[0];
    for (j = 1; j < V; j++) {
        Rb_list[j] = &tweakable_Rb_list[j];
        memcpy(b_LIST[j], b_LIST[j-1], MUSIG2_SCALAR_BYTES);
        if (!secp256k1_ec_seckey_tweak_mul(mc->ctx, b_LIST[j], b)) {
            return MUSIG2_ERR_CALC_R;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, Rb_list[j], b_LIST[j])) {
            return MUSIG2_ERR_CALC_R;
        }
    }

    /* R = SUM ({ R_j * b^(j-1) }) */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &temp_R, (const secp256k1_pubkey *const *)Rb_list, V))
        return MUSIG2_ERR_CALC_R;

    /* Get x_only versions and parities of aggregated public key and aggregated R */
    assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_xonly_pubkey, &mc->pk_parity, &mc->aggr_pubkey));
    assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, aggr_R, R_parity, &temp_R));

    /* If just the parity of R is 1, negate b_list and change the parity of R */
    if (*R_parity == 1 && mc->pk_parity == 0){
        for (j = 0; j < V; j++) {
            if (!secp256k1_ec_seckey_negate(mc->ctx, b_LIST[j])) {
                return MUSIG2_ERR_CALC_R;
            }
        }
        *R_parity = 0;
    }
    return MUSIG2_OK;
}

static MUSIG2_ERROR musig2_set_parsig(musig2_context_signer *mcs, unsigned char *partial_signature, unsigned char b_LIST[V][MUSIG2_SCALAR_BYTES], unsigned char *a, unsigned char *c, int R_parity) {

    unsigned char sr_list[V][MUSIG2_SCALAR_BYTES];
    unsigned char temp_rb[MUSIG2_SCALAR_BYTES];
    unsigned char x[MUSIG2_SCALAR_BYTES];
    int j;

    /* Extract the secret key of the signer */
    assert(secp256k1_keypair_sec(mcs->mc.ctx, x, &mcs->keypair));

    /* Extract the nonces of the signer for current state */
    for (j = 0; j < V; j++) {
        assert(secp256k1_keypair_sec(mcs->mc.ctx, sr_list[j], mcs->comm_list[V * mcs->state + j]));
        free(mcs->comm_list[V * mcs->state + j]);
        mcs->comm_list[V * mcs->state + j] = NULL;
    }

    /* Update the state everytime we free the memory of a nonce */
    mcs->state++;

    /* Condition where R is even and PK is odd. We negate the challenge */
    if (R_parity == 0 && mcs->mc.pk_parity == 1) {
        if (!secp256k1_ec_seckey_negate(mcs->mc.ctx, c)){
            return MUSIG2_ERR_SET_PARSIG;
        }
    }

    /* Compute (a * x * c) */
    memcpy(partial_signature, c, MUSIG2_SCALAR_BYTES);
    if (!secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, partial_signature, x) ||
        !secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, partial_signature, a)) {
        return MUSIG2_ERR_SET_PARSIG;
    }

    /* Finalise the computation of a * x * c + \sum_{i=0}^V r_i * b_i */
    for (j = 0; j < V; j++) {
        memcpy(temp_rb, sr_list[j], MUSIG2_SCALAR_BYTES);
        if (!secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, temp_rb, b_LIST[j]) ||
            !secp256k1_ec_seckey_tweak_add(mcs->mc.ctx, partial_signature, temp_rb)) {
            return MUSIG2_ERR_SET_PARSIG;
        }
    }

    /* The third condition, if both R and pk are odd, we negate the partial signature. */
    if (R_parity == 1 && mcs->mc.pk_parity == 1) {
        if (!secp256k1_ec_seckey_negate(mcs->mc.ctx, partial_signature)) {
            return MUSIG2_ERR_SET_PARSIG;
        }
    }
    return MUSIG2_OK;
}

static MUSIG2_ERROR musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pubkey_list) {

    secp256k1_pubkey tweakable_pubkey_list[mc->nr_signers];
    const secp256k1_pubkey* pubkey_pointer_list[mc->nr_signers];
    secp256k1_xonly_pubkey temp_xonly_pubkey;
    unsigned char temp_a[MUSIG2_SCALAR_BYTES];
    unsigned char serialized_pubkey_list[mc->nr_signers][MUSIG2_AGGR_PUBKEY_BYTES];
    int i;

    /* Allocate memory for L */
    mc->L = malloc(MUSIG2_AGGR_PUBKEY_BYTES * mc->nr_signers);

    /* Multiply pk_i with a_i. Store in temp_pk_list[i]. */
    for (i = 0; i < mc->nr_signers; i++) {
        /* Copy the current public key into temp_pk_list */
        memcpy(tweakable_pubkey_list[i].data, pubkey_list[i].data, MUSIG2_PUBKEY_BYTES_FULL);
        pubkey_pointer_list[i] = &tweakable_pubkey_list[i];
        assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_xonly_pubkey, NULL, pubkey_pointer_list[i]));
        secp256k1_xonly_pubkey_serialize(mc->ctx, serialized_pubkey_list[i], &temp_xonly_pubkey);

        /* Update L */
        memcpy(&mc->L[i * MUSIG2_AGGR_PUBKEY_BYTES], serialized_pubkey_list[i], MUSIG2_AGGR_PUBKEY_BYTES);
    }

    for (i = 0; i < mc->nr_signers; i++) {
        /* Get the exponent `a` of current public key */
        musig2_key_agg_coef(mc, temp_a, serialized_pubkey_list[i]);

        /* Compute `pk_i * a_i` */
        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, (secp256k1_pubkey*)pubkey_pointer_list[i], temp_a))
            return MUSIG2_ERR_AGGR_PK;
    }

    /* Aggregate the public keys */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &mc->aggr_pubkey, pubkey_pointer_list, mc->nr_signers)) {
        return MUSIG2_ERR_AGGR_PK;
    }

    return MUSIG2_OK;
}

static MUSIG2_ERROR musig2_aggregate_R(musig2_context *mc, secp256k1_pubkey batch_list[][V], int state) {

    secp256k1_pubkey* temp_R_list[mc->nr_signers];
    int i, j;

    /* Aggregate the batch commitments for current message */
    for (j = 0; j < V; j++) {
        mc->aggr_R_list[state * V + j] = malloc(sizeof (secp256k1_pubkey));
        for (i = 0; i < mc->nr_signers; i++) {
            temp_R_list[i] = &batch_list[i][j];
        }
        if (!secp256k1_ec_pubkey_combine(mc->ctx, mc->aggr_R_list[state * V + j], (const secp256k1_pubkey *const *) temp_R_list, mc->nr_signers)) {
            return MUSIG2_ERR_AGGR_R;
        }
    }

    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_init_signer(musig2_context_signer *mcs, int nr_messages) {

    mcs->mc.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    mcs->state = 0;
    mcs->mc.nr_messages = nr_messages;

    /* Generate a key pair for given signer */
    if (musig2_key_gen(mcs) != MUSIG2_OK) {
        return MUSIG2_ERR_KEY_GEN;
    }
    if (musig2_batch_commitment(mcs) != MUSIG2_OK){
        return MUSIG2_ERR_BATCH_COMM;
    }
    return MUSIG2_OK;
}

void musig2_serialise_shareable_context(musig2_context_signer *mcs, unsigned char *serialized_pubkey, unsigned char serialized_batch_list[][MUSIG2_PUBKEY_BYTES_COMPRESSED]){
    secp256k1_pubkey temp_pk;
    size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED;
    int i;

    if (secp256k1_keypair_pub(mcs->mc.ctx, &temp_pk, &mcs->keypair)) {
        secp256k1_ec_pubkey_serialize(mcs->mc.ctx, serialized_pubkey, &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED);
    }

    for (i = 0; i < mcs->mc.nr_messages * V; i++) {
        if (secp256k1_keypair_pub(mcs->mc.ctx, &temp_pk, mcs->comm_list[i])) {
            secp256k1_ec_pubkey_serialize(mcs->mc.ctx, serialized_batch_list[i], &ser_size, &temp_pk, SECP256K1_EC_COMPRESSED);
        }
    }
}

MUSIG2_ERROR musig2_signer_precomputation(musig2_context *mc, unsigned char *serialized_pubkey_list, unsigned char *serialized_batch_list, int nr_signers){
    int i, j, k, ind;
    secp256k1_pubkey batch_list[mc->nr_messages][nr_signers][V];   // Stores the batches of signers
    secp256k1_pubkey pubkey_list[nr_signers];

    mc->nr_signers = nr_signers;
    mc->aggr_R_list = malloc(sizeof (secp256k1_pubkey*) * mc->nr_messages * V);


    /* Parse the batch commitments of the signers */
    for (i = 0; i < nr_signers; i++) {
        if (!secp256k1_ec_pubkey_parse(mc->ctx, &pubkey_list[i], &serialized_pubkey_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], MUSIG2_PUBKEY_BYTES_COMPRESSED)){
            return MUSIG2_ERR_PARSE_PK;
        }
        for (k = 0; k < mc->nr_messages; k++) {
            for (j = 0; j < V; j++) {
                ind = (k * nr_signers * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED;
                if(!secp256k1_ec_pubkey_parse(mc->ctx, &batch_list[k][i][j], &serialized_batch_list[ind], MUSIG2_PUBKEY_BYTES_COMPRESSED)){
                    return MUSIG2_ERR_PARSE_COMM;
                }
            }
        }
    }
    /* Aggregate pk */
    if (musig2_aggregate_pubkey(mc, pubkey_list) != MUSIG2_OK){
        return MUSIG2_ERR_AGGR_PK;
    }
    /* Aggregate R for each message to be signed. */
    for (k = 0; k < mc->nr_messages; k++) {
        if (musig2_aggregate_R(mc, batch_list[k], k) != MUSIG2_OK) {
            return MUSIG2_ERR_AGGR_R;
        }
    }
    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_sign(musig2_context_signer *mcs, musig2_context_signature *mps, const unsigned char *msg, int msg_len) {

    secp256k1_xonly_pubkey temp_xonly_pubkey;
    unsigned char serialized_pubkey[MUSIG2_AGGR_PUBKEY_BYTES];  // Serialized public key of signer
    unsigned char serialized_aggr_pubkey[MUSIG2_AGGR_PUBKEY_BYTES];
    unsigned char serialized_aggr_R[MUSIG2_AGGR_PUBKEY_BYTES];
    unsigned char bytes_to_hash[MUSIG2_AGGR_PUBKEY_BYTES * 2 + msg_len];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )
    unsigned char a[MUSIG2_SCALAR_BYTES], b[MUSIG2_SCALAR_BYTES], c[MUSIG2_SCALAR_BYTES];
    unsigned char b_LIST[V][MUSIG2_SCALAR_BYTES] = {0};
    int j, index, R_parity;

    index = V * mcs->state;
    for (j = 0; j < V; j++) {
        if (mcs->comm_list[index + j] == NULL) {
            return MUSIG2_ERR_CHECK_COMM;
        }
    }

    assert(secp256k1_keypair_xonly_pub(mcs->mc.ctx, &temp_xonly_pubkey, NULL, &mcs->keypair));
    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, serialized_pubkey, &temp_xonly_pubkey);

    /* Get the exponent `a` of signer */
    musig2_key_agg_coef(&mcs->mc, a, serialized_pubkey);

    assert(secp256k1_xonly_pubkey_from_pubkey(mcs->mc.ctx, &temp_xonly_pubkey, NULL, &mcs->mc.aggr_pubkey));
    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, serialized_aggr_pubkey, &temp_xonly_pubkey);

    musig2_calc_b(&mcs->mc, b, serialized_aggr_pubkey, msg, msg_len, mcs->state);

    /* Compute `R` */
    if (musig2_calc_R(&mcs->mc, (secp256k1_xonly_pubkey *) &mps->R, &R_parity, b_LIST, b, mcs->state) != MUSIG2_OK) {
        return MUSIG2_ERR_CALC_R;
    }

    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, serialized_aggr_R, &mps->R);

    memcpy(bytes_to_hash, &serialized_aggr_R, MUSIG2_AGGR_PUBKEY_BYTES);
    memcpy(&bytes_to_hash[MUSIG2_AGGR_PUBKEY_BYTES], &serialized_aggr_pubkey, MUSIG2_AGGR_PUBKEY_BYTES);
    memcpy(&bytes_to_hash[MUSIG2_AGGR_PUBKEY_BYTES * 2], msg, msg_len);

    assert(secp256k1_tagged_sha256(mcs->mc.ctx, c, (const unsigned char *)"BIP0340/challenge" , 17, bytes_to_hash, sizeof (bytes_to_hash)));

    if (musig2_set_parsig(mcs, mps->signature, b_LIST, a, c, R_parity) != MUSIG2_OK) {
        return MUSIG2_ERR_SET_PARSIG;
    }

    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_aggregate_partial_sig(musig2_context_signature *mps, unsigned char *signature, int nr_signatures) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    int i;

    /* Check whether all aggregated R are equal */
    for (i = 1; i < nr_signatures; i++) {
        if (secp256k1_xonly_pubkey_cmp(ctx, &mps[i].R, &mps[i - 1].R) != 0) {
            return MUSIG2_ERR_CMP_R ;
        }
    }

    /* Serialize R to store in signature */
    secp256k1_xonly_pubkey_serialize(ctx, signature, &mps[0].R);

    /* Aggregate the partial signatures */
    memcpy(signature + MUSIG2_AGGR_PUBKEY_BYTES, mps[0].signature, MUSIG2_SCALAR_BYTES);
    for (i = 1; i < nr_signatures; i++) {
        if (!secp256k1_ec_seckey_tweak_add(ctx, signature + MUSIG2_AGGR_PUBKEY_BYTES, mps[i].signature)) {
            secp256k1_context_destroy(ctx);
            return MUSIG2_ERR_ADD_PARSIG;
        }
    }

    secp256k1_context_destroy(ctx);
    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_prepare_verifier(musig2_aggr_pubkey *aggr_pubkey, unsigned char *serialized_pubkey_list, int nr_signers) {

    musig2_context verifier_context;
    secp256k1_pubkey pubkey_list[nr_signers];
    int i;

    verifier_context.aggr_R_list = NULL;
    verifier_context.nr_signers = nr_signers;
    verifier_context.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    for (i = 0; i < nr_signers; i++) {
        if (!secp256k1_ec_pubkey_parse(verifier_context.ctx, &pubkey_list[i], &serialized_pubkey_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED],
                                         MUSIG2_PUBKEY_BYTES_COMPRESSED)){
            return MUSIG2_ERR_PARSE_PK;
        }
    }

    if (musig2_aggregate_pubkey(&verifier_context, pubkey_list) != MUSIG2_OK) {
        musig2_context_free(&verifier_context);
        return MUSIG2_ERR_AGGR_PK;
    }

    /* Get the xonly public key */
    assert(secp256k1_xonly_pubkey_from_pubkey(verifier_context.ctx, aggr_pubkey, NULL, &verifier_context.aggr_pubkey));

    musig2_context_free(&verifier_context);
    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_verify(musig2_aggr_pubkey *aggr_pubkey, unsigned char *signature, const unsigned char *msg, int msg_len){
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_schnorrsig_verify(ctx, signature, msg, msg_len, aggr_pubkey)) {
        secp256k1_context_destroy(ctx);
        return MUSIG2_OK;
    }
    secp256k1_context_destroy(ctx);
    return MUSIG2_INVALID;
}

void musig2_context_free(musig2_context *mc) {
    int l;
    if (mc->ctx != NULL) {
        secp256k1_context_destroy(mc->ctx);
    }
    if (mc->L != NULL) {
        free(mc->L);
    }
    if (mc->aggr_R_list != NULL) {
        for (l = 0; l < V * mc->nr_messages; l++) {
            if (mc->aggr_R_list != NULL){
                free(mc->aggr_R_list[l]);
            }
        }
        free(mc->aggr_R_list);
    }
}

void musig2_context_sig_free(musig2_context_signer *mcs) {
    int l;
    for (l = mcs->state * V; l < mcs->mc.nr_messages * V; l++) {
        free(mcs->comm_list[l]);
    }
    free(mcs->comm_list);
    musig2_context_free(&mcs->mc);
}
