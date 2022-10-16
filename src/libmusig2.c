#include "libmusig2.h"

static int musig2_key_gen(musig2_context_sig *mcs) {
    unsigned char x[SCALAR_BYTES];

    while (1) {
        if (!fill_random(x, sizeof(x))) {
            printf("Failed to generate randomness\n");
            return 0;
        }
        /* Try to create a keypair with a valid context, it should only fail if
         * the secret key is zero or out of range. */
        if (secp256k1_keypair_create(mcs->mc.ctx, &mcs->keypair, x))
            return 1;
    }
}

static int musig2_batch_commitment(musig2_context_sig *mcs) {

    unsigned char x[SCALAR_BYTES];
    mcs->comm_list = malloc(sizeof (secp256k1_keypair*) * mcs->nr_messages * V);

    int i, j, k;
    i = 0;
    /* Create nr_msgs * V batch commitments for signer */
    for (k = 0; k < mcs->nr_messages; k++) {
        for (j = 0; j < V; j++, i++) {
            mcs->comm_list[i] = malloc(sizeof(secp256k1_keypair));
            while (1) {
                if (!fill_random(x, SCALAR_BYTES)) {
                    printf("Failed to generate randomness\n");
                    musig2_context_sig_destroy(mcs);
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
    unsigned char temp_concat[(mc->nr_signers + 1) * XONLY_BYTES];    // Temp to store the concatenation of public keys

    memcpy(temp_concat, mc->L, mc->nr_signers * XONLY_BYTES );      // Copy L into temp_concat
    memcpy(&temp_concat[mc->nr_signers * XONLY_BYTES], ser_pk, XONLY_BYTES );  /* Copy given pk besides L */
    assert(secp256k1_tagged_sha256(mc->ctx, a, tag, sizeof (tag), temp_concat, sizeof (temp_concat)));
}

static void musig2_calc_b(musig2_context *mc, const unsigned char *ser_aggr_pk, unsigned char *b, const unsigned char *msg, int msg_len) {

    int j;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag for the hash to compute b
    unsigned char ser_R[XONLY_BYTES];
    unsigned char temp_concat[(1 + V) * XONLY_BYTES + msg_len]; // Temp value to store the concatenation of aggr_pk, aggr_R_list and the message.
    secp256k1_xonly_pubkey xonly_R;

    /* Copy ser_aggr_pk into temp_concat */
    memcpy(temp_concat, ser_aggr_pk, XONLY_BYTES);

    /* Get x_only R_j, serialize and concatenate. */
    for (j = 0; j < V; j++) {
        assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &xonly_R, NULL, &mc->aggr_R_list[j]));
        secp256k1_xonly_pubkey_serialize(mc->ctx, ser_R, &xonly_R);
        memcpy(&temp_concat[XONLY_BYTES * (j + 1)], ser_R, XONLY_BYTES);
    }

    /* Concatenate msg to end */
    memcpy(&temp_concat[(1 + V) * XONLY_BYTES], msg, msg_len);

    /* Compute b */
    assert(secp256k1_tagged_sha256(mc->ctx, b, tag, sizeof (tag), temp_concat, sizeof(temp_concat)));

}

static int musig2_calc_R(musig2_context *mc, unsigned char *b, unsigned char b_LIST[V][SCALAR_BYTES]) {

    int j;
    unsigned char ser_aggr_pk[XONLY_BYTES];
    secp256k1_pubkey tweakable_Rb_list[V];
    secp256k1_pubkey *Rb_list[V];
    secp256k1_xonly_pubkey xonly_temp;   // temp value to store xonly point

    for (j = 0; j < V; j++)
        memcpy(tweakable_Rb_list[j].data, mc->aggr_R_list[j].data, PK_BYTES);
    /* Compute b_LIST = { b^(j-1) } and Rb_LIST = { R_j * b^(j-1) } */
    b_LIST[0][31] = 1; // first element of b_LIST = 1;
    Rb_list[0] = &tweakable_Rb_list[0];

    for (j = 1; j < V; j++) {
        Rb_list[j] = &tweakable_Rb_list[j];
        memcpy(b_LIST[j], b_LIST[j-1], SCALAR_BYTES);
        if (!secp256k1_ec_seckey_tweak_mul(mc->ctx, b_LIST[j], b))
            return 0;

        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, Rb_list[j], b_LIST[j]))
            return 0;
    }

    /* R = SUM ({ R_j * b^(j-1) }) */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &mc->aggr_R, (const secp256k1_pubkey *const *)Rb_list, V))
        return 0;

    /* Get x_only version of aggregated public key and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &xonly_temp, &mc->par_pk, &mc->aggr_pk));

    /* Get x_only version of aggregated R and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &xonly_temp, &mc->par_R, &mc->aggr_R));

    if (mc->par_R == 1 && mc->par_pk == 0){
        // we negate b_LIST
        for (j = 0; j < V; j++) {
            if (!secp256k1_ec_seckey_negate(mc->ctx, b_LIST[j])) {
                printf("Failed to negate b. \n");
                return 0;
            }
        }
        // we negate R
        mc->par_R = 0;
    }

    return 1;
}

static int musig2_set_parsig(musig2_context_sig *mcs, unsigned char *a, unsigned char *c, unsigned char b_LIST[V][SCALAR_BYTES], unsigned char *parsig) {
    int j;
    unsigned char temp_rb[SCALAR_BYTES];
    unsigned char x[SCALAR_BYTES];
    unsigned char sr_list[V][SCALAR_BYTES];

    /* Extract the secret key of the signer */
    assert(secp256k1_keypair_sec(mcs->mc.ctx, x, &mcs->keypair));

    /* Extract the nonces of the signer for current state */
    for (j = 0; j < V; j++){
        assert(secp256k1_keypair_sec(mcs->mc.ctx, sr_list[j], mcs->comm_list[V * mcs->state + j]));
        free(mcs->comm_list[V * mcs->state + j]);
    }

    /* Update the state everytime we free the memory of a nonce */
    mcs->state++;

    // Condition where R is even and PK is odd. We negate the challenge
    if (mcs->mc.par_R == 0 && mcs->mc.par_pk == 1){
        if (!secp256k1_ec_seckey_negate(mcs->mc.ctx, c)){
            printf("Failed to negate c. \n");
            return 0;
        }
    }

    /* Compute (a * x * c) */
    memcpy(parsig, c, SCALAR_BYTES);
    if (!secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, parsig, x) || !secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, parsig, a))
        return 0;

    /* Finalise the computation of a * x * c + \sum_{i=0}^V r_i * b_i */
    for (j = 0; j < V; j++) {
        memcpy(temp_rb, sr_list[j], SCALAR_BYTES);
        if (!secp256k1_ec_seckey_tweak_mul(mcs->mc.ctx, temp_rb, b_LIST[j]) || !secp256k1_ec_seckey_tweak_add(mcs->mc.ctx, parsig, temp_rb))
            return 0;
    }

    // The third condition, if both R and pk are odd, we negate the partial signature.
    if (mcs->mc.par_R == 1 && mcs->mc.par_pk == 1){
        if (!secp256k1_ec_seckey_negate(mcs->mc.ctx, parsig)){
            printf("Failed to negate partial signature. \n");
            return 0;
        }
    }

    return 1;
}

/*** Destroy MuSig2 context ***/
void musig2_context_destroy(musig2_context *mc) {
    if (mc->L != NULL) {
        free(mc->L);
    }
}

/*** Destroy MuSig2 Sig context ***/
void musig2_context_sig_destroy(musig2_context_sig *mcs) {
    for (int l = mcs->state * V; l < mcs->nr_messages * V; l++) {
        free(mcs->comm_list[l]);
    }
    free(mcs->comm_list);
    musig2_context_destroy(&mcs->mc);
}

/**** Signer ****/
int musig2_init_signer(musig2_context_sig *mcs, secp256k1_context *ctx, int nr_messages) {

    mcs->mc.ctx = ctx;
    mcs->state = 0;
    mcs->nr_messages = nr_messages;

    /* Generate a key pair for given signer */
    if (!musig2_key_gen(mcs))
        return 0;

    /* Generate the batch commitments for given signer */
    if (!musig2_batch_commitment(mcs))
        return 0;

    return 1;
}

int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list, int nr_signers) {

    int i;
    unsigned char temp_a[SCALAR_BYTES];
    unsigned char ser_pk_list[nr_signers][XONLY_BYTES];
    secp256k1_pubkey tweakable_pk_list[nr_signers];
    const secp256k1_pubkey* pk_pointer_list[nr_signers];
    secp256k1_xonly_pubkey temp_xonly_pk;

    /* Allocate memory for L */
    mc->L = malloc(XONLY_BYTES * nr_signers);
    mc->nr_signers = nr_signers;

    /* Multiply pk_i with a_i. Store in temp_pk_list[i]. */
    for (i = 0; i < nr_signers; i++) {
        /* Copy the current public key into temp_pk_list */
        memcpy(tweakable_pk_list[i].data, pk_list[i].data, PK_BYTES);
        pk_pointer_list[i] = &tweakable_pk_list[i];
        assert(secp256k1_xonly_pubkey_from_pubkey(mc->ctx, &temp_xonly_pk, NULL, pk_pointer_list[i]));
        secp256k1_xonly_pubkey_serialize(mc->ctx, ser_pk_list[i], &temp_xonly_pk);

        /* Update L */
        memcpy(&mc->L[i * XONLY_BYTES], ser_pk_list[i], XONLY_BYTES);
    }

    for (i = 0; i < nr_signers; i++) {
        /* Get the exponent `a` of current public key */
        musig2_key_agg_coef(mc, ser_pk_list[i], temp_a);

        /* Compute `pk_i * a_i` */
        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, (secp256k1_pubkey*)pk_pointer_list[i], temp_a)){
            printf("Failed to generate partial multiplication. \n");
            musig2_context_destroy(mc);
            return 0;
        }
    }

    /* Aggregate the public keys */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &mc->aggr_pk, pk_pointer_list, nr_signers)){
        printf("Failed to aggregate public keys. \n");
        musig2_context_destroy(mc);
        return 0;
    }

    return 1;
}

int musig2_aggregate_R(musig2_context *mc, secp256k1_pubkey batch_list[][V]) {

    int i, j;
    secp256k1_pubkey* temp_R_list[mc->nr_signers];

    /* Aggregate the batch commitments for current message */
    for (j = 0; j < V; j++) {
        for (i = 0; i < mc->nr_signers; i++) {
            temp_R_list[i] = &batch_list[i][j];
        }
        if (!secp256k1_ec_pubkey_combine(mc->ctx, &mc->aggr_R_list[j], (const secp256k1_pubkey *const *) temp_R_list, mc->nr_signers)){
            printf("Failed to aggregate commitments. \n");
            return 0;
        }
    }
    return 1;
}

int musig2_sign(musig2_context_sig *mcs, musig2_partial_signatures *mps, const unsigned char *msg, int msg_len) {

    unsigned char ser_aggr_pk[XONLY_BYTES];
    unsigned char ser_aggr_R[XONLY_BYTES];
    unsigned char bytes_to_hash[XONLY_BYTES * 2 + msg_len];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )
    unsigned char a[SCALAR_BYTES], b[SCALAR_BYTES], c[SCALAR_BYTES];
    unsigned char b_LIST[V][SCALAR_BYTES] = {0};

    unsigned char ser_pk[XONLY_BYTES];  // Serialized public key of signer
    secp256k1_xonly_pubkey xonly_temp;

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

    musig2_calc_b(&mcs->mc, ser_aggr_pk, b, msg, msg_len);
    /* Compute `R` */
    if (!musig2_calc_R(&mcs->mc, b, b_LIST)){
        printf("Failed to calculate R. \n");
        return 0;
    }

    assert(secp256k1_xonly_pubkey_from_pubkey(mcs->mc.ctx, &xonly_temp, NULL, &mcs->mc.aggr_R));
    secp256k1_xonly_pubkey_serialize(mcs->mc.ctx, ser_aggr_R, &xonly_temp);

    memcpy(bytes_to_hash, &ser_aggr_R, XONLY_BYTES);
    memcpy(&bytes_to_hash[XONLY_BYTES], &ser_aggr_pk, XONLY_BYTES);
    memcpy(&bytes_to_hash[XONLY_BYTES * 2], msg, msg_len);

    assert(secp256k1_tagged_sha256(mcs->mc.ctx, c, (const unsigned char *)"BIP0340/challenge" , 17, bytes_to_hash, sizeof (bytes_to_hash)));

    if (!musig2_set_parsig(mcs, a, c, b_LIST, parsig)) {
        printf("Failed to generate partial signature. \n");
        return 0;
    }

    return 1;
}

/**** Aggregator ****/
int musig2_aggregate_partial_sig(secp256k1_context *ctx, musig2_partial_signatures *mps, unsigned char *signature, int nr_signatures) {
    int i;
    secp256k1_xonly_pubkey xonly_R; // x_only R

    /* Check whether all aggregated R are equal */
    for (i = 1; i < nr_signatures; i++) {
        if (secp256k1_ec_pubkey_cmp(ctx, &mps[i].R, &mps[i - 1].R) != 0){
            return -1 ;
        }
    }

    /* Get x_only R */
    assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_R, NULL, &mps[0].R));

    /* Serialize R to store in signature */
    secp256k1_xonly_pubkey_serialize(ctx, signature, &xonly_R);

    /* Aggregate the partial signatures */
    memcpy(signature + XONLY_BYTES, mps[0].sig, SCALAR_BYTES);
    for (i = 1; i < nr_signatures; i++) {
        if (!secp256k1_ec_seckey_tweak_add(ctx, signature + XONLY_BYTES, mps[i].sig)){
            printf("Failed to aggregate signatures. \n");
            return 0;
        }
    }

    return 1;
}
