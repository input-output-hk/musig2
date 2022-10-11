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
        if (secp256k1_keypair_create(mcs->mc->ctx, &mcs->keypair, x))
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
        for (j = 0; j < V; j++) {
            mcs->comm_list[i] = malloc(sizeof(secp256k1_keypair));
            while (1) {
                if (!fill_random(x, SCALAR_BYTES)) {
                    printf("Failed to generate randomness\n");
                    return 0;
                }
                if (secp256k1_keypair_create(mcs->mc->ctx, mcs->comm_list[i], x))
                    break;
            }
            i++;
        }
    }
    return 1;
}

static void musig2_key_agg_coef(musig2_context *mc, unsigned char *ser_pk, unsigned char *a, unsigned char *L) {

    unsigned char tag[13] = "BIP0340/nonce";    // Tag of hash to generate the exponents
    unsigned char temp_concat[(mc->nr_signers + 1) * XONLY_BYTES];    // Temp to store the concatenation of public keys

    memcpy(temp_concat, L, mc->nr_signers * XONLY_BYTES );      // Copy L into temp_concat
    memcpy(&temp_concat[mc->nr_signers * XONLY_BYTES], ser_pk, XONLY_BYTES );  /* Copy given pk besides L */
    assert(secp256k1_tagged_sha256(mc->ctx, a, tag, sizeof (tag), temp_concat, sizeof (temp_concat)));
}

static void musig2_calc_b(musig2_context_sig *mcs, musig2_param *param) {

    int j;
    unsigned char tag[13] = "BIP0340/nonce";    // Tag for the hash to compute b
    unsigned char ser_R[XONLY_BYTES];
    unsigned char temp_concat[(1 + V) * XONLY_BYTES + param->msg_len]; // Temp value to store the concatenation of aggr_pk, aggr_R_list and the message.
    secp256k1_xonly_pubkey xonly_R;

    /* Copy ser_aggr_pk into temp_concat */
    memcpy(temp_concat, param->ser_aggr_pk, XONLY_BYTES);

    /* Get x_only R_j, serialize and concatenate. */
    for (j = 0; j < V; j++) {
        assert(secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &xonly_R, NULL, &mcs->aggr_R_list[j]));
        secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, ser_R, &xonly_R);
        memcpy(&temp_concat[XONLY_BYTES * (j + 1)], ser_R, XONLY_BYTES);
    }

    /* Concatenate msg to end */
    memcpy(&temp_concat[(1 + V) * XONLY_BYTES], param->msg, param->msg_len);

    /* Compute b */
    assert(secp256k1_tagged_sha256(mcs->mc->ctx, param->b, tag, sizeof (tag), temp_concat, sizeof(temp_concat)));

}

static int musig2_calc_R(musig2_context_sig *mcs, musig2_param *param) {

    int j;
    secp256k1_pubkey tweakable_Rb_list[V];
    secp256k1_pubkey *Rb_list[V];
    secp256k1_xonly_pubkey temp_xonly_R;

    /* Compute b_LIST = { b^(j-1) } and Rb_LIST = { R_j * b^(j-1) } */
    for (j = 0; j < V; j++) {
        memcpy(tweakable_Rb_list[j].data, mcs->aggr_R_list[j].data, PK_BYTES);
        Rb_list[j] = &tweakable_Rb_list[j];
        if (j == 0 && param->par_R == 0) {
        }
        else if (j == 0 && param->par_R == 1) {
            assert(secp256k1_ec_pubkey_negate(mcs->mc->ctx, Rb_list[j]));
        }
        else {
            if (j == 1){
                /* If j = 1 => b_LIST[j] = b .*/
                memcpy(param->b_LIST[j], param->b, SCALAR_BYTES);
                if (!secp256k1_ec_pubkey_tweak_mul(mcs->mc->ctx, Rb_list[j], param->b_LIST[j]))
                    return 0;
            }
            else{
                memcpy(param->b_LIST[j], param->b_LIST[j-1], SCALAR_BYTES);
                /* Compute b * b^(j-1) */
                if (!secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, param->b_LIST[j], param->b))
                    return 0;

                assert(secp256k1_ec_seckey_negate(mcs->mc->ctx, param->b_LIST[j]));

                if (!secp256k1_ec_pubkey_tweak_mul(mcs->mc->ctx, Rb_list[j], param->b_LIST[j]))
                    return 0;
            }
        }
    }

    /* R = SUM ({ R_j * b^(j-1) })
     * Get x_only R, store in xonly_temp
     * Get parity R to check whether b is needed to be negated.
     * Serialize x_only R into ser_xonly_R */
    if (!secp256k1_ec_pubkey_combine(mcs->mc->ctx, &mcs->mc->aggr_R, (const secp256k1_pubkey *const *)Rb_list, V))
        return 0;

    assert(secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &temp_xonly_R, &param->par_R, &mcs->mc->aggr_R));
    assert(secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param->ser_aggr_R, &temp_xonly_R));

    return 1;
}

static void musig2_calc_c(musig2_context *mc, musig2_param *param) {
    unsigned char tag[17] = "BIP0340/challenge";        // Tag of the hash to compute challenge.

    unsigned char temp_concat[XONLY_BYTES * 2 + param->msg_len];   // Temp to store ( ser_xonly_R || ser_xonly_X_ || msg_hash )

    memcpy(temp_concat, param->ser_aggr_R, XONLY_BYTES);
    memcpy(&temp_concat[XONLY_BYTES], param->ser_aggr_pk, XONLY_BYTES);
    memcpy(&temp_concat[XONLY_BYTES * 2], param->msg, param->msg_len);

    assert(secp256k1_tagged_sha256(mc->ctx, param->c, tag , sizeof (tag), temp_concat, sizeof (temp_concat)));
}

static int musig2_set_parsig(musig2_context_sig *mcs, musig2_param *param, unsigned char *parsig) {
    int j;
    unsigned char temp_rb[SCALAR_BYTES];
    unsigned char sum_rb[SCALAR_BYTES];
    unsigned char x[SCALAR_BYTES];
    unsigned char sr_list[V][SCALAR_BYTES];

    /* Extract the secret key of the signer */
    assert(secp256k1_keypair_sec(mcs->mc->ctx, x, &mcs->keypair));

    /* Extract the nonces of the signer for current state and message */
    int index = V * mcs->mc->state;
    for (j = 0; j < V; j++){
        assert(secp256k1_keypair_sec(mcs->mc->ctx, sr_list[j], mcs->comm_list[index + j]));
        mcs->comm_list[index + j] = NULL;
    }

    /* Compute (a * x * c) */
    memcpy(parsig, param->c, SCALAR_BYTES);
    if (!secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, parsig, x) || !secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, parsig, param->a))
        return 0;

    /* If j = 0 => b = -1. So, r_0 * b_LIST[0] = - sec_r_LIST[0].
     * If j = 0 => b = 1.
     * Else, Copy r_j to temp_rb, compute r_j * b_LIST[j], and add temp_rb to sum_rb. */
    for (j = 0; j < V; j++) {
        /* If the parity of R is -1 negate `b` (b=1) or equivalently negate sr_list[j] */
        if (j == 0 && param->par_R == -1) {
            if(!secp256k1_ec_seckey_negate(mcs->mc->ctx, sr_list[j]))
                return 0;

            memcpy(sum_rb, sr_list[j], SCALAR_BYTES);
        }
        else if (j == 0) memcpy(sum_rb, sr_list[j], SCALAR_BYTES);
        else {
            memcpy(temp_rb, sr_list[j], SCALAR_BYTES);
            if (!secp256k1_ec_seckey_tweak_mul(mcs->mc->ctx, temp_rb, param->b_LIST[j]) || !secp256k1_ec_seckey_tweak_add(mcs->mc->ctx, sum_rb, temp_rb))
                return 0;
        }
    }

    /* Finalize response */
    if (!secp256k1_ec_seckey_tweak_add(mcs->mc->ctx, parsig, sum_rb))
        return 0;

    return 1;
}


/**** Signer ****/
int musig2_init_signer(musig2_context_sig *mcs, secp256k1_context *ctx, int nr_messages) {

    mcs->mc = malloc(sizeof (musig2_context));
    mcs->mc->ctx = ctx;
    mcs->mc->state = 0;
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
    unsigned char *ser_pk_list[nr_signers];
    secp256k1_pubkey tweakable_pk_list[nr_signers];
    const secp256k1_pubkey* pk_pointer_list[nr_signers];
    secp256k1_xonly_pubkey temp_xonly_pk;

    /* Allocate memory for L */
    mc->L = malloc(XONLY_BYTES * nr_signers);
    mc->nr_signers = nr_signers;

    /* Multiply pk_i with a_i. Store in temp_pk_list[i]. */
    for (i = 0; i < nr_signers; i++) {
        ser_pk_list[i] = malloc(XONLY_BYTES);

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
        musig2_key_agg_coef(mc, ser_pk_list[i], temp_a, mc->L);

        /* Compute `pk_i * a_i` */
        if (!secp256k1_ec_pubkey_tweak_mul(mc->ctx, (secp256k1_pubkey*)pk_pointer_list[i], temp_a)){
            printf("Failed to generate partial multiplication. \n");
            return 0;
        }
    }

    /* Aggregate the public keys */
    if (!secp256k1_ec_pubkey_combine(mc->ctx, &mc->aggr_pk, pk_pointer_list, nr_signers)){
        printf("Failed to aggregate public keys. \n");
        return 0;
    }

    return 1;
}

int musig2_aggregate_R(musig2_context_sig *mcs, secp256k1_pubkey *batch_list) {

    int i, j;
    int ind = mcs->mc->state * (V * mcs->mc->nr_signers);
    secp256k1_pubkey* temp_R_list[mcs->mc->nr_signers];

    /* Aggregate the batch commitments for current message */
    for (j = 0; j < V; j++) {
        i = 0;
        while (i < mcs->mc->nr_signers) {
            temp_R_list[i] = malloc(sizeof (secp256k1_pubkey));
            memcpy(temp_R_list[i++], batch_list[ind++].data, PK_BYTES);
        }
        if (!secp256k1_ec_pubkey_combine(mcs->mc->ctx, &mcs->aggr_R_list[j], (const secp256k1_pubkey *const *) temp_R_list, mcs->mc->nr_signers)){
            printf("Failed to aggregate commitments. \n");
            return 0;
        }
    }
    return 1;
}

int musig2_sign(musig2_context_sig *mcs, musig2_partial_signatures *mps, const unsigned char *msg, int msg_len) {

    unsigned char ser_pk[XONLY_BYTES];  // Serialized public key of signer
    secp256k1_xonly_pubkey xonly_pk;    // x_only public key of signer
    secp256k1_xonly_pubkey xonly_aggr_pk;   // x_only aggregated public key
    musig2_param param;  // Parameters used to generate partial signature

    int j;
    int index = V * mcs->mc->state;
    for (j = 0; j < V; j++)
        if (mcs->comm_list[index + j] == NULL)
            return -1;

    /* Set the message and its length to param */
    param.msg = malloc(msg_len);
    memcpy(param.msg, msg, msg_len);
    param.msg_len = msg_len;

    /* Get the exponent `a` of signer */
    assert(secp256k1_keypair_xonly_pub(mcs->mc->ctx, &xonly_pk, NULL, &mcs->keypair));
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, ser_pk, &xonly_pk);
    musig2_key_agg_coef(mcs->mc, ser_pk, param.a, mcs->mc->L);

    /* Get x_only version of aggregated public key and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mcs->mc->ctx, &xonly_aggr_pk, &param.par_pk, &mcs->mc->aggr_pk));
    secp256k1_xonly_pubkey_serialize(mcs->mc->ctx, param.ser_aggr_pk, &xonly_aggr_pk);


    /* Compute `b`, `R`, and `c` */
    param.par_R = 0;
    musig2_calc_b(mcs, &param);
    if (!musig2_calc_R(mcs, &param)){
        printf("Failed to calculate R. \n");
        return 0;
    }
    musig2_calc_c(mcs->mc, &param);

    /* If par_R is 1, then negate b, call Calc_R again, and compute parsig */
    if (param.par_R == 1 && param.par_pk == 0){
        if (!secp256k1_ec_seckey_negate(mcs->mc->ctx, param.b)){
            printf("Failed to negate b. \n");
            return 0;
        }
        if (!musig2_calc_R(mcs, &param)){
            printf("Failed to calculate R. \n");
            return 0;
        }
        param.par_R = -1;
        if (!musig2_set_parsig(mcs, &param, mps->sig)){
            printf("Failed to generate partial signature. \n");
            return 0;
        }
    }
    /* If par_pk is 1, negate c and compute parsig */
    else if (param.par_R == 0 && param.par_pk == 1){
        if (!secp256k1_ec_seckey_negate(mcs->mc->ctx, param.c)){
            printf("Failed to negate c. \n");
            return 0;
        }
        if (!musig2_set_parsig(mcs, &param, mps->sig)){
            printf("Failed to generate partial signature. \n");
            return 0;
        }
    }
    /* If par_pk == par_R, compute parsig */
    else{
        if (!musig2_set_parsig(mcs, &param, mps->sig)){
            printf("Failed to generate partial signature. \n");
            return 0;
        }
    }

    memcpy(mps->R.data, mcs->mc->aggr_R.data, PK_BYTES);

    /* Update the state after each signature */
    mcs->mc->state++;

    return 1;
}

/**** Aggregator ****/
int musig2_aggregate_partial_sig(secp256k1_context *ctx, musig2_context *mca, musig2_partial_signatures *mps, secp256k1_pubkey *pk_list, unsigned char *signature, int nr_signers) {

    int i;
    int par_pk = 0;  // Parity of aggregated pk
    int par_R = 0;  // Parity of R
    unsigned char aggr_sig[SCALAR_BYTES]; // Aggregated signature
    unsigned char ser_R[SCALAR_BYTES];   // Serialized R
    secp256k1_xonly_pubkey xonly_pk; // x_only pk
    secp256k1_xonly_pubkey xonly_R; // x_only R

    mca->ctx = ctx;
    for (i = 0; i < nr_signers; i++) {
        if (mps[i].sig[0] == '\0'){
            return -2 ;
        }
    }

    /* Aggregate the given list of public keys */
    musig2_aggregate_pubkey(mca, pk_list, nr_signers);

    /* Check whether all aggregated R is same */
    for (i = 1; i < nr_signers; i++) {
        if (secp256k1_ec_pubkey_cmp(ctx, &mps[i].R, &mps[i - 1].R) != 0){
            return -1 ;
        }
    }

    /* Set given R */
    memcpy(&mca->aggr_R, mps[0].R.data, PK_BYTES);

    /* Get x_only pk and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mca->ctx, &xonly_pk, &par_pk, &mca->aggr_pk));

    /* Get x_only R and its parity */
    assert(secp256k1_xonly_pubkey_from_pubkey(mca->ctx, &xonly_R, &par_R, &mca->aggr_R));

    /* Serialize R to store in signature */
    secp256k1_xonly_pubkey_serialize(mca->ctx, ser_R, &xonly_R);

    /* Aggregate the partial signatures */
    memcpy(aggr_sig, mps[0].sig, SCALAR_BYTES);
    for (i = 1; i < nr_signers; i++) {
        if (!secp256k1_ec_seckey_tweak_add(mca->ctx, aggr_sig, mps[i].sig)){
            printf("Failed to aggregate signatures. \n");
            return 0;
        }
    }

    /* Negate the aggregated signature if both par_pk and par_R are 1 */
    if (par_pk == 1 && par_R == 1)
        if (!secp256k1_ec_seckey_negate(mca->ctx, aggr_sig)){
            printf("Failed to negate signature. \n");
            return 0;
        }

    /* Set the signature of type schnorr signature */
    memcpy(signature, ser_R, SCALAR_BYTES);
    memcpy(&signature[SCALAR_BYTES], aggr_sig, SCALAR_BYTES);

    return 1;
}

/**** Verifier ****/
int musig2_ver_musig(secp256k1_context *ctx, const unsigned char *signature, secp256k1_pubkey aggr_pk, const unsigned char *msg, int msg_len) {

    secp256k1_xonly_pubkey xonly_pk;

    /* Get the xonly public key */
    assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pk, NULL, &aggr_pk));

    /* Verify musig2 with secp256k1_schnorrsig_verify */
    return secp256k1_schnorrsig_verify(ctx, signature, msg, msg_len, &xonly_pk);
}
