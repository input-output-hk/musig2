#include "libmusig2.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Generate key-pair.
int keypair_gen(unsigned char *sk, unsigned char *pk) {

    crypto_core_ristretto255_scalar_random(sk);
    return crypto_scalarmult_ristretto255_base(pk, sk);
}

// Function that generates randomness for a single message. Note that we are generating
// two points, meaning that for now we are working in the AGM.
// todo: check if the way of handling arrays is best practice.
int commit(unsigned char *commitment, unsigned char *randomness) {

   // creating two NR_V nonces
    crypto_core_ristretto255_scalar_random(randomness);
    crypto_core_ristretto255_scalar_random(randomness + crypto_core_ristretto255_SCALARBYTES);

    if (crypto_scalarmult_ristretto255_base(commitment, randomness) != 0) {
        return crypto_scalarmult_ristretto255_base(commitment, randomness);
    }

    return crypto_scalarmult_ristretto255_base(
            commitment + crypto_core_ristretto255_BYTES,
            randomness + crypto_core_ristretto255_SCALARBYTES);
}

// Given a set of public keys, computes the aggr_pk and the exponent corresponding
// to position `owns_position`.
// todo: best to specify the size of each input?
int aggregate_pks_with_exp(unsigned char *aggr_pk,
                           unsigned char *pks[],
                           unsigned char *own_exponent,
                           const int owns_position,
                           int number_signers)
{
    // We create the multiset of keys to include it in the hash
    unsigned char pk_multiset[number_signers * crypto_core_ristretto255_BYTES];
    for (int i = 0; i < number_signers; i++) {
        memmove(pk_multiset + (i * crypto_core_ristretto255_BYTES), pks[i], crypto_core_ristretto255_BYTES);
    }

    for (int j = 0; j < number_signers; j++) {
        // we use MAX (64) instead of normal (32) to get almost uniformity.
        unsigned char hash[crypto_generichash_BYTES_MAX];
        unsigned char temp_point[crypto_core_ristretto255_BYTES];
        unsigned char jth_exp[crypto_core_ristretto255_SCALARBYTES];

        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, sizeof hash);
        crypto_generichash_update(&state, pk_multiset, number_signers * crypto_core_ristretto255_BYTES);
        crypto_generichash_update(&state, pks[j], crypto_core_ristretto255_BYTES);

        crypto_generichash_final(&state, hash, sizeof hash);

        crypto_core_ristretto255_scalar_reduce(jth_exp, hash);
        if (crypto_scalarmult_ristretto255(temp_point, jth_exp, pks[j]) != 0){
            printf("pk at position %d is the identity point", j);
        }

        if (j == owns_position) {
            memmove(own_exponent, jth_exp, crypto_core_ristretto255_SCALARBYTES);
        }

        // todo: ensure this "add-assign" works properly.
        crypto_core_ristretto255_add(aggr_pk, aggr_pk, temp_point);
    }

    return 0;
}

// Given a set of public keys, return the corresponding aggregate.
int aggregate_pks(unsigned char *aggr_pk, unsigned char *pks[], int number_signers) {
    return aggregate_pks_with_exp(aggr_pk, pks, NULL, -1, number_signers);
}

// Given as input a Ed25519 secret key, return the partial
// signature corresponding to the given message.
int partial_signature(unsigned char *sig,
                      unsigned char *aggr_announcement,
                      unsigned char *pks[],
                      unsigned char *committed_nonces[],
                      const unsigned char *m,
                      unsigned long long mlen,
                      unsigned long long nr_signers,
                      unsigned long long owns_position,
                      const unsigned char *secret_nonces,
                      const unsigned char *sk) {
    // First, we aggregate the public keys, and store the signers own exponent
    unsigned char own_exponent[crypto_core_ristretto255_SCALARBYTES];
    unsigned char aggr_pks[crypto_core_ristretto255_BYTES] = {0};
    aggregate_pks_with_exp(aggr_pks, pks, own_exponent, owns_position, nr_signers);

    // Now we combine the committed_nonces from all participants, by adding all of them.
    unsigned char aggr_comms[NR_V * crypto_core_ristretto255_BYTES];
    for (int j = 0; j < NR_V; j++) {
        unsigned char zero[crypto_core_ristretto255_BYTES] = {0};
        memmove(aggr_comms + (j * crypto_core_ristretto255_BYTES), zero, crypto_core_ristretto255_BYTES);

        for (int i = 0; i < nr_signers; i++){
            crypto_core_ristretto255_add(
                    aggr_comms + (j * crypto_core_ristretto255_BYTES),
                    aggr_comms + (j * crypto_core_ristretto255_BYTES),
                    committed_nonces[i] + j * crypto_core_ristretto255_BYTES
            );
        }
    }

    // And now, we compute the announcement. We have to store the exponents,
    // so we keep them around.
    unsigned char exponents[NR_V * crypto_core_ristretto255_SCALARBYTES] = {0};
    compute_announcement(
            aggr_announcement,
            exponents,
            aggr_pks,
            aggr_comms,
            m,
            mlen
            );

    // Challenge computation
    unsigned char challenge[crypto_core_ristretto255_SCALARBYTES];
    compute_challenge(
            challenge,
            aggr_pks,
            aggr_announcement,
            m,
            mlen);

    // Response computation
    compute_response(
            sig,
            challenge,
            own_exponent,
            sk,
            exponents,
            secret_nonces);

    return 0;
}

int verify_signature(
        unsigned char *announcement,
        unsigned char *aggr_pks,
        unsigned char *aggr_sig,
        const unsigned char *message,
        unsigned long long message_len
        ) {
    unsigned char lhs[crypto_core_ristretto255_BYTES];
    unsigned char rhs[crypto_core_ristretto255_BYTES];

    // we compute the challenge
    unsigned char challenge[crypto_core_ristretto255_SCALARBYTES];
    compute_challenge(challenge, aggr_pks, announcement, message, message_len);

    crypto_scalarmult_ristretto255_base(lhs, aggr_sig);
    if (crypto_scalarmult_ristretto255(rhs, challenge, aggr_pks) != 0) {
        printf("aggr_pk is the identity point. Should not be");
    }
    crypto_core_ristretto255_add(rhs, rhs, announcement);

    for (int i = 1; i < crypto_core_ristretto255_BYTES; i++) {
        if (rhs[i] != lhs[i]) {
            return 0;
        }
    }
    return 0;
}

int aggr_partial_sigs(
        unsigned char *response,
        unsigned char *partial_sigs[],
        unsigned long long nr_signers
        ) {
    response[0] = 0;
    for (int i = 0; i < nr_signers; i++) {
        crypto_core_ristretto255_scalar_add(response, response, partial_sigs[i]);
    }

    return 0;
}

int compute_response(
        unsigned char *response,
        unsigned char *challenge,
        unsigned char *own_exponent,
        const unsigned char *sk,
        unsigned char *exponents,
        const unsigned char *secret_nonces
        ) {
    crypto_core_ristretto255_scalar_mul(response, challenge, own_exponent);
    crypto_core_ristretto255_scalar_mul(response, response, sk);

    unsigned char temp_scalar[crypto_core_ristretto255_SCALARBYTES];
    for (int i = 0; i < NR_V; i++) {
        crypto_core_ristretto255_scalar_mul(
                temp_scalar,
                secret_nonces + (i * crypto_core_ristretto255_SCALARBYTES),
                exponents + (i * crypto_core_ristretto255_SCALARBYTES));
        crypto_core_ristretto255_scalar_add(response, response, temp_scalar);
    }



    return 0;
}

int compute_challenge(unsigned char *challenge,
                      unsigned char *aggr_pks,
                      unsigned char *announcement,
                      const unsigned char *m,
                      unsigned long long mlen
        ) {
    // we use MAX (64) instead of normal (32) to get almost uniformity.
    unsigned char hash[crypto_generichash_BYTES_MAX];

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof hash);
    crypto_generichash_update(&state, aggr_pks, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, announcement, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, m, mlen);

    crypto_generichash_final(&state, hash, sizeof hash);

    crypto_core_ristretto255_scalar_reduce(challenge, hash);
    return 0;
}

int compute_announcement(unsigned char *announcement,
                                 unsigned char *exponents,
                                 unsigned char *aggr_pk,
                                 unsigned char *grouped_commitments,
                                 const unsigned char *message,
                                 unsigned long long message_len) {
    // We initilise the announcemet as R[0], given that the first exponent is 1.
    exponents[0] = 1;
    memmove(announcement, grouped_commitments, crypto_core_ristretto255_BYTES);

    // Now we compute each exponent, and add to `announcement` the power of the corresponding
    // randomness commitment.
    for (int i = 1; i < NR_V; i++) {
        // we use MAX (64) instead of normal (32) to get almost uniformity.
        unsigned char hash[crypto_generichash_BYTES_MAX];
        unsigned char temp_point[crypto_core_ristretto255_BYTES];
        unsigned char index = (unsigned char)i;

        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, sizeof hash);
        crypto_generichash_update(&state, &index, sizeof(int));
        crypto_generichash_update(&state, aggr_pk, crypto_core_ristretto255_BYTES);
        crypto_generichash_update(&state, grouped_commitments, NR_V * crypto_core_ristretto255_BYTES);
        crypto_generichash_update(&state, message, message_len);

        crypto_generichash_final(&state, hash, sizeof hash);

        crypto_core_ristretto255_scalar_reduce(exponents + (i * crypto_core_ristretto255_SCALARBYTES), hash);

        if (crypto_scalarmult_ristretto255(temp_point, exponents + (i * crypto_core_ristretto255_SCALARBYTES), grouped_commitments + (i * crypto_core_ristretto255_BYTES)) != 0){
            printf("Commitment at position %d is the identity point", i);
        }

        // todo: ensure this "add-assign" works properly.
        crypto_core_ristretto255_add(announcement, announcement, temp_point);
    }
    return 0;
}
