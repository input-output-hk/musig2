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
    return batch_commit(commitment, randomness, 1);
}

int batch_commit(unsigned char *commitment, unsigned char *randomness, unsigned long long batch_size) {
    for (int j = 0; j < batch_size; j ++){
        for (int i = 0; i < NR_V; i++) {
            crypto_core_ristretto255_scalar_random(randomness + j * NR_V * crypto_core_ristretto255_SCALARBYTES + i * crypto_core_ristretto255_SCALARBYTES);

            crypto_scalarmult_ristretto255_base(
                    commitment + j * NR_V * crypto_core_ristretto255_SCALARBYTES + i * crypto_core_ristretto255_BYTES,
                    randomness + j * NR_V * crypto_core_ristretto255_SCALARBYTES + i * crypto_core_ristretto255_SCALARBYTES);
        }
    }
    return 0;
}

// Given a set of public keys, computes the aggr_pk and the exponent corresponding
// to position `owns_position`.
// todo: best to specify the size of each input?
int aggregate_pks_with_exp(unsigned char *aggr_pk,
                           unsigned char *pks,
                           unsigned char *own_exponent,
                           const int owns_position,
                           int number_signers)
{
    memset(aggr_pk, 0, crypto_core_ristretto255_BYTES);
    for (int j = 0; j < number_signers; j++) {
        // we use MAX (64) instead of normal (32) to get almost uniformity.
        unsigned char hash[crypto_generichash_BYTES_MAX];
        unsigned char temp_point[crypto_core_ristretto255_BYTES];
        unsigned char jth_exp[crypto_core_ristretto255_SCALARBYTES];

        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, sizeof hash);
        crypto_generichash_update(&state, pks, number_signers * crypto_core_ristretto255_BYTES);
        crypto_generichash_update(&state, pks + j * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);

        crypto_generichash_final(&state, hash, sizeof hash);

        crypto_core_ristretto255_scalar_reduce(jth_exp, hash);
        if (crypto_scalarmult_ristretto255(temp_point, jth_exp, pks + j * crypto_core_ristretto255_BYTES) != 0){
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
int aggregate_pks(unsigned char *aggr_pk, unsigned char *pks, int number_signers) {
    return aggregate_pks_with_exp(aggr_pk, pks, NULL, -1, number_signers);
}

// Given as input a Ed25519 secret key, return the partial
// signature corresponding to the given message.
int partial_signature(unsigned char *sig,
                      unsigned char *aggr_announcement,
                      unsigned char *pks,
                      unsigned char *committed_nonces,
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
    unsigned char aggr_comms[NR_V * crypto_core_ristretto255_BYTES] = {0};
    for (int j = 0; j < NR_V; j++) {
        for (int i = 0; i < nr_signers; i++) {
            crypto_core_ristretto255_add(
                    aggr_comms + (j * crypto_core_ristretto255_BYTES),
                    aggr_comms + (j * crypto_core_ristretto255_BYTES),
                    committed_nonces + i * NR_V * crypto_core_ristretto255_BYTES + j * crypto_core_ristretto255_BYTES
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
            return -1;
        }
    }
    return 0;
}

int aggr_partial_sigs(
        unsigned char *aggr_sig,
        unsigned char *partial_sigs,
        unsigned long long nr_signers
        ) {
    memset(aggr_sig, 0, crypto_core_ristretto255_SCALARBYTES);
    for (int i = 0; i < nr_signers; i++) {
        crypto_core_ristretto255_scalar_add(aggr_sig, aggr_sig, partial_sigs + i * crypto_core_ristretto255_SCALARBYTES);
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
    unsigned char hash[64];
    // before hashing we need to change the encoding of the points, to make
    // sure that the verifier gets the same challenge
    unsigned char pk_ed25519[crypto_core_ed25519_BYTES];
    unsigned char announcement_ed25519[crypto_core_ed25519_BYTES];

    if (prepare_sig_and_pk(pk_ed25519, announcement_ed25519, aggr_pks, announcement) == -1) {
        printf("conversion went wrong");
    }

    // Now we need to get the torsion-free representative of the ristretto points in edwards form, to ensure
    // that the verification equation will validate.
    mul_torsion_safe_scalar(pk_ed25519, pk_ed25519);
    mul_torsion_safe_scalar(announcement_ed25519, announcement_ed25519);

    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, announcement_ed25519, 32);
    crypto_hash_sha512_update(&state, pk_ed25519, 32);
    crypto_hash_sha512_update(&state, m, mlen);

    crypto_hash_sha512_final(&state, hash);

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
