#include "libmusig2.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Generate key-pair.
void keypair_gen(unsigned char *sk, unsigned char *pk) {

    crypto_core_ristretto255_scalar_random(sk);
    crypto_scalarmult_ristretto255_base(pk, sk);
}

// Function that generates randomness and its corresponding commitment, for a single signature.
void commit(unsigned char *commitment, unsigned char *randomness) {
    return batch_commit(commitment, randomness, 1);
}

// Function that generates randomness and their corresponding commitments, for `batch_size` signatures.
void batch_commit(unsigned char *commitment, unsigned char *randomness, unsigned long batch_size) {
    for (int j = 0; j < batch_size; j ++){
        for (int i = 0; i < NR_V; i++) {
            crypto_core_ristretto255_scalar_random(randomness + j * NR_V * crypto_core_ristretto255_SCALARBYTES + i * crypto_core_ristretto255_SCALARBYTES);

            crypto_scalarmult_ristretto255_base(
                    commitment + j * NR_V * crypto_core_ristretto255_SCALARBYTES + i * crypto_core_ristretto255_BYTES,
                    randomness + j * NR_V * crypto_core_ristretto255_SCALARBYTES + i * crypto_core_ristretto255_SCALARBYTES);
        }
    }
}

// Given a set of public keys, this function computes the exponent corresponding to
// index `position`. This exponent is used when computing the aggregate signature.
void compute_exponent(unsigned char *exponent, const unsigned char *pks, unsigned long position, unsigned long number_keys) {
    // we use MAX (64) instead of normal (32) to get almost uniformity.
    unsigned char hash[crypto_generichash_BYTES_MAX];

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof hash);
    crypto_generichash_update(&state, pks, number_keys * crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, pks + position * crypto_core_ristretto255_BYTES, crypto_core_ristretto255_BYTES);

    crypto_generichash_final(&state, hash, sizeof hash);

    crypto_core_ristretto255_scalar_reduce(exponent, hash);
}

// Given a set of public keys, computes the aggregate key aggr_pk.
// todo: best to specify the size of each input?
int aggregate_pks(unsigned char *aggr_pk,
                           const unsigned char *pks,
                           unsigned long number_signers)
{
    memset(aggr_pk, 0, crypto_core_ristretto255_BYTES);
    for (int j = 0; j < number_signers; j++) {
        unsigned char temp_point[crypto_core_ristretto255_BYTES];
        unsigned char jth_exp[crypto_core_ristretto255_SCALARBYTES];

        if (crypto_core_ristretto255_is_valid_point(pks + j * crypto_core_ristretto255_BYTES) != 1) {
            printf("pk at position %d is not a valid ristretto point", j);
            return -1;
        }

        compute_exponent(jth_exp, pks, j, number_signers);
        if (crypto_scalarmult_ristretto255(temp_point, jth_exp, pks + j * crypto_core_ristretto255_BYTES) != 0){
            printf("pk at position %d is the identity point", j);
            return -1;
        }

        crypto_core_ristretto255_add(aggr_pk, aggr_pk, temp_point);
    }

    return 0;
}

// Given as input a MuSig2 aggregated key, a secret key, a (unused) secret nonce, the commitments of other parties
// secret nonces, the signers public exponent, and a message, return the partial signature corresponding to the given
// message.
void partial_signature(unsigned char *sig,
                      unsigned char *aggr_announcement,
                      const unsigned char *aggr_pk,
                      const unsigned char *sk,
                      const unsigned char *secret_nonce,
                      const unsigned char *committed_nonces,
                      const unsigned char *own_exponent,
                      const unsigned char *m,
                      unsigned long long mlen,
                      unsigned long nr_signers) {
    // First, we combine the committed_nonces from all participants, by adding all of them.
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
    // to use them in the response.
    unsigned char exponents[NR_V * crypto_core_ristretto255_SCALARBYTES] = {0};
    compute_announcement(
            aggr_announcement,
            exponents,
            aggr_pk,
            aggr_comms,
            m,
            mlen
            );

    // Challenge computation
    unsigned char challenge[crypto_core_ristretto255_SCALARBYTES];
    compute_challenge(
            challenge,
            aggr_pk,
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
            secret_nonce);
}

int verify_signature(
        const unsigned char *announcement,
        const unsigned char *aggr_pks,
        const unsigned char *aggr_sig,
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
        return -1;
    }
    crypto_core_ristretto255_add(rhs, rhs, announcement);

    for (int i = 1; i < crypto_core_ristretto255_BYTES; i++) {
        if (rhs[i] != lhs[i]) {
            return -1;
        }
    }
    return 0;
}

void aggr_partial_sigs(
        unsigned char *aggr_sig,
        const unsigned char *partial_sigs,
        unsigned long nr_signers
        ) {
    memset(aggr_sig, 0, crypto_core_ristretto255_SCALARBYTES);
    for (int i = 0; i < nr_signers; i++) {
        crypto_core_ristretto255_scalar_add(aggr_sig, aggr_sig, partial_sigs + i * crypto_core_ristretto255_SCALARBYTES);
    }
}

void compute_response(
        unsigned char *response,
        const unsigned char *challenge,
        const unsigned char *own_exponent,
        const unsigned char *sk,
        const unsigned char *exponents,
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
}

void compute_challenge(unsigned char *challenge,
                      const unsigned char *aggr_pks,
                      const unsigned char *announcement,
                      const unsigned char *m,
                      unsigned long long mlen
        ) {
    // we use MAX (64) instead of normal (32) to get almost uniformity.
    unsigned char hash[64];
    // before hashing we need to change the encoding of the points, to make
    // sure that the verifier gets the same challenge
    unsigned char pk_ed25519[crypto_core_ed25519_BYTES];
    unsigned char announcement_ed25519[crypto_core_ed25519_BYTES];

    // Now we need to get the torsion-free representative of the ristretto points in edwards form, to ensure
    // that the verification equation will validate (the verifier will handle torsion-free elements).

    // Now we need to get the torsion-free representative of the ristretto points in edwards form, to ensure
    // that the verification equation will validate.
    if (map_ristretto_prime_subgroup(pk_ed25519, aggr_pks) == -1 ||
            map_ristretto_prime_subgroup(announcement_ed25519, announcement) == -1) {
        printf("conversion went wrong");
    }

    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, announcement_ed25519, 32);
    crypto_hash_sha512_update(&state, pk_ed25519, 32);
    crypto_hash_sha512_update(&state, m, mlen);

    crypto_hash_sha512_final(&state, hash);

    crypto_core_ristretto255_scalar_reduce(challenge, hash);
}

void compute_announcement(unsigned char *announcement,
                                 unsigned char *exponents,
                                 const unsigned char *aggr_pk,
                                 const unsigned char *grouped_commitments,
                                 const unsigned char *message,
                                 unsigned long long message_len) {
    // The new version of MuSig2 (see changelog in their latest version of the paper) uses a single
    // pseudorandom value, to the power of each index (instead of several different pseudorandom
    // values).
    // we use MAX (64) instead of normal (32) to get almost uniformity.
    unsigned char hash[crypto_generichash_BYTES_MAX];
    unsigned char single_rand[crypto_core_ristretto255_SCALARBYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof hash);
    crypto_generichash_update(&state, aggr_pk, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, grouped_commitments, NR_V * crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, message, message_len);

    crypto_generichash_final(&state, hash, sizeof hash);
    crypto_core_ristretto255_scalar_reduce(single_rand, hash);

    // We initilise the announcemet as R[0], given that the first exponent is `single_rand` ^ 0.
    exponents[0] = 1;
    memmove(announcement, grouped_commitments, crypto_core_ristretto255_BYTES);

    // Now we compute each exponent, and add to `announcement` the power of the corresponding
    // randomness commitment.
    for (int i = 1; i < NR_V; i++) {
        crypto_core_ristretto255_scalar_mul(exponents + i * crypto_core_ristretto255_SCALARBYTES, exponents + (i - 1) * crypto_core_ristretto255_SCALARBYTES, single_rand);

        unsigned char temp_point[crypto_core_ristretto255_BYTES];
        if (crypto_scalarmult_ristretto255(temp_point, exponents + i * crypto_core_ristretto255_SCALARBYTES, grouped_commitments + (i * crypto_core_ristretto255_BYTES)) != 0){
            printf("Commitment at position %d is the identity point", i);
        }

        crypto_core_ristretto255_add(announcement, announcement, temp_point);
    }
}

// This function takes as input the partial signatures, the announcement and the message signed
// and returns an ed25519 compatible signature.
void prepare_final_signature(unsigned char *ed25519_compat_sig,
                            const unsigned char *partial_sigs, const unsigned char *announcement,
                            const unsigned char *m, unsigned long long mlen, unsigned long nr_signers) {
    unsigned char aggr_sig[crypto_core_ristretto255_SCALARBYTES], announcement_ed25519[crypto_core_ristretto255_BYTES];
    aggr_partial_sigs(aggr_sig, partial_sigs, nr_signers);


    if (map_ristretto_prime_subgroup(announcement_ed25519, announcement) == -1) {
        printf("ERROR: announcement is not a valid ristretto point");
    }

    memmove(ed25519_compat_sig, announcement_ed25519, 32);
    memmove(ed25519_compat_sig + 32, aggr_sig, 32);
    memmove(ed25519_compat_sig + 64, m, mlen);
}
