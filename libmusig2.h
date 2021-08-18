#ifndef MUSIG2_LIBRARY_H
#define MUSIG2_LIBRARY_H

/// Number of nonces. This will be constant once we choose to go either with the
/// algebraic group model and random oracle model (=2), or only with the latter (>4).
#define NR_V (const int) 2

int keypair_gen(unsigned char *sk, unsigned char *pk);

int commit(unsigned char *commitment, unsigned char *randomness);

int batch_commit(unsigned char *commitment, unsigned char *randomness, unsigned long batch_size);

void compute_exponent(unsigned char *exponent, const unsigned char *pks, unsigned long position, unsigned long number_keys);

int aggregate_pks(unsigned char *aggr_pk, const unsigned char *pks, unsigned long number_signers);

int partial_signature(unsigned char *sig,
                      unsigned char *aggr_announcement,
                      const unsigned char *aggr_pk,
                      const unsigned char *sk,
                      const unsigned char *secret_nonce,
                      const unsigned char *committed_nonces,
                      const unsigned char *own_exponent,
                      const unsigned char *m,
                      unsigned long long mlen,
                      unsigned long nr_signers);

int verify_signature(
        const unsigned char *announcement,
        const unsigned char *aggr_pks,
        const unsigned char *aggr_sig,
        const unsigned char *message,
        unsigned long long message_len
);

int aggr_partial_sigs(
        unsigned char *response,
        const unsigned char *partial_sigs,
        unsigned long nr_signers
);

int compute_response(
        unsigned char *response,
        const unsigned char *challenge,
        const unsigned char *own_exponent,
        const unsigned char *sk,
        const unsigned char *exponents,
        const unsigned char *secret_nonces
);

int compute_announcement(unsigned char *announcement,
                         unsigned char *exponents,
                         const unsigned char *aggr_pk,
                         const unsigned char *grouped_commitments,
                         const unsigned char *message,
                         unsigned long long message_len);

int compute_challenge(unsigned char *challenge,
                      const unsigned char *aggr_pks,
                      const unsigned char *announcement,
                      const unsigned char *m,
                      unsigned long long mlen);

#endif //MUSIG2_LIBRARY_H
