#ifndef MUSIG2_LIBRARY_H
#define MUSIG2_LIBRARY_H

/// Number of nonces. This will be constant once we choose to go either with the
/// algebraic group model and random oracle model (=2), or only with the latter (>4).
#define NR_V (const int) 2

int keypair_gen(unsigned char *sk, unsigned char *pk);

int commit(unsigned char *commitment, unsigned char *randomness);
int batch_commit(unsigned char *commitment, unsigned char *randomness, unsigned long long batch_size);

int partial_signature(unsigned char *sig,
                      unsigned char *aggr_announcement,
                      unsigned char *pks,
                      unsigned char *committed_nonces,
                      const unsigned char *m,
                      unsigned long long mlen,
                      unsigned long long nr_signers,
                      unsigned long long owns_position,
                      const unsigned char *secret_nonces,
                      const unsigned char *sk);

int verify_signature(
        unsigned char *announcement,
        unsigned char *aggr_pks,
        unsigned char *aggr_sig,
        const unsigned char *message,
        unsigned long long message_len
);

int aggr_partial_sigs(
        unsigned char *response,
        unsigned char *partial_sigs,
        unsigned long long nr_signers
);

int compute_response(
        unsigned char *response,
        unsigned char *challenge,
        unsigned char *own_exponent,
        const unsigned char *sk,
        unsigned char *exponents,
        const unsigned char *secret_nonces
);

int compute_announcement(unsigned char *announcement,
                         unsigned char *exponents,
                                 unsigned char *aggr_pk,
                                 unsigned char *grouped_commitments,
                                 const unsigned char *message,
                                 unsigned long long message_len);

int compute_challenge(unsigned char *challenge,
                      unsigned char *aggr_pks,
                      unsigned char *announcement,
                      const unsigned char *m,
                      unsigned long long mlen);

int aggregate_pks(unsigned char *aggr_pk, unsigned char *pks, int number_signers);

int aggregate_pks_with_exp(unsigned char *aggr_pk, unsigned char *pks, unsigned char *own_exponent,
                  const int owns_position, int number_signers);


#endif //MUSIG2_LIBRARY_H
