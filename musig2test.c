#include "libmusig2.h"
#include "stdio.h"

#include <sodium.h>
#include <string.h>
#include <assert.h>

int main(int argc, char **argv) {
    // Number of signers
    const int NR_SIGNERS = 4;

    // We provide an example with two messages, where parties precompute the nonces.
    // In the precomputation scenario, it is very important
    // that they keep state of what are the rand_nonces that they have used, otherwise
    // their keys will be vulnerable.
    const int NR_MESSAGES = 2;
    int STATE = 0;
    #define MESSAGE (const unsigned char *) "test"
    #define MESSAGE_LEN 4

    #define MESSAGE_2 (const unsigned char *) "testcallrustsign"
    #define MESSAGE_2_LEN 16

    // Parties generate their key-pairs
    unsigned char pks[NR_SIGNERS * crypto_core_ristretto255_BYTES];
    unsigned char sks[NR_SIGNERS * crypto_core_ristretto255_SCALARBYTES];

    for (int i = 0; i < NR_SIGNERS; i++) {
        keypair_gen(sks + i * crypto_core_ristretto255_SCALARBYTES, pks + i * crypto_core_ristretto255_BYTES);
    }

    // Now each party generates their batched randomness---note that here signers do not
    // need to know the pks of other participants nor the message. Once they precompute all
    // randomness, they send it over the broadcast channel.
    unsigned char rand_comm[NR_MESSAGES * NR_SIGNERS * NR_V * crypto_core_ristretto255_BYTES];
    unsigned char rand_nonc[NR_MESSAGES * NR_SIGNERS * NR_V * crypto_core_ristretto255_SCALARBYTES];

    for (int i = 0; i < NR_SIGNERS; i++) {
        batch_commit(rand_comm + i * NR_MESSAGES * NR_V * crypto_core_ristretto255_BYTES,
               rand_nonc + i * NR_MESSAGES * NR_V * crypto_core_ristretto255_SCALARBYTES,
               NR_MESSAGES);
    }

    // Now parties generate their partial signature for message 1. They broadcast their
    // partial signature to the other participants. Alternatively, this can be sent
    // to a single aggregator, or to the verifier.
    unsigned char part_sigs[NR_SIGNERS * crypto_core_ristretto255_SCALARBYTES];
    unsigned char aggr_announcement[crypto_core_ristretto255_BYTES];

    for (int i = 0; i < NR_SIGNERS; i++) {
        partial_signature(part_sigs + i * crypto_core_ristretto255_SCALARBYTES,
                          aggr_announcement,
                          pks,
                          rand_comm + STATE * NR_SIGNERS * NR_V * crypto_core_ristretto255_BYTES,
                          MESSAGE,
                          MESSAGE_LEN,
                          NR_SIGNERS,
                          i,
                          rand_nonc + STATE * NR_SIGNERS * NR_V * crypto_core_ristretto255_SCALARBYTES + i * NR_V * crypto_core_ristretto255_SCALARBYTES,
                          sks + i * crypto_core_ristretto255_SCALARBYTES);
    }

    // At each signature, the state needs to be updated
    STATE = 1;

    // And finally, the different parties (or the aggregator) aggregate the different signatures
    unsigned char aggr_sig[crypto_core_ristretto255_SCALARBYTES] = {0};
    aggr_partial_sigs(aggr_sig, part_sigs, NR_SIGNERS);

    // VERIFICATION //

    // First, we need to compute the aggregate public key. This can be performed by the
    // verifier, or directly by the signature aggregator.
    unsigned char aggr_pks[crypto_core_ristretto255_BYTES] = {0};
    aggregate_pks(aggr_pks, pks, NR_SIGNERS);

    printf("First verification: ");
    // now we check the signature!
    if (verify_signature(aggr_announcement, aggr_pks, aggr_sig, MESSAGE, MESSAGE_LEN) == 0) {
        printf("Success!\n");
    } else {
        printf("Failure!\n");
    }

    // Second message //
    // Now that we have precomputed the nonces, we can directly compute the signature
    unsigned char part_sigs_2[NR_SIGNERS * crypto_core_ristretto255_SCALARBYTES];
    unsigned char aggr_announcement_2[crypto_core_ristretto255_BYTES];

    for (int i = 0; i < NR_SIGNERS; i++) {
        partial_signature(part_sigs_2 + i * crypto_core_ristretto255_SCALARBYTES,
                          aggr_announcement_2,
                          pks,
                          rand_comm + STATE * NR_V * crypto_core_ristretto255_BYTES,
                          MESSAGE_2,
                          MESSAGE_2_LEN,
                          NR_SIGNERS,
                          i,
                          rand_nonc + STATE * NR_V * crypto_core_ristretto255_SCALARBYTES + i * NR_V * crypto_core_ristretto255_SCALARBYTES,
                          sks + i * crypto_core_ristretto255_SCALARBYTES);
    }

    // And finally, we aggregate the different signatures
    unsigned char aggr_sig_2[crypto_core_ristretto255_SCALARBYTES] = {0};
    aggr_partial_sigs(aggr_sig_2, part_sigs_2, NR_SIGNERS);

    // VERIFICATION //


    printf("Second verification: ");
    // now we check the signature! We use the same aggregate public key as before.
    if (verify_signature(aggr_announcement_2, aggr_pks, aggr_sig_2, MESSAGE_2, MESSAGE_2_LEN) == 0) {
        printf("Success!\n");
    } else {
        printf("Failure!\n");
    }
}