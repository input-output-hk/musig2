#include "libmusig2.h"
#include "stdio.h"

#include <sodium.h>
#include <string.h>
#include <assert.h>

int main(int argc, char **argv) {
    // Number of signers
    const int NR_SIGNERS = 2;
    // Message
    #define MESSAGE (const unsigned char *) "test"
    #define MESSAGE_LEN 4

    // We first generate the key pair of the participants
    unsigned char sk_1[crypto_core_ristretto255_SCALARBYTES];
    unsigned char pk_1[crypto_core_ristretto255_BYTES];

    keypair_gen(sk_1, pk_1);

    unsigned char sk_2[crypto_core_ristretto255_SCALARBYTES];
    unsigned char pk_2[crypto_core_ristretto255_BYTES];

    keypair_gen(sk_2, pk_2);

    unsigned char *pks_list[NR_SIGNERS * crypto_core_ristretto255_BYTES] = {pk_1, pk_2};

    // Now each party generates their randomness---note that here signers do not
    // need to know the pks of other participants nor the message.
    unsigned char rand_comm_1[NR_V * crypto_core_ristretto255_BYTES];
    unsigned char rand_nonc_1[NR_V * crypto_core_ristretto255_SCALARBYTES];
    commit(rand_comm_1, rand_nonc_1);

    unsigned char rand_comm_2[NR_V * crypto_core_ristretto255_BYTES];
    unsigned char rand_nonc_2[NR_V * crypto_core_ristretto255_SCALARBYTES];
    commit(rand_comm_2, rand_nonc_2);

    unsigned char *comm_list[NR_V * crypto_core_ristretto255_BYTES] = {rand_comm_1, rand_comm_2};

    // Now party one generates its partial signature
    unsigned char part_sig_1[crypto_core_ristretto255_SCALARBYTES];
    unsigned char aggr_announcement_1[crypto_core_ristretto255_BYTES];
    partial_signature(part_sig_1,
                      aggr_announcement_1,
                      pks_list,
                      comm_list,
                      MESSAGE,
                      MESSAGE_LEN,
                      NR_SIGNERS,
                      0,
                      rand_nonc_1,
                      sk_1);

    // Now party two generates its partial signature
    unsigned char part_sig_2[crypto_core_ristretto255_SCALARBYTES];
    unsigned char aggr_announcement_2[crypto_core_ristretto255_BYTES];
    partial_signature(part_sig_2,
                      aggr_announcement_2,
                      pks_list,
                      comm_list,
                      MESSAGE,
                      MESSAGE_LEN,
                      NR_SIGNERS,
                      1,
                      rand_nonc_2,
                      sk_2);

    // The two aggr_announcement should be the same for both signers
    for (int i = 0; i < crypto_core_ristretto255_BYTES; i++) {
        assert(aggr_announcement_1[i] == aggr_announcement_2[i]);
    }

    unsigned char *part_sigs[] = {part_sig_1, part_sig_2};

    // now we aggregate the different signatures
    unsigned char aggr_response[crypto_core_ristretto255_SCALARBYTES];
    aggr_partial_sigs(aggr_response, part_sigs, NR_SIGNERS);

    // VERIFICATION //

    // First, we need to compute the aggregate public key. This can be performed by the
    // verifier, or directly by the signature aggregator.
    unsigned char aggr_pks[crypto_core_ristretto255_BYTES];
    aggregate_pks(aggr_pks, pks_list, NR_SIGNERS);

    printf("Verification: ");
    // now we check the signature!
    if (verify_signature(aggr_announcement_2, aggr_pks, aggr_response, MESSAGE, MESSAGE_LEN) == 0) {
        printf("Success!\n");
    } else {
        printf("Failure!\n");
    }
}