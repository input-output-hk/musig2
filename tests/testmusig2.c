#include <gtest/gtest.h>
extern "C" {
#include "../src/libmusig2.h"
#include "config.h"

MUSIG2_ERROR musig2_helper_setup(musig2_context_signer *mcs_list, unsigned char *serialized_pubkey_list, unsigned char *serialized_batch_list, int nr_participants) {
    int i, j, k, l;
    MUSIG2_ERROR err;

    /**** Initialization ****/
    for (i = 0; i < nr_participants; i++) {

        err = musig2_init_signer(&mcs_list[i],  NR_MESSAGES);
        if (err != MUSIG2_OK)
            return err;
        }

        /* *** Registration ****/
        for (i = 0; i < nr_participants; i++) {
            unsigned char serialized_comm_list[V * NR_MESSAGES][MUSIG2_PUBKEY_BYTES_COMPRESSED];
            unsigned char serialized_pubkey[MUSIG2_PUBKEY_BYTES_COMPRESSED];

            musig2_serialise_shareable_context(&mcs_list[i], serialized_pubkey, serialized_comm_list);

            memcpy(&serialized_pubkey_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_pubkey, MUSIG2_PUBKEY_BYTES_COMPRESSED);
            l = 0; // the index of the signer's commitment list.
            for (k = 0; k < NR_MESSAGES; k++)
                for (j = 0; j < V; j++, l++)
                    memcpy(&serialized_batch_list[(k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_comm_list[l],
                    MUSIG2_PUBKEY_BYTES_COMPRESSED);
    }
    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_helper_precomputation(unsigned char *serialized_pubkey_list, unsigned char *serialized_batch_list, musig2_context_signer *mcs_list, int nr_participants) {
    /**** Aggregate the public keys and batch commitments for each signer ****/
    int i;
    MUSIG2_ERROR err;
    for (i = 0; i < nr_participants; i++){
        err = musig2_signer_precomputation(&mcs_list[i].mc, serialized_pubkey_list, serialized_batch_list, nr_participants);
        if (err != MUSIG2_OK)
            return err;
    }
    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_helper_sign(musig2_context_signer *mcs_list, musig2_context_signature *mps, int nr_participants) {
    int i;
    MUSIG2_ERROR err;
    for (i = 0; i < nr_participants; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], &mps[i], MSG_1, MSG_1_LEN);
        if (err != MUSIG2_OK) {
            return err;
        }
    }
    return MUSIG2_OK;
}

MUSIG2_ERROR musig2_helper_verify(unsigned char *serialized_pubkey_list, unsigned char *signature, const unsigned char *msg, int msg_len, int nr_participants){
    MUSIG2_ERROR err;
    musig2_aggr_pubkey aggr_pubkey;
    err = musig2_prepare_verifier(&aggr_pubkey, serialized_pubkey_list, nr_participants);
    if (err != MUSIG2_OK){
        return err;
    }
    err = musig2_verify(&aggr_pubkey, signature, msg, msg_len);
    if (err != MUSIG2_OK) {
        return err;
    }
    return MUSIG2_OK;
}

#include "functiontest.c"
#include "failtest.c"
#include "serdetest.c"
}

int main(int argc, char* argv[]){
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
