#include <gtest/gtest.h>
extern "C" {
#include "../src/libmusig2.h"
#include "config.h"

int init_musig2(unsigned char *serialized_pk_list, unsigned char *serialized_batch_list, musig2_context_sig *mcs_list, int nr_participants) {
    int i, j, k, l;
    int err;

    /**** Initialization ****/
    for (i = 0; i < nr_participants; i++) {
        unsigned char serialized_comm_list[V * NR_MESSAGES][MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serialized_pk[MUSIG2_PUBKEY_BYTES_COMPRESSED];

        /* Generate a keypair for the signer and get batch commitments. */
        err = musig2_init_signer(&mcs_list[i], serialized_pk, serialized_comm_list, NR_MESSAGES);
        if (err != 1)
            return err;

        memcpy(&serialized_pk_list[i * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_pk, MUSIG2_PUBKEY_BYTES_COMPRESSED);
        l = 0; // the index of the signer's commitment list.
        for (k = 0; k < NR_MESSAGES; k++)
            for (j = 0; j < V; j++, l++)
                memcpy(&serialized_batch_list[(k * NR_SIGNERS * V + i * V + j) * MUSIG2_PUBKEY_BYTES_COMPRESSED], serialized_comm_list[l],
                       MUSIG2_PUBKEY_BYTES_COMPRESSED);
    }
    return 1;
}

int aggregate_pk_batch(unsigned char *serialized_pk_list, unsigned char *serialized_batch_list, musig2_context_sig *mcs_list) {
    /**** Aggregate the public keys and batch commitments for each signer ****/
    int i;
    int cnt = 0;
    for (i = 0; i < NR_SIGNERS; i++)
        cnt += musig2_signer_precomputation(&mcs_list[i].mc, serialized_pk_list, serialized_batch_list, NR_SIGNERS, NR_MESSAGES);
    if (cnt != NR_SIGNERS) {
        return cnt;
    }
    return 1;
}

int sign_partial(musig2_context_sig *mcs_list, musig2_partial_signature *mps, int nr_participants) {
    int i, err;
    for (i = 0; i < nr_participants; i++) {
        /* Generate the partial signatures */
        err = musig2_sign(&mcs_list[i], &mps[i], MSG_1, MSG_1_LEN);
        if (err != 1) {
            return err;
        }
    }
    return 1;
}

int musig2_ver_musig(secp256k1_context *ctx, const unsigned char *signature, secp256k1_pubkey aggr_pk , const unsigned char *msg, int msg_len ){
    secp256k1_xonly_pubkey xonly_aggr_pk;
    assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_aggr_pk, NULL, &aggr_pk)) ;

    return secp256k1_schnorrsig_verify(ctx, signature, msg, msg_len, & xonly_aggr_pk ) ;
}

#include "functiontest.c"
#include "serdetest.c"
}

int main(int argc, char* argv[]){
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


