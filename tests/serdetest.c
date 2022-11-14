#include <gtest/gtest.h>
extern "C" {

    TEST (musig2, pk_list_serialize_deserialize) {

        int i, err;
        size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED; // Size of the compressed ec pubkey of secp256k1.

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
        unsigned char serialized_pk_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
        unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serde_pk_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list

        secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
        secp256k1_pubkey deser_pk_list[NR_SIGNERS];

        err = init_musig2(ctx, serialized_pk_list, serialized_batch_list, mcs_list, NR_SIGNERS);
        ASSERT_EQ(err, MUSIG2_OK);

        for (i = 0; i < NR_SIGNERS; i++)
            ASSERT_EQ(secp256k1_ec_pubkey_parse(ctx, &deser_pk_list[i], &serialized_pk_list[i * ser_size], ser_size), 1);

        for (i = 0; i < NR_SIGNERS; i++)
            secp256k1_ec_pubkey_serialize(ctx, &serde_pk_list[i * ser_size], &ser_size, &deser_pk_list[i], SECP256K1_EC_COMPRESSED);

        for (i = 0; i < NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED; i++)
            ASSERT_EQ(serde_pk_list[i], serialized_pk_list[i]);

    }

    TEST (musig2, commitments_serialize_deserialize) {

        int i, err;
        size_t ser_size = MUSIG2_PUBKEY_BYTES_COMPRESSED; // Size of the compressed ec pubkey of secp256k1.

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        musig2_context_sig mcs_list[NR_SIGNERS]; // Array that holds NR_SIGNERS musig2_context_sig
        unsigned char serialized_pk_list[NR_SIGNERS * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list
        unsigned char serialized_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];
        unsigned char serde_batch_list[NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED];    // Signers' public key list

        secp256k1_pubkey batch_list[NR_SIGNERS * V * NR_MESSAGES];   // Stores the batches of signers
        secp256k1_pubkey deser_batch_list[NR_SIGNERS * V * NR_MESSAGES];

        err = init_musig2(ctx, serialized_pk_list, serialized_batch_list, mcs_list, NR_SIGNERS);
        ASSERT_EQ(err, MUSIG2_OK);

        for (i = 0; i < NR_SIGNERS * V * NR_MESSAGES; i++)
            ASSERT_EQ(secp256k1_ec_pubkey_parse(ctx, &deser_batch_list[i], &serialized_batch_list[i * ser_size], ser_size), 1);

        for (i = 0; i < NR_SIGNERS * V * NR_MESSAGES; i++)
            secp256k1_ec_pubkey_serialize(ctx, &serde_batch_list[i * ser_size], &ser_size, &deser_batch_list[i], SECP256K1_EC_COMPRESSED);

        for (i = 0; i < NR_MESSAGES * NR_SIGNERS * V * MUSIG2_PUBKEY_BYTES_COMPRESSED; i++)
            ASSERT_EQ(serde_batch_list[i], serialized_batch_list[i]);

    }

}
