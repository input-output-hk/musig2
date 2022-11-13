#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "random.h"

#define V                                   2           // Number of nonce values
#define MUSIG2_SCALAR_BYTES                 32          // size of a scalar
#define MUSIG2_PARSIG_BYTES                 32          // size of the musig2 partial signature
#define MUSIG2_AGGR_PUBKEY_BYTES            32          // size of the musig2 public key equivalent of secp256k1_xonly_pubkey
#define MUSIG2_PUBKEY_BYTES_COMPRESSED      33          // size of compressed public key where one extra byte represents the sign.
#define MUSIG2_PUBKEY_BYTES_FULL            64          // size of uncompressed public key with full x and y coordinates
#define MUSIG2_BYTES                        64          // size of the musig2 signature including the aggregate R and aggregate signature

typedef enum musig2_error {
    MUSIG2_OK = 0,
    MUSIG2_ERR_KEY_GEN,
    MUSIG2_ERR_BATCH_COMM,
    MUSIG2_ERR_AGGR_R,
    MUSIG2_ERR_AGGR_PK,
    MUSIG2_ERR_CALC_R,
    MUSIG2_ERR_SET_PARSIG,
    MUSIG2_ERR_CHECK_COMM,
    MUSIG2_ERR_ADD_PARSIG,
    MUSIG2_ERR_CMP_R,
    MUSIG2_ERR_SER_PK,
    MUSIG2_ERR_SER_COMM,
    MUSIG2_INVALID,
} MUSIG2_ERROR;



/** MuSig2 public key as secp256k1_xonly_pubkey
 * */
typedef secp256k1_xonly_pubkey musig2_aggr_pubkey;

/** musig2_context stores the parameters of musig2.
 *  Parameters  : ctx:          a secp256k1_context object.
 *              : aggr_pubkey:  Aggregated public key.
 *              : aggr_R_list:  The list of aggregated batch commitments for all states.
 *              : L:            Concatenation of x_only public keys of signers.
 *              : pk_parity:    Parity of aggregate pubkey.
 *              : nr_signers:   The number of signers.
 *              : nr_messages:  The number of messages.
* */
typedef struct{
    secp256k1_context* ctx;
    secp256k1_pubkey aggr_pubkey;
    secp256k1_pubkey **aggr_R_list;
    unsigned char *L;
    int pk_parity;
    int nr_signers;
    int nr_messages;
}musig2_context;

/** musig2_context_signer stores the parameters of musig2 signer.
 *  Parameters  : mc:           a musig2_context object including the parameters of musig2.
 *              : comm_list:    Batch commitment list of a signer.
 *              : keypair:      Public and secret keys of signers.
 *              : state:        The state of musig2.
 * */
typedef struct {
    musig2_context mc;
    secp256k1_keypair **comm_list;
    secp256k1_keypair keypair;
    int state;
}musig2_context_signer;

/** musig2_context_signature stores the parameters to aggregate a partial signature.
 *  Parameters  : signature: The partial signature of a signer.
 *              : R:         The aggregated commitment of the signature.
 * */
typedef struct{
    unsigned char signature[MUSIG2_PARSIG_BYTES];
    secp256k1_xonly_pubkey R;
}musig2_context_signature;


/** Initialize a musig2 signer.
 *
 *  Returns: 0 if signer initialisation fails, 1 otherwise.
 *
 *  In:     nr_messages:    the number of messages
 *  Out:    mcs:            a musig2_context_signer object
 *
 *  Generates the keypair and creates a list of batch commitments for all defined states.
 */
MUSIG2_ERROR musig2_init_signer(musig2_context_signer *mcs, int nr_messages);

/** Serialize the shareable content in compressed (33-byte) form.
 *
 *  Returns: If all content serialized successfully, it returns 1, 0 otherwise.
 *
 *  In:     mcs:                    a musig2_context_signer object
 *  Out:    serialized_pubkey:      33-byte serialized public key of signer.
 *          serialized_batch_list:  the list of 33-byte serialized commitments.
 *
 *  Takes musig2_context_signer as input which includes the public key and the commitment list of the signer.
 *  Public key and the commitments are stored within keypair type in the struct, thus before serialization,
 *  public key content is extracted from keypair for both pubkey and commitments.
 * */
MUSIG2_ERROR musig2_serialise_shareable_context(musig2_context_signer *mcs, unsigned char *serialized_pubkey, unsigned char serialized_batch_list[][MUSIG2_PUBKEY_BYTES_COMPRESSED]);

/** Signer precomputation before signing round.
 *
 *  Returns: 1 if precomputation is successful, 0 if key aggregation fails, -1 if R aggregation fails.
 *
 *  In/Out: mc:                     a musig2_context object
 *  In:     serialized_pubkey_list: a string including the list of serialized public keys from all signers.
 *          serialized_batch_list:  a string including the list of serialized batch commitments of all signers for all states.
 *          nr_signers:             the total number of signers/keys submitted.
 *
 *  Prepares the signer for partial signature generation for a batch of `nr_messages`.
 *  Aggregates the public keys and the batch commitments for all messages to be signed.
 *
 *  It takes serialized_pubkey_list and serialized_batch_list as parameters and they are expected to be
 *  serialized in compressed form (a public key is represented with 33 bytes in compressed form).
 *  Returns 1 if all public keys and all commitments aggregated successfully.
 * */
MUSIG2_ERROR musig2_signer_precomputation(musig2_context *mc, unsigned char *serialized_pubkey_list, unsigned char *serialized_batch_list, int nr_signers);

/** Generate partial signature.
 *
 *  Returns: 1 if partial signature is created successfully, -1 if the corresponding commitment is NULL,
 *          -2 if calculation of R fails, and 0 if partial signature cannot be set.
 *
 *  In:     mcs:            a musig2_context object
 *          msg:            the message to be signed.
 *          msg_len:        the length of the message.
 *  Out:    mps:            a musig2_context_signature object
 * */
MUSIG2_ERROR musig2_sign(musig2_context_signer *mcs, musig2_context_signature *mps, const unsigned char *msg, int msg_len);

/** Aggregate the given list of partial signatures.
 *
 *  Returns: 1 if multi-signature is created successfully, -1 if not all the `R` values are equal, and 0 if aggregation fails.
 *
 *  In:     mps:                a list of musig2_context_signature objects
 *          nr_signatures:      the number of signatures.
 *  Out:    signature:          an aggregated signature
 * */
MUSIG2_ERROR musig2_aggregate_partial_sig(musig2_context_signature *mps, unsigned char *signature, int nr_signatures);

/** Prepare verifier.
 *
 *  Returns: 1 if verifier prepared, 0 if public key aggregation fails.
 *
 *  In:     serialized_pubkey_list: a string including the list of serialized public keys from all signers.
 *          nr_signers:             the number of signers.
 *  Out:    aggr_pubkey:            the aggregated signature
 *
 *  Prepares verification for schnorr verifier function. Aggregates the public key and serialises
 *  to the format accepted by schnorr_verify. Fails if public key aggregation is not succeeded.
 * */
MUSIG2_ERROR musig2_prepare_verifier(musig2_aggr_pubkey *aggr_pubkey, unsigned char *serialized_pubkey_list, int nr_signers);

/** Verify given musig2 signature of given message with secp256k1_schnorrsig_verify.
 *
 *  Returns: If verification succeeds, it returns 1, 0 otherwise.
 *  In:     aggr_pubkey:    verification key of the signature.
 *          signature:      musig2_context_signer object.
 *          msg:            message of the signature to be verified.
 *          msg_len:        length of the message.
 *
 *  Note that this function could also aggregate public keys and there would be no need to have a function
 *  to prepare verifier which basically aggregates given list of public keys. However, musig2 should be verifiable
 *  without the knowledge of the signers' public keys.
 *
 *  Furthermore, musig2 generates a signature which is indistinguishable from a normal schnorr signature that
 *  libsecp generates. Therefore, verification should be done with the inputs of schnorr verify function which
 *  are the signature, message, message length, and the public key.
 * */
MUSIG2_ERROR musig2_verify(musig2_aggr_pubkey *aggr_pubkey, unsigned char *signature, const unsigned char *msg, int msg_len);


/** Free memory allocated in MuSig2 context
 * */
void musig2_context_free(musig2_context *mc);

/** Free memory allocated in MuSig2 signer context
 * */
void musig2_context_sig_free(musig2_context_signer *mcs);
