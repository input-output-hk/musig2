#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "random.h"


// todo: use the secp library constants
#define V                   2          // Number of nonce values
#define SCALAR_BYTES       32          // SCALAR BYTES
#define XONLY_BYTES        32          // XONLY PUBLIC KEY BYTES
#define PAR_SIG_BYTES      32          // PARTIAL SIGNATURE BYTES
#define PK_BYTES           64          // FULL SIZE PUBLIC KEY BYTES
#define SCH_SIG_BYTES      64          // SCHNORR SIGNATURE BYTES


/** Struct      : musig2_context
 *  Purpose     : Stores the parameters of musig2.
 *  Parameters  : ctx: a secp256k1_context object.
 *              : aggr_pk: Aggregated public key.
 *              : aggr_R: Aggregated R.
 *              : L: Concatenation of x_only public keys of signers.
 *              : state: The state of musig2.
 *              : nr_signers: The number of signers.
 * */
typedef struct{
    secp256k1_context* ctx;
    secp256k1_pubkey aggr_pk;
    secp256k1_pubkey aggr_R_list[V];
    int par_pk;
    int nr_signers;
    unsigned char *L;
}musig2_context;

/** Struct      : musig2_context_sig
 *  Purpose     : Stores the parameters of musig2 signer.
 *  Parameters  : mc: a musig2_context object including the parameters of musig2.
 *              : comm_list: Batch commitment list of a signer.
 *              : keypair: Public and secret keys of signers.
 *              : aggr_R_list: The list of aggregated batch commitments.
 *              : nr_messages: The number of messages.
 * */
typedef struct {
    musig2_context mc;
    secp256k1_keypair **comm_list;
    secp256k1_keypair keypair;
    int nr_messages;
    int state;
}musig2_context_sig;

/** Struct      : musig2_partial_signature
 *  Purpose     : Stores the parameters to aggregate a partial signature.
 *  Parameters  : sig: The partial signature of a signer.
 *              : R: The nonce of a signer.
 * */
typedef struct{
    unsigned char sig[PAR_SIG_BYTES];
    secp256k1_xonly_pubkey R;
}musig2_partial_signature;

/*** Free memory allocated in MuSig2 context ***/
void musig2_context_free(musig2_context *mc);

/*** Free memory allocated in MuSig2 context ***/
void musig2_context_sig_free(musig2_context_sig *mcs);

/** Function    : musig2_init_signer
 *  Purpose     : Initializes a musig2 signer. Generates the keypair and creates a list of batch commitments for  signer.
 *                Returns 0 if signer initialisation fails, 1 otherwise.
 *  Parameters  : IN/OUT    : mcs: A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : ctx: A secp256k1_context object.
 *                          : nr_messages: The number of messages.
 * Returns      : 1/0.
 * */
int musig2_init_signer(musig2_context_sig *mcs, secp256k1_context *ctx, int nr_messages);

/** Function    : musig2_aggregate_pubkey
 *  Purpose     : Aggregates the given list of public keys.
 *                Returns 1 if keys aggregated successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mc: A musig2_context object including musig2 parameters.
 *              : IN        : pk_list: List of public keys.
 *                          : nr_signers: The number of signers.
 * Returns      : 1/0.
 * */
int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list, int nr_signers);

/** Function    : musig2_aggregate_R
 *  Purpose     : Aggregates the given list of batch commitments of `n` signers for `V` into `aggr_R_list`.
 *                Returns 1 if aggr_R_list is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs: A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : batch_list: The list of batch commitments.
 * Returns      : 1/0.
 * */
int musig2_aggregate_R(musig2_context *mc, secp256k1_pubkey batch_list[][V]);

/** Function    : musig2_sign
 *  Purpose     : Starts the signature process for signer and calls `musig2_sign_partial`.
 *                Returns 1 if partial signature is created successfully, -1 if the corresponding commitment is NULL, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs: A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : msg: The message to be signed.
 *                          : msg_len: The length of the message.
 * Returns      : 1/-1/0.
 * */
int musig2_sign(musig2_context_sig *mcs, musig2_partial_signature *mps, const unsigned char *msg, int msg_len);

/** Function    : musig2_aggregate_partial_sig
 *  Purpose     : Aggregates the given list of partial signatures. Sets the musig2 signature.
 *                Returns 1 if musig2 signature is created successfully, -1 if not all the `R` values are equal
 *                and 0 otherwise.
 *  Parameters  : IN/OUT    : signature: A musig2 signature.
 *              : IN        : ctx: secp256k1_context object.
 *                          : mps: The list of partial signatures and R values of signers.
 *                          : pk_list: The list of public keys.
 *                          : nr_signatures: The number of signatures.
 * Returns      : 1/0.
 * */
int musig2_aggregate_partial_sig(secp256k1_context *ctx, musig2_partial_signature *mps, unsigned char *signature, int nr_signatures);

/** Function    : musig2_prepare_verifier
 *  Purpose     : Prepares verification for schnorr verifier function. Aggregates the public key and serialises
 *                to the format accepted by schorr_verify.
 *  Parameters  : IN/OUT    : aggr_pk: serialised aggregated public key.
 *              : IN        : ctx: secp256k1_context object.
 *                          : pk_list: list of public keys from all signers
 *                          : nr_signers: the total number of signers/keys submitted.
 */
void musig2_prepare_verifier(secp256k1_context *ctx, secp256k1_xonly_pubkey *aggr_pk, secp256k1_pubkey *pk_list, int nr_signers);
