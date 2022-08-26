#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "random.h"
#include "../config.h"



#define V                   2          // Number of nonce values
#define SCALAR_BYTES       32          // SCALAR BYTES
#define XONLY_BYTES        32          // XONLY PUBLIC KEY BYTES
#define PAR_SIG_BYTES      32          // PARTIAL SIGNATURE BYTES
#define PK_BYTES           64          // FULL SIZE PUBLIC KEY BYTES
#define SCH_SIG_BYTES      64          // SCHNORR SIGNATURE BYTES


/** Struct      : musig2_context
 *  Purpose     : Stores the parameters of musig2.
 *  Parameters  : ctx: a secp256k1_context object.
 *              : X_: Aggregated public key.
 *              : R_: Aggregated R.
 *              : L: Concatenation of x_only public keys of signers.
 *              : state: The state of musig2.
 * */
typedef struct{
    secp256k1_context* ctx;
    secp256k1_pubkey X_;
    secp256k1_pubkey R_;
    unsigned char *L;
    int state;
}musig2_context;

/** Struct      : musig2_context_sig
 *  Purpose     : Stores the parameters of musig2 signer.
 *  Parameters  : mc: a musig2_context object including the parameters of musig2.
 *              : commlist: Batch commitment list of a signer.
 *              : keypair: Public and secret keys of signers.
 *              : agg_R_list: The list of aggregated batch commitments.
 * */
typedef struct {
    musig2_context *mc;
    secp256k1_keypair **commlist;
    secp256k1_keypair keypair;
    secp256k1_pubkey agg_R_list[V];
}musig2_context_sig;

/** Struct      : musig2_param
 *  Purpose     : Stores the parameters to generate a partial signature.
 *  Parameters  : a: The exponent `a` of signer.
 *              : b: nonce, b = H_non(X, (R_1, ..., R_V), msg).
 *              : c: challenge, c = H_sig(X, R, msg).
 *              : b_list: The list of `b` values, b_LIST = { b^(j-1) }.
 *              : msg: The message to be signed.
 *              : sx_X: Serialized x_only aggregated public key.
 *              : sx_R: Serialized x_only aggregated R.
 *              : par_R: Parity of R.
 *              : par_X: Parity of X.
 *              : msg_len: The length of message.
 * */
typedef struct{
    unsigned char a[SCALAR_BYTES];
    unsigned char b[SCALAR_BYTES];
    unsigned char c[SCALAR_BYTES];
    unsigned char *b_LIST[V];
    unsigned char *msg;
    unsigned char sx_X[XONLY_BYTES];
    unsigned char sx_R[XONLY_BYTES];
    int par_R;
    int par_X;
    int msg_len;
}musig2_param;

/** Struct      : musig2_partial_signatures
 *  Purpose     : Stores the parameters to aggregate a partial signatures.
 *  Parameters  : sig: The partial signature of a signer.
 *              : R_: The nonce of a signer.
 * */
typedef struct{
    unsigned char sig[PAR_SIG_BYTES];
    secp256k1_pubkey R_;
}musig2_partial_signatures;


/** Function    : musig2_init_signer
 *  Purpose     : Initializes a musig2 signer. Generates the keypair and creates a list of batch commitments for  signer.
 *  Parameters  : IN/OUT    : mcs: A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : ctx: A secp256k1_context object.
 * */
void musig2_init_signer(musig2_context_sig *mcs, secp256k1_context *ctx);

/** Function    : musig2_aggregate_pubkey
 *  Purpose     : Aggregates the given list of public keys.
 *                Returns 1 if keys aggregated successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mc: A musig2_context object including musig2 parameters.
 *              : IN        : pk_list: List of public keys.
 * Returns      : 1/0.
 * */
int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list);

/** Function    : musig2_agg_R
 *  Purpose     : Aggregates the given list of batch commitments of `n` signers for `V` into `agg_R_list`.
 *                Returns 1 if agg_R_list is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs: A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : batch_list: The list of batch commitments.
 * Returns      : 1/0.
 * */
int musig2_agg_R(musig2_context_sig *mcs, secp256k1_pubkey *batch_list);

/** Function    : musig2_sign
 *  Purpose     : Starts the signature process for signer and calls `musig2_sign_partial`.
 *                Returns 1 if partial signature is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs: A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : msg: The message to be signed.
 *                          : msg_len: The length of the message.
 * Returns      : 1/0.
 * */
int musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, int msg_len, unsigned char *parsig);

/** Function    : musig2_aggregate_partial_sig
 *  Purpose     : Aggregates the given list of partial signatures. Sets the musig2 signature.
 *                Returns 1 if musig2 signature is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mca: A musig2_context object.
 *                          : signature: A musig2 signature.
 *              : IN        : ctx: secp256k1_context object.
 *                          : mps: The list of partial signatures and R values of signers.
 *                          : pk_list: The list of public keys.
 *                          : signature: The aggregated signature.
 * Returns      : 1/0.
 * */
int musig2_aggregate_partial_sig(secp256k1_context *ctx, musig2_context *mca, musig2_partial_signatures *mps, secp256k1_pubkey *pk_list, unsigned char *signature);

/** Function    : musig2_ver_musig
 *  Purpose     : Verifies the musig2 signature with `secp256k1_schnorrsig_verify`.
 *                Returns 1 if musig2 signature is verified successfully, 0 otherwise.
 *  Parameters  : IN        : ctx: A secp256k1_context object including parameters of musig2 verifier.
 *                          : signature: A musig2 signature.
 *                          : X_: Aggregated public key.
 *                          : msg: The message to be signed.
 *                          : msg_len: The length of the message.
 * Returns      : 1/0.
 * */
int musig2_ver_musig(secp256k1_context *ctx, const unsigned char *signature, secp256k1_pubkey X_, const unsigned char *msg, int msg_len );
