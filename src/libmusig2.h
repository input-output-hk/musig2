#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "random.h"



#define V                   2          // Number of nonce values
#define SCALAR_BYTES       32          // SCALAR BYTES
#define XONLY_BYTES        32          // XONLY PUBLIC KEY BYTES
#define PK_BYTES           64          // FULL SIZE PUBLIC KEY BYTES
#define SCH_SIG_BYTES      64          // SCHNORR SIGNATURE BYTES


/** Struct      : musig2_context
 *  Purpose     : Stores the parameters of musig2.
 *  Parameters  : ctx: a secp256k1_context object.
 *              : X_: Aggregated public key.
 *              : L: Concatenation of x_only public keys of signers.
 *              : state: The state of musig2.
 *              : R: Aggregated R.
 * */
typedef struct{
    secp256k1_context* ctx;
    secp256k1_pubkey X_;
    unsigned char *L;
    int state;
    secp256k1_pubkey R;
}musig2_context;

/** Struct      : musig2_context_sig
 *  Purpose     : Stores the parameters of musig2 signer.
 *  Parameters  : mc: a musig2_context object including the parameters of musig2.
 *              : commlist: Batch commitment list of a signer.
 *              : keypair: Public and secret keys of signers.
 *              : agg_R_list: The list of aggregated batch commitments.
 *              : parsig: Partial signature of the signer.
 * */
typedef struct {
    musig2_context *mc;
    secp256k1_keypair **commlist;
    secp256k1_keypair keypair;
    secp256k1_pubkey agg_R_list[V];
    unsigned char parsig[SCALAR_BYTES];
}musig2_context_sig;

/** Struct      : musig2_context_agg
 *  Purpose     : Stores the parameters of musig2 aggregator.
 *  Parameters  : mc: a musig2_context object including the parameters of musig2.
 *              : signature: MuSig2 signature.
 * */
typedef struct {
    musig2_context *mc;
    unsigned char signature[SCH_SIG_BYTES];
}musig2_context_agg;

/** Struct      : musig2_context_ver
 *  Purpose     : Stores the parameters of musig2 verifier.
 *  Parameters  : ctx: a secp256k1_context object.
 *              : x_X: x_only aggregated key.
 *              : signature: MuSig2 signature.
 * */
typedef struct{
    secp256k1_context* ctx;
    secp256k1_xonly_pubkey x_X;
    unsigned char signature[SCH_SIG_BYTES];
}musig2_context_ver;

/** Struct      : musig2_param
 *  Purpose     : Stores the parameters to generate a partial signature.
 *  Parameters  : a: The exponent `a` of signer.
 *              : b: nonce, b = H_non(X, (R_1, ..., R_V), msg).
 *              : c: challenge, c = H_sig(X, R, msg).
 *              : b_list: The list of `b` values, b_LIST = { b^(j-1) }.
 *              : msg_hash: The hash of given message with given tag.
 *              : sx_X: Serialized x_only aggregated public key.
 *              : sx_R: Serialized x_only aggregated R.
 *              : par_R: Parity of R.
 *              : par_X: Parity of X.
 * */
typedef struct{
    unsigned char a[SCALAR_BYTES];
    unsigned char b[SCALAR_BYTES];
    unsigned char c[SCALAR_BYTES];
    unsigned char *b_LIST[V];
    unsigned char msg_hash[SCALAR_BYTES];
    unsigned char sx_X[SCALAR_BYTES];
    unsigned char sx_R[SCALAR_BYTES];
    int par_R;
    int par_X;
}musig2_param;


/** Function    : musig2_key_gen
 *  Purpose     : Generates a keypair for signer of type secp256k1_keypair.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including signer parameters.
 * */
void musig2_key_gen(musig2_context_sig *mcs);

/** Function    : musig2_batch_commitment
 *  Purpose     : Randomly generates a secp256k1_keypair list of batch commitments of size NR_MSGS*V, for signer.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including signer parameters.
 * */
void musig2_batch_commitment(musig2_context_sig *mcs) ;

/** Function    : musig2_key_agg_coef
 *  Purpose     : Computes the exponent `a` for given serialized x_only public key and concatenated public keys L.
 *                Returns 1 if key aggregation coefficient is computed successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mc, A musig2_context object including musig2 parameters.
 *                          : a, Exponent `a`.
 *              : IN        : ser_xonly_X: Serialized x_only public key of a signer.
 *                          : L: Concatenation of serialized x_only public keys of signers.
 *                          : n: Number of signers.
 * Returns      : 1/0.
 * */
int musig2_key_agg_coef(musig2_context *mc, unsigned char *ser_xonly_X, unsigned char *a, unsigned char *L, int n) ;

/** Function    : musig2_aggregate_pubkey
 *  Purpose     : Aggregates the given list of public keys.
 *                Returns 1 if keys aggregated successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mc, A musig2_context object including musig2 parameters.
 *              : IN        : pk_list, List of public keys.
 *                          : n: Number of signers.
 * Returns      : 1/0.
 * */
int musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list, int n );

/** Function    : musig2_calc_b
 *  Purpose     : Calculates b = H_non(X, (R_1, ..., R_V), msg).
 *                Returns 1 if `b` is computed successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : param, A musig2_param object including parameters to generate partial signature.
 *              : IN        : mcs, A musig2_context_sig object including parameters of musig2 signer.
 * Returns      : 1/0.
 * */
int musig2_calc_b(musig2_context_sig *mcs, musig2_param *param);

/** Function    : musig2_calc_R
 *  Purpose     : Calculates the aggregated commitment `R`.
 *                Returns 1 if `R` is computed successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : param, A musig2_param object including parameters to generate partial signature.
 *              : IN        : mcs, A musig2_context_sig object including parameters of musig2 signer.
 * Returns      : 1/0.
 * */
int musig2_calc_R(musig2_context_sig *mcs, musig2_param *param);

/** Function    : musig2_calc_c
 *  Purpose     : Calculates the challenge c.
 *  Parameters  : IN/OUT    : param, A musig2_param object including parameters to generate partial signature.
 *              : IN        : mcs, A musig2_context_sig object including parameters of musig2 signer.
 * */
void musig2_calc_c(musig2_context *mc, musig2_param *param);

/** Function    : musig2_set_parsig
 *  Purpose     : Generates the partial signature of the signer.
 *                Returns 1 if the partial signature is computed successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : param, A musig2_param object including parameters to generate partial signature.
 * Returns      : 1/0.
 * */
int musig2_set_parsig(musig2_context_sig *mcs, musig2_param *param);

/** Function    : musig2_sign_partial
 *  Purpose     : Generates the partial signature of the signer.
 *                Returns 1 if the partial signature is computed successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : param, A musig2_param object including parameters to generate partial signature.
 * Returns      : 1/0.
 * */
int musig2_sign_partial(musig2_context_sig *mcs, musig2_param *param);
























