#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "random.h"
#include <stddef.h>
#include <string.h>


/*************************************************************************/
/****************************** DEFINITIONS ******************************/
/*************************************************************************/


#define SCALAR_BYTES       32          /* SCALAR BYTES      */
#define XONLY_BYTES        32          /* XONLY PK BYTES    */
#define PK_BYTES           64          /* FULL PK BYTES     */


/*************************************************************************/
/************************ FUNCTION DECLARATIONS **************************/
/*************************************************************************/


/** Function    : INIT_Signer
 *  Purpose     : Generates the keypair of given signer for a random secret key in given ctx.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                IN/OUT    : signer, secp256k1_keypair object.
 * */
void INIT_Signer(secp256k1_context* ctx, secp256k1_keypair* signer);



/** Function    : CALC_Exponent
 *  Purpose     : Calculates the exponent "a" for the given list of serialized public keys.
 *                Stores the exponents in sxo_PK_LIST, returns 1 if the exponent list generated
 *                successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : sxo_PK_LIST, the list of serialised public keys.
 *                          : L, concatenation of the serialised public keys.
 *                          : N, number of signers.
 *              : IN/OUT    : exp_LIST, the ordered list of signers' exponents.
 * Returns      : 1/0
 * */
int CALC_Exponent(const secp256k1_context* ctx, unsigned char** sxo_PK_LIST, unsigned char** exp_LIST, unsigned char* L, int N);



/** Function    : AGG_Key
 *  Purpose     : Computes the aggregated public key X_ for given list of public keys and corresponding exponent list.
 *                Each public key is multiplied with its exponent and the results are combined in X_. The x_only version
 *                of X_ is stored in xo_X_ and serialised x_only version is stored in sxo_X_. If x_only version is the negative
 *                of the public key, parity_X is set to 1.  If the public keys are aggregated successfully returns 1, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : PK_LIST, the list of public keys.
 *                          : exp_LIST, the list of exponents.
 *                          : N, number of signers.
 *              : IN/OUT    : X_, the aggregated public key.
 *                          : xo_X_, the x_only aggregated public key.
 *                          : sxo_X_, the serialized x_only aggregated public key.
 *                          : parity_X, parity of xo_X_.
 * Returns      : 1/0
 * */
int AGG_Key(const secp256k1_context* ctx, secp256k1_pubkey* PK_LIST, secp256k1_pubkey* X_, secp256k1_xonly_pubkey* xo_X_, unsigned char* sxo_X_, unsigned char** exp_LIST, int* parity_X, int N);



/** Function    : BATCH_Commitment
 *  Purpose     : Generates random nonce values and stores in nonce_LIST. Computes corresponding commitments and stores
 *                in COMM_LIST. Total number of nonce-commitment is NR_MSGS * V * N.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : NR_MSGS, the number of messages.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : COMM_LIST, the list of public commitments.
 *                          : nonce_LIST, the list of secret nonce values.
 *                          : cnt, the last index of commitment list to assign next entry.
 * */
void BATCH_Commitment(const secp256k1_context* ctx, secp256k1_pubkey** COMM_LIST, unsigned char** nonce_LIST, int* cnt, int NR_MSGS, int V);



/** Function    : SIG_Partial
 *  Purpose     : This is the main function that generates partial signatures. It aggregate public commitments in aggr_COMMS
 *                of size V. It calls CALC_b, CALC_Nonce, CALC_Challenge, and SET_Response for a signer. It negates b or c according
 *                to the parity of xo_R or xo_X_, respectively. If both 1, it sets parity_XR to 1, to negate aggregated signature at
 *                the end of the signature process.
 *                Returns 1 if partial signature is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : COMM_LIST, the secp256k1_pubkey commitment list.
 *                          : sec_nonce_LIST, the list of secret nonces of signer.
 *                          : seckey, the secret key of signer.
 *                          : sxo_X_, the serialized x_only aggregated public key.
 *                          : exp, the exponent of signer.
 *                          : msg_hash, the 32-byte hash of the message to be signed.
 *                          : parity_X, the parity of xo_X_.
 *                          : STATE, the state of Musig2.
 *                          : N, the number of signers.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : par_sig, the partial signature of the signer.
 *                          : sxo_R, the serialized x_only R.
 *                          : parity_XR, the parity for xo_X_ and xo_R_.
 *  Returns     : 1/0.
 * */
int SIG_Partial(const secp256k1_context* ctx,  secp256k1_pubkey** COMM_LIST, unsigned char** sec_nonce_LIST,
                unsigned char* sxo_R, unsigned char* par_sig, unsigned char* seckey, unsigned char* sxo_X_,
                unsigned char* exp, unsigned char* msg_hash, int parity_X, int* parity_XR,
                int STATE, int N, int V) ;



/** Function    : CALC_b
 *  Purpose     : Computes b = H(aggr_COMMS, X, msg_hash) for given serialized x_only public key sxo_X_, msg_hash, and aggr_COMMS.
 *                Returns 1 if hash is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : aggr_COMMS, the list of aggregated commitments.
 *                          : sxo_X_, the serialized x_only aggregated public key.
 *                          : msg_hash, 32-byte hash of the message to be signed.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : b, the 32-byte, tagged hash of sxo_X_, msg_hash, and aggr_COMMS.
 *  Returns     : 1/0.
 * */
int CALC_b(const secp256k1_context* ctx, secp256k1_pubkey** aggr_COMMS, unsigned char* sxo_X_, unsigned char* b, unsigned char* msg_hash, int V) ;



/** Function    : CALC_Nonce
 *  Purpose     : Computes b_LIST = {b^(j-1)} for j in V. Calculates Rb_LIST = {aggr_COMMS[j] * b_LIST[j]} for j in V.
 *                Takes the sum of the values in Rb_LIST, gets x_only R with parity_R and serializes it into sxo_R.
 *                Returns 1 if b_LIST, Rb_LIST, and sxo_R are generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : aggr_COMMS, the list of aggregated commitments.
 *                          : b, b = H(aggr_COMMS, X, msg_hash) of size 32-bytes.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : b_LIST, the list of b exponents of size V to be used to calculate R.
 *                          : sxo_R, the serialized x_only R.
 *                          : parity_R, the parity of x_only R.
 *  Returns     : 1/0.
 * */
int CALC_Nonce(const secp256k1_context *ctx, secp256k1_pubkey **aggr_COMMS, unsigned char **b_LIST, unsigned char *sxo_R, unsigned char *b, int* parity_R, int V) ;



/** Function    : CALC_Challenge
 *  Purpose     : Computes challenge c = H(sxo_R, sxo_X_, msg_hash).
 *                Returns 1 if c is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : sxo_X_, the serialized x_only aggregated public key.
 *                          : sxo_R, the serialized x_only nonce R.
 *                          : msg_hash, the 32-byte hash of the message to be signed.
 *              : IN/OUT    : c, the 32-byte challenge.
 *  Returns     : 1/0.
 * */
int CALC_Challenge(const secp256k1_context* ctx, const unsigned char* sxo_X_, unsigned char* sxo_R, unsigned char* msg_hash, unsigned char* c) ;



/** Function    : SET_Response
 *  Purpose     : Computes the partial signature of given signer with
 *                par_sig = SUM (exp * c * seckey, (SUM(b_LIST[j] * sec_nonce_LIST[j])).
 *                Returns 1 if partial signature is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : b_LIST, the serialized x_only aggregated public key.
 *                          : sec_nonce_LIST, the list of secret nonces of signer.
 *                          : c, the 32-byte challenge.
 *                          : msg_hash, the 32-byte hash of the message to be signed.
 *                          : exp, the exponent of signer
 *                          : seckey, the secret key of signer.
 *                          : parity_R, parity of x_only R.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : par_sig, the partial signature of the signer.
 *  Returns     : 1/0.
 * */
int SET_Response(const secp256k1_context* ctx, unsigned char** b_LIST, unsigned char** sec_nonce_LIST, unsigned char* par_sig, unsigned char* c, unsigned char* exp, unsigned char* seckey, int parity_R, int V) ;



/** Function    : AGG_SIG_SecondRound
 *  Purpose     : Aggregates the partial signatures of N signers in par_sig_LIST, stores the result in agg_sig.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : par_sig_LIST, the list of partial signatures.
 *                          : N, the number of signers.
 *              : IN/OUT    : agg_sig, the aggregated signature.
 * */
void AGG_SIG_SecondRound(const secp256k1_context* ctx, unsigned char** par_sig_LIST, unsigned char* agg_sig, int N);



