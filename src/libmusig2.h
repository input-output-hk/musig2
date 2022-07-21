#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include "random.h"



/*************************************************************************/
/****************************** DEFINITIONS ******************************/
/*************************************************************************/


#define SCALAR_BYTES       32          // SCALAR BYTES
#define XONLY_BYTES        32          // XONLY PK BYTES
#define PK_BYTES           64          // FULL PK BYTES


/*************************************************************************/
/************************ FUNCTION DECLARATIONS **************************/
/*************************************************************************/


/** Function    : MuSig2_KeyGen
 *  Purpose     : Generates the keypair of given signer for a random secret key in given ctx.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                IN/OUT    : signer, secp256k1_keypair object.
 * */
void MuSig2_KeyGen(secp256k1_context *ctx,
                   secp256k1_keypair *signer_keypair) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : MuSig2_KeyAggCoef
 *  Purpose     : Calculates the exponent "a" for the given list of serialized xonly public keys.
 *                Stores the exponents in a_LIST, returns 1 if the exponent list generated
 *                successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : sxo_PK_LIST, the list of serialised public keys.
 *                          : L, concatenation of the serialised public keys.
 *                          : N, number of signers.
 *              : IN/OUT    : a_LIST, the ordered list of signers' exponents.
 * Returns      : 1/0
 * */
int MuSig2_KeyAggCoef(const secp256k1_context *ctx,
                      unsigned char **ser_xonly_X_LIST, unsigned char **a_LIST, unsigned char *L,
                      int N ) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : MuSig2_KeyAgg
 *  Purpose     : Computes the aggregated public key X_ for given list of public keys and corresponding exponent list.
 *                Each public key is multiplied with its exponent and the results are combined in X_. The x_only version
 *                of X_ is stored in xonly_X_ and serialised x_only version is stored in ser_xonly_X_. If x_only version is the negative
 *                of the aggregated public key, parity_X_ is set to 1.  If the public keys are aggregated successfully
 *                returns 1, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : X_LIST, the list of public keys.
 *                          : a_LIST, the list of exponents.
 *                          : N, number of signers.
 *              : IN/OUT    : X_, the aggregated public key.
 *                          : xonly_X_, the x_only aggregated public key.
 *                          : ser_xonly_X_, the serialized x_only aggregated public key.
 *                          : parity_X_, parity of xo_X_.
 * Returns      : 1/0
 * */
int MuSig2_KeyAgg(const secp256k1_context *ctx,
                  secp256k1_pubkey *X_LIST, secp256k1_pubkey *X_,
                  secp256k1_xonly_pubkey *xonly_X_,
                  unsigned char *ser_xonly_X_, unsigned char **a_LIST,
                  int *parity_X_, int N) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : MuSig2_BatchCommitment
 *  Purpose     : Generates random nonce values and stores in r_LIST. Computes corresponding commitments and stores
 *                in R_LIST. Total number of nonce-commitment is NR_MSGS * V * N.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : NR_MSGS, the number of messages.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : R_LIST, the list of public commitments.
 *                          : r_LIST, the list of secret nonce values.
 *                          : cnt, the last index of commitment list to assign next entry.
 * */
void MuSig2_BatchCommitment(const secp256k1_context *ctx,
                            secp256k1_pubkey **R_LIST,
                            unsigned char **r_LIST,
                            int i, int N, int NR_MSGS, int V) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : MuSig2_SignPartial
 *  Purpose     : This is the main function that generates partial signatures. It aggregate public commitments in
 *                aggr_R_LIST of size V. It calls Calc_b, Calc_R, Calc_c, and Set_sig for a signer.
 *                It negates b or c according to the parity of xonly_R or xonly_X_, respectively.
 *                If both 1, it sets parity_RX_ to 1, to negate aggregated signature at the end of the signature process.
 *                Returns 1 if partial signature is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : R_LIST, the secp256k1_pubkey commitment list.
 *                          : r_LIST, the list of secret nonces of signer.
 *                          : x, the secret key of signer.
 *                          : ser_xonly_X_, the serialized x_only aggregated public key.
 *                          : a, the exponent of signer.
 *                          : msg_hash, the 32-byte hash of the message to be signed.
 *                          : parity_X_, the parity of xonly_X_.
 *                          : STATE, the state of Musig2.
 *                          : N, the number of signers.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : parsig, the partial signature of the signer.
 *                          : ser_xonly_R, the serialized xonly_R .
 *                          : parity_RX_, the parity for xonly_X_ and xonly_R.
 *  Returns     : 1/0.
 * */
int MuSig2_SignPartial(const secp256k1_context *ctx,
                        secp256k1_pubkey **R_LIST,
                        unsigned char **r_LIST, unsigned char *ser_xonly_R, unsigned char *parsig, unsigned char *x, unsigned char *ser_xonly_X_, unsigned char *a, unsigned char *msg_hash,
                        int parity_X_, int *parity_RX_, int STATE, int N, int V) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : MuSig2_AggSignatures
 *  Purpose     : Aggregates the partial signatures of N signers in parsig_LIST, stores the result in aggsig.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : parsig_LIST, the list of partial signatures.
 *                          : N, the number of signers.
 *              : IN/OUT    : aggsig, the aggregated signature.
 * */
void MuSig2_AggSignatures(const secp256k1_context *ctx,
                          unsigned char **parsig_LIST, unsigned char *aggsig,
                          int N) ;
/*----------------------------------------------------------------------------------------------------------*/


/*----------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------*/

/** Function    : Calc_b
 *  Purpose     : Computes b = H(aggr_R_LIST, ser_xonly_X_, msg_hash) for given serialized x_only public key ser_xonly_X_, msg_hash, and aggr_R_LIST.
 *                Returns 1 if hash is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : aggr_R_LIST, the list of aggregated commitments.
 *                          : ser_xonly_X_, the serialized x_only aggregated public key.
 *                          : msg_hash, 32-byte hash of the message to be signed.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : b, the 32-byte, tagged hash of ser_xonly_X_, aggr_R_LIST, and msg_hash.
 *  Returns     : 1/0.
 * */
int Calc_b(const secp256k1_context *ctx,
           secp256k1_pubkey **aggr_R_LIST,
           unsigned char *ser_xonly_X_, unsigned char *b, unsigned char *msg_hash,
           int V) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : Calc_R
 *  Purpose     : Computes b_LIST = {b^(j-1)} for j in V. Calculates Rb_LIST = {aggr_R_LIST[j] * b_LIST[j]} for j in V.
 *                Takes the sum of the values in Rb_LIST, gets x_only R with parity_R and serializes it into sxo_R.
 *                Returns 1 if b_LIST, Rb_LIST, and sxo_R are generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : aggr_R_LIST, the list of aggregated commitments.
 *                          : b, b = Calc_b(ctx, aggr_R_LIST, ser_xonly_X_, b, msg_hash, V).
 *                          : V, the number of nonce values.
 *              : IN/OUT    : b_LIST, the list of b exponents of size V to be used to calculate R.
 *                          : ser_xonly_R, the serialized x_only R.
 *                          : parity_R, the parity of x_only R.
 *  Returns     : 1/0.
 * */
int Calc_R(const secp256k1_context *ctx,
           secp256k1_pubkey **aggr_R_LIST,
           unsigned char **b_LIST, unsigned char *ser_xonly_R, unsigned char *b,
           int* parity_R, int V) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : Calc_c
 *  Purpose     : Computes challenge c = H(ser_xonly_R, ser_xonly_X_, msg_hash).
 *                Returns 1 if c is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : ser_xonly_X_, the serialized x_only aggregated public key.
 *                          : ser_xonly_R, the serialized x_only nonce R.
 *                          : msg_hash, the 32-byte hash of the message to be signed.
 *              : IN/OUT    : c, the 32-byte challenge.
 *  Returns     : 1/0.
 * */
int Calc_c(const secp256k1_context *ctx,
           const unsigned char *ser_xonly_X_, unsigned char *ser_xonly_R, unsigned char *msg_hash, unsigned char *c) ;
/*----------------------------------------------------------------------------------------------------------*/


/** Function    : Set_parsig
 *  Purpose     : Computes the partial signature of given signer with
 *                parsig = SUM (a * c * x, (SUM(b_LIST[j] * sec_r_LIST[j])).
 *                Returns 1 if partial signature is generated successfully, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : b_LIST, the serialized x_only aggregated public key.
 *                          : sr_LIST, the list of secret nonces of signer.
 *                          : c, the 32-byte challenge.
 *                          : msg_hash, the 32-byte hash of the message to be signed.
 *                          : a, the exponent of signer
 *                          : x, the secret key of signer.
 *                          : parity_R, parity of x_only R.
 *                          : V, the number of nonce values.
 *              : IN/OUT    : parsig, the partial signature of the signer.
 *  Returns     : 1/0.
 * */
int Set_parsig(const secp256k1_context* ctx,
               unsigned char **b_LIST, unsigned char **sr_LIST, unsigned char *parsig, unsigned char *c, unsigned char *a, unsigned char *x,
               int parity_R, int V) ;
/*----------------------------------------------------------------------------------------------------------*/





