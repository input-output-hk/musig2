#include "config.h"
#include "libmusig2.h"



/** Function    : musig2_init_signer
 *  Purpose     : Initializes a musig2 signer. Generates the keypair and creates a list of batch commitments for  signer.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including parameters of musig2 signer.
 * */
void musig2_init_signer(musig2_context_sig *mc);

/** Function    : musig2_agg_R
 *  Purpose     : Aggregates the given list of batch commitments of `n` signers for `V` into `agg_R_list`.
 *                Returns 1 if agg_R_list is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : batch_list: The list of batch commitments.
 *                          : n: Number of signers.
 * Returns      : 1/0.
 * */
int musig2_agg_R(musig2_context_sig *mcs, secp256k1_pubkey *batch_list, int n);

/** Function    : musig2_sign
 *  Purpose     : Starts the signature process for signer and calls `musig2_sign_partial`.
 *                Returns 1 if partial signature is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcs, A musig2_context_sig object including parameters of musig2 signer.
 *              : IN        : msg: The message to be signed.
 *                          : tag: The tag of the message.
 *                          : n: Number of signers.
 * Returns      : 1/0.
 * */
int musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, const unsigned char *tag, int n);

/** Function    : musig2_init_aggregator
 *  Purpose     : Initializes the musig2 aggregator. For the given list of public keys, computes aggregated public key.
 *                Sets the aggregated commitment R.
 *  Parameters  : IN/OUT    : mca, A musig2_context_agg object including parameters of musig2 aggregator.
 *              : IN        : pk_list: The list of public keys.
 *                          : R: Aggregated commitment R.
 *                          : n: Number of signers.
 * */
void musig2_init_aggregator(musig2_context_agg *mca, secp256k1_pubkey *pk_list, secp256k1_pubkey R, int n);

/** Function    : musig2_aggregate_parsig
 *  Purpose     : Aggregates the given list of partial signatures. Sets the musig2 signature.
 *                Returns 1 if musig2 signature is created successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mca, A musig2_context_agg object including parameters of musig2 aggregator.
 *              : IN        : parsig_list: The list of partial signatures.
 *                          : n: Number of signers.
 * Returns      : 1/0.
 * */
int musig2_aggregate_parsig(musig2_context_agg *mca, unsigned char **parsig_list, int n);

/** Function    : musig2_init_verifier
 *  Purpose     : Initializes a musig2 verifier.
 *  Parameters  : IN/OUT    : mca, A musig2_context_ver object including parameters of musig2 verifier.
 *              : IN        : signature: The list of partial signatures.
 *                          : X: Public key.
 * */
void musig2_init_verifier(musig2_context_ver *mcv, unsigned char *signature, secp256k1_pubkey X);

/** Function    : musig2_verify_musig
 *  Purpose     : Verifies the musig2 signature with `secp256k1_schnorrsig_verify`.
 *                Returns 1 if musig2 signature is verified successfully, 0 otherwise.
 *  Parameters  : IN/OUT    : mcv, A musig2_context_ver object including parameters of musig2 verifier.
 *              : IN        : msg: The message to be signed.
 *                          : tag: The tag of the message.
 * Returns      : 1/0.
 * */
int musig2_verify_musig(musig2_context_ver *mcv,const unsigned char *msg, const unsigned char *tag );

















