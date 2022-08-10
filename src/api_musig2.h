#include "libmusig2.h"

#define N               5 /* Number of signers */
#define V               2 /* Number of nonce values. Note that V>2 is not working yet. */

#define NR_MSGS         (const int)2
#define MSG_1           (const unsigned char *) "Musig2 Schnorr MSG 1"
#define MSG_2           (const unsigned char *) "Musig2 Schnorr MSG 2"
#define TAG_1           (const unsigned char *) "MSG_1"
#define TAG_2           (const unsigned char *) "MSG_2"


/** Pointer     : MUSIG2
 *  Purpose     : Stores the parameters used in Musig2 generation.
 *  Parameters  : R_LIST, the secp256k1_pubkey array of public batch commitments.
 *              : xonly_X_, the x_only aggregated public key of X_.
 *              : r_LIST, the array of batch nonces of size 32-bytes.
 *              : a_LIST, the array of exponents of size 32-bytes.
 *              : ser_xonly_X_, the serialized xonly_X_.
 *              : parity_X_, the parity of xonly_X_.
 *              : STATE, the current state of Musig2.
 * */
typedef struct{
    secp256k1_pubkey **R_LIST;
    secp256k1_xonly_pubkey *xonly_X_;
    unsigned char **r_LIST;
    unsigned char **a_LIST;
    unsigned char *ser_xonly_X_;
    int parity_X_;
    int STATE;
}MUSIG2_t, *MUSIG2;

/** Pointer     : SIGNER
 *  Purpose     : Stores the parameters of a MuSig2 signer.
 *  Parameters  : keypair, the secp256k1_keypair object holding a keypair on secp256k1 curve.
 *              : r_LIST, the list to store V secret nonces of size 32-bytes.
 * */
typedef struct{
    secp256k1_keypair *keypair;
    unsigned char **r_LIST;
}SIGNER_t, *SIGNER;


/** Function    : Gen_MuSig2
 *  Purpose     : This is the main function to compute a whole process of Musig2 for a specific message and defined parameters.
 *                It returns 1 if the generated signature is validated by secp256k1_schnorrsig_verify function, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : Signers, the list of secp256k1_keypair objects of signers.
 *                          : msg, the message to be signed.
 *                          : the tag of the hash function for msg.
 *                          : param, is a pointer to parameters of Musig2.
 *  Returns     : 1/0.
 * */
int Gen_MuSig2(secp256k1_context *ctx, SIGNER *Signers, MUSIG2 param, const unsigned char *msg, const unsigned char *tag);
/*----------------------------------------------------------------------------------------------------------*/