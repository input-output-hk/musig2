#include "src/libmusig2.h"

#define N               5 /* Number of signers */
#define V               2 /* Number of nonce values. Note that V>2 is not working yet. */

#define NR_MSGS         (const int)2
#define MSG_1           (const unsigned char *) "Musig2 Schnorr MSG 1"
#define MSG_2           (const unsigned char *) "Musig2 Schnorr MSG 2"
#define TAG_1           (const unsigned char *) "MSG_1"
#define TAG_2           (const unsigned char *) "MSG_2"


/** Pointer     : MUSIG2
 *  Purpose     : Stores the parameters used in Musig2 generation.
 *  Parameters  : COMM_LIST, the secp256k1_pubkey array of public batch commitments.
 *              : xo_X_, the x_only aggregated public key of X_
 *              : nonce_LIST, the array of batch nonces of size 32-bytes.
 *              : exp_LIST, the array of exponents of size 32-bytes.
 *              : sxo_X_, the serialized x_only X_.
 *              : parity_X, the parity of xo_X_.
 *              : STATE, the current state of Musig2.
 * */
typedef struct{
    secp256k1_pubkey** COMM_LIST;
    secp256k1_xonly_pubkey* xo_X_;
    unsigned char** nonce_LIST;
    unsigned char** exp_LIST;
    unsigned char* sxo_X_;
    int parity_X;
    int STATE;
}MUSIG2_t[0], *MUSIG2;


/** Function    : GEN_Musig2
 *  Purpose     : This is the main function to compute a whole process of Musig2 for a specific message and defined parameters.
 *                It returns 1 if the generated signature is validated by secp256k1_schnorrsig_verify function, 0 otherwise.
 *  Parameters  : IN        : ctx, a secp256k1_context object.
 *                          : Signers, the list of secp256k1_keypair objects of signers.
 *                          : msg, the message to be signed.
 *                          : the tag of the hash function for msg.
 *                          : param, is a pointer to parameters of Musig2.
 *  Returns     : 1/0.
 * */
int GEN_Musig2(secp256k1_context* ctx, secp256k1_keypair* Signers, MUSIG2 param, const unsigned char* msg, const unsigned char* tag);