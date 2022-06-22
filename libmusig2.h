#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include "random.h"

/*************************************************************************/
/****************************** DEFINITIONS ******************************/
/*************************************************************************/
#define N               7 /* Number of signers */

/************ DO NOT CHANGE ************/
#define V               2 /* Number of nonce values. Note that V>2 is not working yet. */

#define SK_BYTES        32
#define SK_SIZE	        SK_BYTES*sizeof(unsigned char)

#define PK_BYTES        33
#define PK_SIZE         PK_BYTES*sizeof(unsigned char)
/***************************************/
/*************************************************************************/


/*************************************************************************/
/************************* DATA STRUCTURES *******************************/
/*************************************************************************/
/* Pointer:     SIGNER
 * Purpose:     Pointer to a signer object holding signer keys and nonce values.
 * Parameters:  sk: Signer's secret key, 32 Bytes.
 *              r:  Char array that holds V random values of size SK_SIZE.
 *              PK: Signer's compressed public key of size 33 Bytes.
 */
typedef struct{
    unsigned char* sk;
    unsigned char** r ;
    unsigned char* PK;
    unsigned char** R;
}SIGNER_t[0], *SIGNER;

/* Type:        NONCE
 * Purpose:     A type storing the nonce values of signers.
 * Parameters:  R : Char array holding N nonce values of size PK_SIZE.
 */
struct NONCE{
    unsigned char** R;
};

/* Pointer:     AGG_ROUND1
 * Purpose:     Pointer to an object holding the parameters and output of first round signature.
 * Parameters:  PK_LIST:    The list of public keys.
 *              R_LIST:     An array type of NONCE that holds V NONCE.
 *              OUT_R_LIST: The aggregated output of first round.
 *              OUT:        The concatenation of the content of OUT_R_LIST.
 */
typedef struct{
    unsigned char** PK_LIST;
    struct NONCE** R_LIST;
    unsigned char** OUT_R_LIST;
    unsigned char* OUT;
}AGG_ROUND1_t[0], *AGG_ROUND1;

/* Pointer:     PARAM_ROUND2
 * Purpose:     Pointer to an object holding the parameters of the second round signature.
 * Parameters:  X_:         The aggregated public key.
 *              L:          Concatenation of public keys.
 *              b:          Stores H(X_, OUT, msg).
 *              R_state:    Stores the state of second round R = SUM(Rj*b^j).
 */
typedef struct{
    unsigned char* X_;
    unsigned char* L;
    unsigned char* b;
    unsigned char* R_state;
}PARAM_ROUND2_t[0], *PARAM_ROUND2;

/* Pointer:     VER_MUSIG2
 * Purpose:     Pointer to an object holding the parameters of the verification.
 * Parameters:  X:          The aggregated public key.
 *              out:        Concatenation of public keys.
 *              STATE:      Stores the state of second round R = SUM(Rj*b^j).
 */
typedef struct{
    unsigned char* X;
    unsigned char* out;
    unsigned char* STATE;
}VER_MUSIG2_t[0], *VER_MUSIG2;
/*************************************************************************/


/*************************************************************************/
/************************* FUNCTION DECLARATIONS *************************/
/*************************************************************************/
/** Function:       INIT_Signer
 *  Purpose:        Init a signer, set secret (signer->sk) and public (signer->PK) keys.
 *                  sk <- Rand(), PK <- sk*G
 *  Parameters:     IN:     ctx:        secp256k1_context object,
 *                  IN/OUT: signer:     Pointer to object SIGNER.
 */
void INIT_Signer(secp256k1_context* ctx, SIGNER signer);


/** Function:       SIGN_FirstRound
 *  Purpose:        Generate a first round signature and store the values in current signer.
 *                  rj<-Rand(), Rj <- rj*G
 *  Parameters:     IN:     ctx:        secp256k1_context object,
 *                  IN/OUT: signer:     Pointer to object SIGNER.
 */
void SIGN_FirstRound(const secp256k1_context* ctx,SIGNER signer);


/** Function:       COLLECT_Signers
 *  Purpose:        Take the public key and first round of a signer,
 *                  store them in first round aggregation (aggRound1).
 *                  PK_LIST[i] <- pk, R_LIST[j]->R[i] <- Rj
 *  Parameters:     IN:     pk:         Public key of a signer,
 *                          R:          Nonce list of a signer,
 *                          i:          Index of a signer.
 *                  IN/OUT: aggRound1:  Pointer to object AGG_ROUND1.
 */
void COLLECT_Signers(AGG_ROUND1 aggRound1, const unsigned char* pk, unsigned char** x_R, int i);


/** Function:       AGG_SIG_FirstRound
 *  Purpose:        Aggregate the first round signatures.
 *                  OUT_R_LIST[j] <- SUM(R_LIST[j][0], ..., R_LIST[j][N]),
 *                  OUT <- CAT(OUT_R_LIST[0], ..., OUT_R_LIST[V] ).
 *  Parameters:     IN:     ctx:        secp256k1_context object,
 *                  IN/OUT: aggRound1:  Pointer to object AGG_ROUND1.
 */
void AGG_SIG_FirstRound(const secp256k1_context* ctx, AGG_ROUND1 aggRound1);


/** Function:       AGG_Key
 *  Purpose:        Aggregate the public keys of signers, save the aggregate in paramRound2.
 *                  ai <- H(L, PK_LIST[i]), Xi <- ai*PK_LIST[i], X_ <- SUM(Xi).
 *  Parameters:     IN:     ctx:            secp256k1_context object,
 *                  IN/OUT: aggRound1:      Pointer to object AGG_ROUND1.
 *                          paramRound2:    Pointer to object PARAM_ROUND2.
 */
void AGG_Key(const secp256k1_context* ctx, AGG_ROUND1 aggRound1, PARAM_ROUND2 paramRound2);


/** Function:       SET_Param
 *  Purpose:        Set the parameters b and STATE for second round signature.
 *                  b <- H(X_, OUT, msg), STATE <- SUM(OUT_R_LIST[j] * b^(j-1))
 *  Parameters:     IN:     ctx:            secp256k1_context object.
 *                          aggRound1:      Pointer to object AGG_ROUND1.
 *                          msg:            The message to be signed.
 *                  IN/OUT:
 *                          paramRound2:    Pointer to object PARAM_ROUND2.
 */
void SET_Param(const secp256k1_context* ctx, PARAM_ROUND2 paramRound2, AGG_ROUND1 round1, unsigned char* msg);


/** Function:       SIG_SecondRound
 *  Purpose:        Generate the second round signature of given signer for given msg.
 *                  a <- H(L, PK), c <- H(X_,STATE,msg), SIGNATURE <- a*c*sk+[SUM(rj * b^(j-1)]
 *  Parameters:     IN:     ctx:            secp256k1_context object.
 *                          signer:         Pointer to SIGNER object.
 *                          msg:            The message to be signed.
 *                  IN/OUT: paramRound2:    Pointer to object PARAM_ROUND2.
 *                          SIGNATURE:      The signature of a signer.
 */
void SIG_SecondRound(const secp256k1_context* ctx, PARAM_ROUND2 paramRound2, SIGNER signer, unsigned char* SIGNATURE, unsigned char* msg);


/** Function:       AGG_SIG_SecondRound
 *  Purpose:        Aggregate the second round signatures in MUSIG2.
 *                  MUSIG2 <- SUM(SIG_LIST)
 *  Parameters:     IN:     ctx:            secp256k1_context object.
 *                          SIG_LIST:       Pointer to SIGNER object.
 *                  IN/OUT: paramRound2:    Pointer to object PARAM_ROUND2.
 *                          MUSIG2:         Aggregated round 2 signature.
 */
void AGG_SIG_SecondRound(const secp256k1_context* ctx, unsigned char** SIG_LIST, unsigned char* MUSIG2);


/** Function:       VER_Musig2
 *  Purpose:        Verify a musig2 signature, return 1 if musig2 is valid, 0 otherwise.
 *                  c <- H(X_,STATE,msg), RXc <- STATE + X*c, Gs <- out*G, CMP(RXc, Gs)
 *  Parameters:     IN:     ctx:            secp256k1_context object.
 *                          verMusig2:      Pointer to VER_MUSIG2 object.
 *                          msg:            Signed message.
 *  Returns:        0/1.
 */
int VER_Musig2(const secp256k1_context* ctx, VER_MUSIG2 verMusig2, unsigned char* msg);
/*************************************************************************/


/*************************************************************************/
/****************************** HELPERS **********************************/
/*************************************************************************/
void CALC_C(const secp256k1_context* ctx, const unsigned char* X, const unsigned char* STATE, unsigned char* msg, unsigned char* c);

void GEN_L(const unsigned char** PKLIST, unsigned char* L);
/*************************************************************************/
