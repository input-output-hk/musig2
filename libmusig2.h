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
#define N               2 /* Number of signers */

/************ DO NOT CHANGE ************/
#define V               2 /* Number of nonce values. Note that V>2 is not working yet. */

#define SK_BYTES        32          /* SCALAR BYTES */
#define SK_SIZE	        ((SK_BYTES)*sizeof(unsigned char))

//#define PK_BYTES        65
//#define PK_SIZE         ((PK_BYTES)*sizeof(unsigned char))


#define NR_MSGS         (const int)2
#define MSG_1           (const unsigned char *) "Multi"
#define MSG_1_LEN       5

#define MSG_2           (const unsigned char *) "Signature"
#define MSG_2_LEN       10

#define TAG_1           (const unsigned char *) "MSG_1"
#define TAG_1_LEN       5

#define TAG_2           (const unsigned char *) "MSG_2"
#define TAG_2_LEN       5
/***************************************/
/*************************************************************************/


void INIT_Signer(secp256k1_context* ctx, secp256k1_keypair* signer);

void CALC_Exponent(const secp256k1_context* ctx, const unsigned char** s_PK_LIST, unsigned char* L, unsigned char** exp_LIST);

void AGG_Key(const secp256k1_context* ctx, secp256k1_pubkey* PK_LIST, unsigned char** exp_LIST, secp256k1_pubkey* X_);

void BATCH_Commitment(const secp256k1_context* ctx, secp256k1_pubkey** COMM_R , unsigned char** nonce_r, int* cnt);

void SIG_Partial(const secp256k1_context* ctx, unsigned char* par_sig, unsigned char* sk, unsigned char* SX, secp256k1_pubkey** COMM_R, unsigned char** s_nonce, unsigned char* sx_NONCE, secp256k1_pubkey* NONCE, unsigned char* exp, unsigned char* msg, int STATE);

void CALC_Nonce(const secp256k1_context* ctx, unsigned char* sx_NONCE,secp256k1_pubkey* NONCE, unsigned char** b_LIST, unsigned char* SX,  secp256k1_pubkey** aggr_COMMS, unsigned char* msg);

void CALC_Challenge(const secp256k1_context* ctx,  const unsigned char* SX,  unsigned char* sx_NONCE,  unsigned char* msg,  unsigned char* c);

void SET_Response(const secp256k1_context* ctx,  unsigned char* resp, unsigned char* c, unsigned char* exp, unsigned char* sk, unsigned char** b_LIST,  unsigned char** s_nonce);

void AGG_SIG_SecondRound(const secp256k1_context* ctx, unsigned char** SIG_LIST, unsigned char* AGGSIG2);

int MAN_VER_SIG(const secp256k1_context* ctx, unsigned char* AGGSIG2, secp256k1_pubkey* NONCE, secp256k1_pubkey* X_, unsigned char* msg);


