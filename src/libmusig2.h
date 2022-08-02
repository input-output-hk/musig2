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

#define V                   2 /* Number of nonce values. Note that V>2 is not working yet. */

#define SCALAR_BYTES       32          // SCALAR BYTES
#define XONLY_BYTES        32          // XONLY PK BYTES
#define PK_BYTES           64          // FULL PK BYTES
#define SCH_SIG_BYTES      64          // FULL PK BYTES


/** Pointer     : Signer
 *  Purpose     : Stores the parameters of a MuSig2 signer.
 *  Parameters  : keypair, the secp256k1_keypair object holding a keypair on secp256k1 curve.
 *              : r_LIST, the list to store V secret nonces of size 32-bytes.
 * */
typedef struct{
    secp256k1_context* ctx;
    secp256k1_pubkey agg_R_list[V];
    secp256k1_xonly_pubkey x_agg_X;
    unsigned char *L;
    int state;
    int par_X;
}musig2_context;

typedef struct {
    musig2_context *mc;
    secp256k1_keypair **commlist;
    secp256k1_keypair keypair;
    unsigned char parsig[SCALAR_BYTES];
    unsigned char a[SCALAR_BYTES];
}musig2_context_sig;


typedef struct {
    musig2_context *mc;
    unsigned char signature[SCH_SIG_BYTES];
    int par_XR;
}musig2_context_agg;

typedef struct{
    unsigned char b[SCALAR_BYTES];
    unsigned char c[SCALAR_BYTES];
    unsigned char *b_LIST[V];
    unsigned char msg_hash[SCALAR_BYTES];
    unsigned char sx_X[SCALAR_BYTES];
    unsigned char sx_R[SCALAR_BYTES];
    int par_R;
}musig_param;



/*************************************************************************/
/************************ FUNCTION DECLARATIONS **************************/
/*************************************************************************/

void musig2_key_gen(musig2_context_sig *mcs);
void musig2_batch_commitment(musig2_context_sig *mcs, int NR_MSGS) ;
void musig2_key_agg_coef(musig2_context *mc, unsigned char *ser_xonly_X, unsigned char *a, unsigned char *L, int n) ;
void musig2_aggregate_pubkey(musig2_context *mc, secp256k1_pubkey *pk_list, int n );


int musig2_calc_b(musig2_context *mc, musig_param *param);
int musig2_calc_R(musig2_context *mc, musig_param *param);
void musig2_calc_c(musig2_context *mc, musig_param *param);
int musig2_set_parsig(musig2_context_sig *mcs, musig_param *param);
int musig2_sign_partial(musig2_context_sig *mcs, musig_param *param, int n);
























