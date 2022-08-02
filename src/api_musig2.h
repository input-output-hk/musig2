#include "libmusig2.h"

#define N               3 /* Number of signers */

#define NR_MSGS         (const int)2
#define MSG_1           (const unsigned char *) "Musig2 Schnorr MSG 1"
#define MSG_2           (const unsigned char *) "Musig2 Schnorr MSG 2"
#define TAG_1           (const unsigned char *) "MSG_1"
#define TAG_2           (const unsigned char *) "MSG_2"


void musig2_init(musig2_context_sig *mc);

void musig2_agg_R(musig2_context *mc, secp256k1_pubkey *batch_list, int n);
void musig2_sign(musig2_context_sig *mcs, const unsigned char *msg, const unsigned char *tag, int n);
void musig2_init_aggregator(musig2_context_agg *mca, secp256k1_pubkey *pk_list, secp256k1_pubkey *batch_list, int n);
void musig2_aggregate_parsig(musig2_context_agg *mca, unsigned char **parsig_list, const unsigned char *msg, const unsigned char *tag, int n);
void musig2_verify_musig(musig2_context_agg *mca,const unsigned char *msg, const unsigned char *tag );

















