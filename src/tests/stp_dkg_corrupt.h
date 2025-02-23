#ifndef STP_DKG_CORRUPT_H
#define STP_DKG_CORRUPT_H

#include "stp-dkg.h"

void corrupt_vsps_p1t1(STP_DKG_PeerState *ctx);
void corrupt_commitment_p2(STP_DKG_PeerState *ctx);
void corrupt_wrongshare_correct_commitment_p3(STP_DKG_PeerState *ctx);
void corrupt_share_p4(STP_DKG_PeerState *ctx);
void corrupt_false_accuse_p2p3(STP_DKG_PeerState *ctx, uint8_t *fails_len, uint8_t *fails);

#endif // STP_DKG_CORRUPT_H
