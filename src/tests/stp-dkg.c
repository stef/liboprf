#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "toprf.h"
#include "stp-dkg.h"
#include "dkg.h"
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <unistd.h>
#endif

#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

typedef struct {
  uint8_t index;
  uint8_t value[crypto_core_ristretto255_BYTES];
} __attribute((packed)) TOPRF_Part;

static void topart(TOPRF_Part *r, const TOPRF_Share *s) {
  r->index=s->index;
  crypto_scalarmult_ristretto255_base(r->value, s->value);
}

static void shuffle(uint8_t *array, const size_t n) {
  if (n < 2) return;
  srand(time(NULL));
  for(int i=0; i<n-1; i++) {
    size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
    int t = array[j];
    array[j] = array[i];
    array[i] = t;
  }
}

static int verify_shares(const uint8_t n, const TOPRF_Share shares[n], const uint8_t t) {
  uint8_t responses[t][sizeof(TOPRF_Part)];
  uint8_t v0[crypto_scalarmult_ristretto255_BYTES]={0};

  uint8_t indexes[n];
  for(int i=0;i<n;i++) indexes[i]=i;
  if(log_file!=NULL) {
    fprintf(stderr, "order: ");
    for(int i=0;i<t;i++) fprintf(stderr, "%2d, ",indexes[i]);
  }

  for(int i=0;i<t;i++) {
    topart((TOPRF_Part *) responses[i], &shares[indexes[i]]);
  }
  if(toprf_thresholdmult(t, responses, v0)) return 1;
  dump(v0,sizeof v0, "v0\t");

  for(int k=0;k<t-1;k++) {
    uint8_t v1[crypto_scalarmult_ristretto255_BYTES]={0};
    shuffle(indexes,n);
    if(log_file!=NULL) {
      fprintf(stderr, "order: ");
      for(int i=0;i<t;i++) fprintf(stderr, "%2d, ",indexes[i]);
    }

    for(int i=0;i<t;i++) {
        topart((TOPRF_Part *) responses[i], &shares[indexes[i]]);
    }

    if(toprf_thresholdmult(t, responses, v1)) return 1;
    dump(v1,sizeof v1, "v%d\t", k+1);

    if(memcmp(v0,v1,sizeof v1)!=0) {
        fprintf(stderr,"\e[0;31mfailed to verify shares from dkg_finish!\e[0m\n");
        return 1;
    }
  }
  return 0;
}

// simulate network
#define NETWORK_BUF_SIZE (1024*1024*16)
//static size_t _send(uint8_t *net, size_t *pkt_len, const uint8_t *msg, const size_t msg_len) {
static void _send(uint8_t *net, size_t *pkt_len, const uint8_t *msg, const size_t msg_len) {
  if(*pkt_len+msg_len >= NETWORK_BUF_SIZE || msg_len==0 || msg == NULL) {
    return;// 0;
  }
  memcpy(net+*pkt_len, msg, msg_len);
  *pkt_len+=msg_len;
  //return msg_len;
}
//static size_t _recv(const uint8_t *net, size_t *pkt_len, uint8_t *buf, const size_t msg_len) {
static void _recv(const uint8_t *net, size_t *pkt_len, uint8_t *buf, const size_t msg_len) {
  if(*pkt_len < msg_len || msg_len == 0) {
    return; // 0;
  }
  memcpy(buf, net, msg_len);
  *pkt_len-=msg_len;
  //return msg_len;
}

#ifdef FUZZ_DUMP
#if !defined(FUZZ_PEER)
static void fuzz_dump(const uint8_t step, STP_DKG_STPState *ctx, const uint8_t *buf_in, const size_t buf_in_size, const char **argv, const int argc) {
#else
static void fuzz_dump(const uint8_t step, STP_DKG_PeerState *ctx, const uint8_t *buf_in, const size_t buf_in_size, const char **argv, const int argc) {
#endif //!defined(FUZZ_PEER)
  if(argc<5) {
    fprintf(stderr, "error incorrect number of params, run as: %% %s <n> <t> <step> <output-file>\n", argv[0]);
    exit(1);
  }
  if(ctx->step==step) {
    FILE *tc = fopen(argv[4], "wb");
    fwrite(buf_in, 1, buf_in_size, tc);
    fclose(tc);
    exit(0);
  }
}
#endif

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
#if !defined(FUZZ_PEER)
static int fuzz_loop(const uint8_t step, STP_DKG_STPState *stp, STP_DKG_PeerState *peers, uint8_t network_buf[][NETWORK_BUF_SIZE],size_t pkt_len[]) {
  if(stp->step!=step) return 0;

  STP_DKG_STPState checkpoint;
  memcpy(&checkpoint, stp, sizeof(checkpoint));
  STP_DKG_PeerState pcheckpoints[stp->n];
  memcpy(&pcheckpoints, peers, sizeof(pcheckpoints));

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                             // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!
    if (len < sizeof(DKG_Message)) continue;  // check for a required/useful minimum input length

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t stp_out_size = stpdkg_stp_output_size(stp);
    uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
    if(stp_out_size==0) stp_out = NULL;
    else stp_out = stp_out_buf;

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    int ret = stpdkg_stp_next(stp, buf, len, stp_out, stp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
      if(stp->cheater_len > 0) return 125;
      return ret;
    }

    while(stpdkg_stp_not_done(stp)) {
      for(uint8_t i=0;i<stp->n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=stpdkg_stp_peer_msg(stp, stp_out, stp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }

      while(pkt_len[0]==0 && stpdkg_peer_not_done(&peers[1])) {
        for(uint8_t i=0;i<stp->n;i++) {
          // 0sized vla meh
          const size_t peer_out_size = stpdkg_peer_output_size(&peers[i]);
          uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
          if(peer_out_size==0) peers_out = NULL;
          else peers_out = peers_out_buf;

          // 0sized vla meh for the last time..
          const size_t peer_in_size = stpdkg_peer_input_size(&peers[i]);
          uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
          if(peer_in_size==0) peer_in = NULL;
          else peer_in = peer_in_buf;

          _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
          ret = stpdkg_peer_next(&peers[i],
                                peer_in, peer_in_size,
                                peers_out, peer_out_size);

          if(0!=ret) {
            // clean up peers
            for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
            return ret;
          }

          _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
        }
      }

      // doing vla - but avoiding 0 sized ones is ugly
      const size_t stp_out_size = stpdkg_stp_output_size(stp);
      uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
      if(stp_out_size==0) stp_out = NULL;
      else stp_out = stp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t stp_in_size = stpdkg_stp_input_size(stp);
      uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
      if(stp_in_size==0) stp_in = NULL;
      else stp_in = stp_in_buf;

      _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);

      ret = stpdkg_stp_next(stp, stp_in, stp_in_size, stp_out, stp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
        if(stp->cheater_len > 0) return 55;
        return ret;
      }
    }

    /* Reset state. e.g. libtarget_free(tmp) */
    memcpy(stp, &checkpoint, sizeof(STP_DKG_STPState));
    memcpy(peers, &pcheckpoints, sizeof(pcheckpoints));
  }
  return 0;
}
#else // !defined(FUZZ_PEER)
static int fuzz_loop(const uint8_t step, STP_DKG_STPState *stp, STP_DKG_PeerState *peers, uint8_t network_buf[][NETWORK_BUF_SIZE],size_t pkt_len[]) {
  if(peers[0].step!=step) return 0;

  STP_DKG_STPState checkpoint;
  memcpy(&checkpoint, stp, sizeof(checkpoint));
  STP_DKG_PeerState pcheckpoints[stp->n];
  memcpy(&pcheckpoints, peers, sizeof(pcheckpoints));

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                             // and before __AFL_LOOP!

  int ret;
  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!
    if (len < sizeof(DKG_Message)) continue;  // check for a required/useful minimum input length

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t peer_out_size = stpdkg_peer_output_size(&peers[0]);
    uint8_t peer_out_buf[peer_out_size==0?1:peer_out_size], *peer_out;
    if(peer_out_size==0) peer_out = NULL;
    else peer_out = peer_out_buf;

    ret = stpdkg_peer_next(&peers[0], buf, len, peer_out, peer_out_size);
    if(ret!=0) {
      //for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
      return ret;
    }
    _send(network_buf[0], &pkt_len[0], peer_out, peer_out_size);

    for(uint8_t i=1;i<stp->n;i++) {
      // 0sized vla meh
      const size_t peer_out_size = stpdkg_peer_output_size(&peers[i]);
      uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
      if(peer_out_size==0) peers_out = NULL;
      else peers_out = peers_out_buf;

      // 0sized vla meh for the last time..
      const size_t peer_in_size = stpdkg_peer_input_size(&peers[i]);
      uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
      if(peer_in_size==0) peer_in = NULL;
      else peer_in = peer_in_buf;

      _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
      ret = stpdkg_peer_next(&peers[i],
                            peer_in, peer_in_size,
                            peers_out, peer_out_size);

      if(0!=ret) {
        // clean up peers
        //for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
        return ret;
      }
      _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
    }

    while(stpdkg_stp_not_done(stp)) {
      while(pkt_len[0]==0 && stpdkg_peer_not_done(&peers[1])) {
        for(uint8_t i=0;i<stp->n;i++) {
          // 0sized vla meh
          const size_t peer_out_size = stpdkg_peer_output_size(&peers[i]);
          uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
          if(peer_out_size==0) peers_out = NULL;
          else peers_out = peers_out_buf;

          // 0sized vla meh for the last time..
          const size_t peer_in_size = stpdkg_peer_input_size(&peers[i]);
          uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
          if(peer_in_size==0) peer_in = NULL;
          else peer_in = peer_in_buf;

          _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
          ret = stpdkg_peer_next(&peers[i],
                                peer_in, peer_in_size,
                                peers_out, peer_out_size);

          if(0!=ret) {
            // clean up peers
            //for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
            return ret;
          }

          _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
        }
      }

      // doing vla - but avoiding 0 sized ones is ugly
      const size_t stp_out_size = stpdkg_stp_output_size(stp);
      uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
      if(stp_out_size==0) stp_out = NULL;
      else stp_out = stp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t stp_in_size = stpdkg_stp_input_size(stp);
      uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
      if(stp_in_size==0) stp_in = NULL;
      else stp_in = stp_in_buf;

      _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);

      ret = stpdkg_stp_next(stp, stp_in, stp_in_size, stp_out, stp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<stp->n;i++) stpdkg_peer_free(&peers[i]);
        if(stp->cheater_len > 0) return 55;
        return ret;
      }

      for(uint8_t i=0;i<stp->n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=stpdkg_stp_peer_msg(stp, stp_out, stp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }
    }

    /* Reset state. e.g. libtarget_free(tmp) */
    memcpy(stp, &checkpoint, sizeof(STP_DKG_STPState));
    memcpy(peers, &pcheckpoints, sizeof(pcheckpoints));
  }
  return 0;
}
#endif
#endif

int main(const int argc, const char **argv) {
  int ret;
  // enable logging
  log_file = stderr;
  debug = 1;

  if(argc<3) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t> [<step> [<path>]]\n", argv[0]);
#else
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t>\n", argv[0]);
#endif // defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    exit(1);
  }
  uint8_t n=atoi(argv[1]),t=atoi(argv[2]);
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
  uint8_t step=atoi(argv[3]);
#ifdef FUZZ_PEER
  if(step<1 || step > 9 || step==7 || step==8) {
#else
  if(step<1 || step > 9) {
#endif
    fprintf(stderr, "error incorrect value for step must be 1-9 (but not 7 or 8), run as: %% %s <1-7> <output-file>\n", argv[0]);
    exit(1);
  }
#endif

  // mock long-term peer keys
  // known by everyone
  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t lt_sks[n+1][crypto_sign_SECRETKEYBYTES];
  for(uint8_t i=0;i<n+1;i++) {
      crypto_sign_keypair(lt_pks[i], lt_sks[i]);
  }

  STP_DKG_STPState stp;
  uint8_t msg0[stpdkg_msg0_SIZE];
  ret = stpdkg_start_stp(&stp, dkg_freshness_TIMEOUT,
                         n, t,
                         "proto test", 10,
                         &lt_pks, lt_sks[0],
                         sizeof msg0, (DKG_Message*) msg0);
  if(0!=ret) return ret;

  fprintf(stderr, "allocating memory for STP\n");
  // set bufs
  // we need to store these outside of the ctx, since they are
  // variable size, and the struct can only handle one variable size
  // entry...
  // stp needs to store the commitments
  uint8_t stp_commitments[n*t][crypto_core_ristretto255_BYTES];
  memset(stp_commitments,0,sizeof(stp_commitments));
  // stp needs to store the complaints, with max n==128 this takes max 16KB of ram.
  uint16_t stp_complaints[n*n];
  memset(stp_complaints,0,sizeof(stp_complaints));
  uint8_t noisy_shares[n*n][stpdkg_msg10_SIZE];
  memset(noisy_shares,0,sizeof(noisy_shares));
  STP_DKG_Cheater cheaters[t*t - 1];
  memset(cheaters,0,sizeof(cheaters));
  uint64_t last_ts[n];
  stpdkg_stp_set_bufs(&stp, &stp_commitments,
                      &stp_complaints, &noisy_shares,
                      &cheaters, sizeof(cheaters) / sizeof(STP_DKG_Cheater), last_ts);

  // only stp_out can survive for the peers in local scope of the "main protocol loop"
  // and thus we simulate a network with this buffer

  STP_DKG_PeerState peers[n];
  for(uint8_t i=0;i<n;i++) {
    ret = stpdkg_start_peer(&peers[i], dkg_freshness_TIMEOUT, &lt_pks, lt_sks[i+1], (DKG_Message*) msg0);
    if(0!=ret) return ret;
  }

  fprintf(stderr, "allocating memory for peers ..");
  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  uint8_t peers_noise_pks[peers[1].n][crypto_scalarmult_BYTES];
  Noise_XK_session_t *noise_outs[n][n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n][n];
  memset(noise_ins, 0, sizeof noise_ins);
  TOPRF_Share ishares[peers[1].n][peers[1].n];
  memset(ishares, 0, sizeof ishares);
  TOPRF_Share xshares[peers[1].n][peers[1].n];
  memset(xshares, 0, sizeof xshares);
  uint8_t commitment_hashes[peers[1].n][stpdkg_commitment_HASHBYTES];
  uint8_t commitments[peers[1].n][peers[1].n *peers[1].t][crypto_core_ristretto255_BYTES];
  memset(commitments, 0, sizeof commitments);
  uint16_t peer_complaints[peers[1].n][peers[1].n*peers[1].n];
  memset(peer_complaints, 0, sizeof peer_complaints);
  uint8_t peer_my_complaints[peers[1].n][peers[1].n];
  memset(peer_my_complaints, 0, sizeof peer_my_complaints);
  uint64_t peer_last_ts[n][n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  fprintf(stderr, " done\n");

  for(uint8_t i=0;i<n;i++) {
    // in a real deployment peers do not share the same pks buffers
    stpdkg_peer_set_bufs(&peers[i], &lt_pks, &peers_noise_pks,
                        &noise_outs[i], &noise_ins[i],
                        &ishares[i], &xshares[i],
                        &commitment_hashes,
                        &commitments[i],
                        peer_complaints[i], peer_my_complaints[i],
                        peer_last_ts[i]);
  }


  // simulate network.
  uint8_t network_buf[n+1][NETWORK_BUF_SIZE];
  size_t pkt_len[n+1];
  memset(pkt_len,0,sizeof pkt_len);

  // this is the mainloop - normally only one stp or one peer, but here
  // for demo purposes mixed.
  // end condition for peers is stpdkg_peer_not_done(&peer)
  while(stpdkg_stp_not_done(&stp)) {

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t stp_out_size = stpdkg_stp_output_size(&stp);
    uint8_t stp_out_buf[stp_out_size==0?1:stp_out_size], *stp_out;
    if(stp_out_size==0) stp_out = NULL;
    else stp_out = stp_out_buf;

    // avoiding zero-sized vla is still ugly
    const size_t stp_in_size = stpdkg_stp_input_size(&stp);
    uint8_t stp_in_buf[stp_in_size==0?1:stp_in_size], *stp_in;
    if(stp_in_size==0) stp_in = NULL;
    else stp_in = stp_in_buf;

    _recv(network_buf[0], &pkt_len[0], stp_in, stp_in_size);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(FUZZ_PEER)
    ret = fuzz_loop(step, &stp, peers, network_buf, pkt_len);
    if(0!=ret) return ret;
#endif
#if defined(FUZZ_DUMP) && !defined(FUZZ_PEER)
    fuzz_dump(step, &stp, stp_in, stp_in_size, argv, argc);
#endif

    ret = stpdkg_stp_next(&stp, stp_in, stp_in_size, stp_out, stp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<n;i++) stpdkg_peer_free(&peers[i]);
      if(stp.cheater_len > 0) break;
      return ret;
    }

    for(uint8_t i=0;i<stp.n;i++) {
      const uint8_t *msg;
      size_t len;
      if(0!=stpdkg_stp_peer_msg(&stp, stp_out, stp_out_size, i, &msg, &len)) {
        return 1;
      }
      _send(network_buf[i+1], &pkt_len[i+1], msg, len);
    }

    while(pkt_len[0]==0 && stpdkg_peer_not_done(&peers[1])) {
      for(uint8_t i=0;i<n;i++) {
        // 0sized vla meh
        const size_t peer_out_size = stpdkg_peer_output_size(&peers[i]);
        uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
        if(peer_out_size==0) peers_out = NULL;
        else peers_out = peers_out_buf;

        // 0sized vla meh for the last time..
        const size_t peer_in_size = stpdkg_peer_input_size(&peers[i]);
        uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
        if(peer_in_size==0) peer_in = NULL;
        else peer_in = peer_in_buf;

        _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);

#if defined(FUZZ_DUMP) && defined(FUZZ_PEER)
        if(i==0) fuzz_dump(step, &peers[i], peer_in, peer_in_size, argv, argc);
#endif
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && defined(FUZZ_PEER)
        ret = fuzz_loop(step, &stp, peers, network_buf, pkt_len);
        if(0!=ret) return ret;
#endif
        ret = stpdkg_peer_next(&peers[i],
                              peer_in, peer_in_size,
                              peers_out, peer_out_size);

        if(0!=ret) {
          // clean up peers
          for(uint8_t i=0;i<n;i++) stpdkg_peer_free(&peers[i]);
          return ret;
        }

        _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
      }
    }
  }

  // we are done. let's check the shares...
  TOPRF_Share shares[n];
  if(stp.cheater_len == 0) {
    for(uint8_t i=0;i<n;i++) {
      memcpy(&shares[i], (uint8_t*) &peers[i].share, sizeof(TOPRF_Share));
      dump((uint8_t*) &shares[i], sizeof(TOPRF_Share), "share[%d]", i+1);
    }

    if(0!=verify_shares(n, shares, t)) {
        fprintf(stderr, "verify_shares failed\n");
        return 1;
    }
  } else {
    int total_cheaters=0;
    uint8_t tmp[n+1];
    memset(tmp,0,n+1);
    for(int i=0;i<stp.cheater_len;i++) {
      char err[dkg_max_err_SIZE];
      uint8_t p = stpdkg_cheater_msg(&(*stp.cheaters)[i], err, sizeof(err));
      fprintf(stderr,"\e[0;31m%s\e[0m\n", err);
      if(p > n) return 1;
      if(tmp[p]==0) total_cheaters++;
      tmp[p]++;
    }
    fprintf(stderr, "\e[0;31m:/ dkg failed, total cheaters %d, list of cheaters:", total_cheaters);
    for(int i=1;i<=n;i++) {
      if(tmp[i]==0) continue;
      fprintf(stderr," %d(%d)", i, tmp[i]);
    }
    fprintf(stderr, "\e[0m\n");
    return 1;
  }

  // clean up peers
  for(uint8_t i=0;i<n;i++) stpdkg_peer_free(&peers[i]);

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");
  return 0;
}
