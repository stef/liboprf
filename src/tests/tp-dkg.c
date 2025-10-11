#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "toprf.h"
#include "tp-dkg.h"
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
  srand((unsigned) time(NULL));
  for(unsigned i=0; i<n-1; i++) {
    size_t j = i + (unsigned)rand() / ((unsigned)RAND_MAX / (n - i) + 1U);
    uint8_t t = array[j];
    array[j] = array[i];
    array[i] = t;
  }
}

static int verify_shares(const uint8_t n, const TOPRF_Share shares[n], const uint8_t t) {
  uint8_t responses[t][sizeof(TOPRF_Part)];
  uint8_t v0[crypto_scalarmult_ristretto255_BYTES]={0};

  uint8_t indexes[n];
  for(uint8_t i=0;i<n;i++) indexes[i]=i;
  if(liboprf_log_file!=NULL) {
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
    if(liboprf_log_file!=NULL) {
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
static void fuzz_dump(const uint8_t step, TP_DKG_TPState *ctx, const uint8_t *buf_in, const size_t buf_in_size, const char **argv, const int argc) {
#else
static void fuzz_dump(const uint8_t step, TP_DKG_PeerState *ctx, const uint8_t *buf_in, const size_t buf_in_size, const char **argv, const int argc) {
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
static int fuzz_loop(const uint8_t step, TP_DKG_TPState *tp, TP_DKG_PeerState *peers, uint8_t network_buf[][NETWORK_BUF_SIZE],size_t pkt_len[]) {
  if(tp->step!=step) return 0;

  TP_DKG_TPState checkpoint;
  memcpy(&checkpoint, tp, sizeof(checkpoint));
  TP_DKG_PeerState pcheckpoints[tp->n];
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
    const size_t tp_out_size = tpdkg_tp_output_size(tp);
    uint8_t tp_out_buf[tp_out_size==0?1:tp_out_size], *tp_out;
    if(tp_out_size==0) tp_out = NULL;
    else tp_out = tp_out_buf;

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    int ret = tpdkg_tp_next(tp, buf, len, tp_out, tp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
      if(tp->cheater_len > 0) return 125;
      return ret;
    }

    while(tpdkg_tp_not_done(tp)) {
      for(uint8_t i=0;i<tp->n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=tpdkg_tp_peer_msg(tp, tp_out, tp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }

      while(pkt_len[0]==0 && tpdkg_peer_not_done(&peers[1])) {
        for(uint8_t i=0;i<tp->n;i++) {
          // 0sized vla meh
          const size_t peer_out_size = tpdkg_peer_output_size(&peers[i]);
          uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
          if(peer_out_size==0) peers_out = NULL;
          else peers_out = peers_out_buf;

          // 0sized vla meh for the last time..
          const size_t peer_in_size = tpdkg_peer_input_size(&peers[i]);
          uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
          if(peer_in_size==0) peer_in = NULL;
          else peer_in = peer_in_buf;

          _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
          ret = tpdkg_peer_next(&peers[i],
                                peer_in, peer_in_size,
                                peers_out, peer_out_size);

          if(0!=ret) {
            // clean up peers
            for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
            return ret;
          }

          _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
        }
      }

      // doing vla - but avoiding 0 sized ones is ugly
      const size_t tp_out_size = tpdkg_tp_output_size(tp);
      uint8_t tp_out_buf[tp_out_size==0?1:tp_out_size], *tp_out;
      if(tp_out_size==0) tp_out = NULL;
      else tp_out = tp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t tp_in_size = tpdkg_tp_input_size(tp);
      uint8_t tp_in_buf[tp_in_size==0?1:tp_in_size], *tp_in;
      if(tp_in_size==0) tp_in = NULL;
      else tp_in = tp_in_buf;

      _recv(network_buf[0], &pkt_len[0], tp_in, tp_in_size);

      ret = tpdkg_tp_next(tp, tp_in, tp_in_size, tp_out, tp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
        if(tp->cheater_len > 0) return 55;
        return ret;
      }
    }

    /* Reset state. e.g. libtarget_free(tmp) */
    memcpy(tp, &checkpoint, sizeof(TP_DKG_TPState));
    memcpy(peers, &pcheckpoints, sizeof(pcheckpoints));
  }
  return 0;
}
#else // !defined(FUZZ_PEER)
static int fuzz_loop(const uint8_t step, TP_DKG_TPState *tp, TP_DKG_PeerState *peers, uint8_t network_buf[][NETWORK_BUF_SIZE],size_t pkt_len[]) {
  if(peers[0].step!=step) return 0;

  TP_DKG_TPState checkpoint;
  memcpy(&checkpoint, tp, sizeof(checkpoint));
  TP_DKG_PeerState pcheckpoints[tp->n];
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
    const size_t peer_out_size = tpdkg_peer_output_size(&peers[0]);
    uint8_t peer_out_buf[peer_out_size==0?1:peer_out_size], *peer_out;
    if(peer_out_size==0) peer_out = NULL;
    else peer_out = peer_out_buf;

    ret = tpdkg_peer_next(&peers[0], buf, len, peer_out, peer_out_size);
    if(ret!=0) {
      //for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
      return ret;
    }
    _send(network_buf[0], &pkt_len[0], peer_out, peer_out_size);

    for(uint8_t i=1;i<tp->n;i++) {
      // 0sized vla meh
      const size_t peer_out_size = tpdkg_peer_output_size(&peers[i]);
      uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
      if(peer_out_size==0) peers_out = NULL;
      else peers_out = peers_out_buf;

      // 0sized vla meh for the last time..
      const size_t peer_in_size = tpdkg_peer_input_size(&peers[i]);
      uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
      if(peer_in_size==0) peer_in = NULL;
      else peer_in = peer_in_buf;

      _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
      ret = tpdkg_peer_next(&peers[i],
                            peer_in, peer_in_size,
                            peers_out, peer_out_size);

      if(0!=ret) {
        // clean up peers
        //for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
        return ret;
      }
      _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
    }

    while(tpdkg_tp_not_done(tp)) {
      while(pkt_len[0]==0 && tpdkg_peer_not_done(&peers[1])) {
        for(uint8_t i=0;i<tp->n;i++) {
          // 0sized vla meh
          const size_t peer_out_size = tpdkg_peer_output_size(&peers[i]);
          uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
          if(peer_out_size==0) peers_out = NULL;
          else peers_out = peers_out_buf;

          // 0sized vla meh for the last time..
          const size_t peer_in_size = tpdkg_peer_input_size(&peers[i]);
          uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
          if(peer_in_size==0) peer_in = NULL;
          else peer_in = peer_in_buf;

          _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);
          ret = tpdkg_peer_next(&peers[i],
                                peer_in, peer_in_size,
                                peers_out, peer_out_size);

          if(0!=ret) {
            // clean up peers
            //for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
            return ret;
          }

          _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
        }
      }

      // doing vla - but avoiding 0 sized ones is ugly
      const size_t tp_out_size = tpdkg_tp_output_size(tp);
      uint8_t tp_out_buf[tp_out_size==0?1:tp_out_size], *tp_out;
      if(tp_out_size==0) tp_out = NULL;
      else tp_out = tp_out_buf;

      // avoiding zero-sized vla is still ugly
      const size_t tp_in_size = tpdkg_tp_input_size(tp);
      uint8_t tp_in_buf[tp_in_size==0?1:tp_in_size], *tp_in;
      if(tp_in_size==0) tp_in = NULL;
      else tp_in = tp_in_buf;

      _recv(network_buf[0], &pkt_len[0], tp_in, tp_in_size);

      ret = tpdkg_tp_next(tp, tp_in, tp_in_size, tp_out, tp_out_size);
      if(0!=ret) {
        // clean up peers
        for(uint8_t i=0;i<tp->n;i++) tpdkg_peer_free(&peers[i]);
        if(tp->cheater_len > 0) return 55;
        return ret;
      }

      for(uint8_t i=0;i<tp->n;i++) {
        const uint8_t *msg;
        size_t len;
        if(0!=tpdkg_tp_peer_msg(tp, tp_out, tp_out_size, i, &msg, &len)) {
          return 1;
        }
        _send(network_buf[i+1], &pkt_len[i+1], msg, len);
      }
    }

    /* Reset state. e.g. libtarget_free(tmp) */
    memcpy(tp, &checkpoint, sizeof(TP_DKG_TPState));
    memcpy(peers, &pcheckpoints, sizeof(pcheckpoints));
  }
  return 0;
}
#endif
#endif

int main(const int argc, const char **argv) {
  int ret;
  // enable logging
  liboprf_log_file = stderr;
  liboprf_debug = 1;

  if(argc<3) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t> [<step> [<path>]]\n", argv[0]);
#else
    fprintf(stderr, "error incorrect numbers of parameters, run as: %% %s <n> <t>\n", argv[0]);
#endif // defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(FUZZ_DUMP)
    exit(1);
  }
  uint8_t n=(uint8_t)atoi(argv[1]),t=(uint8_t)atoi(argv[2]);
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
  // all known by TP
  uint8_t peer_lt_pks[n][crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t peer_lt_sks[n][crypto_sign_SECRETKEYBYTES];
  for(uint8_t i=0;i<n;i++) {
      crypto_sign_keypair(peer_lt_pks[i], peer_lt_sks[i]);
  }

  TP_DKG_TPState tp;
  uint8_t msg0[tpdkg_msg0_SIZE];
  ret = tpdkg_start_tp(&tp, dkg_freshness_TIMEOUT, n, t, "proto test", 10, sizeof msg0, (DKG_Message*) msg0);
  if(0!=ret) return ret;

  fprintf(stderr, "allocating memory for TP\n");
  // set bufs
  // we need to store these outside of the ctx, since they are
  // variable size, and the struct can only handle one variable size
  // entry...
  uint8_t tp_peers_sig_pks[n][crypto_sign_PUBLICKEYBYTES];
  memset(tp_peers_sig_pks,0,sizeof(tp_peers_sig_pks));
  // tp needs to store the commitments
  uint8_t tp_commitments[n*t][crypto_core_ristretto255_BYTES];
  memset(tp_commitments,0,sizeof(tp_commitments));
  // tp needs to store the complaints, with max n==128 this takes max 16KB of ram.
  uint16_t tp_complaints[n*n];
  memset(tp_complaints,0,sizeof(tp_complaints));
  uint8_t noisy_shares[n*n][tpdkg_msg8_SIZE];
  memset(noisy_shares,0,sizeof(noisy_shares));
  TP_DKG_Cheater cheaters[t*t - 1];
  memset(cheaters,0,sizeof(cheaters));
  uint64_t last_ts[n];
  tpdkg_tp_set_bufs(&tp, &tp_commitments, &tp_complaints, &noisy_shares, &cheaters, sizeof(cheaters) / sizeof(TP_DKG_Cheater), &tp_peers_sig_pks, &peer_lt_pks, last_ts);

  // only tp_out can survive for the peers in local scope of the "main protocol loop"
  // and thus we simulate a network with this buffer

  TP_DKG_PeerState peers[n];
  for(uint8_t i=0;i<n;i++) {
    ret = tpdkg_start_peer(&peers[i], dkg_freshness_TIMEOUT, peer_lt_sks[i], (DKG_Message*) msg0);
    if(0!=ret) return ret;
  }

  fprintf(stderr, "allocating memory for peers ..");
  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  uint8_t peers_sig_pks[peers[1].n][crypto_sign_PUBLICKEYBYTES];
  memset(peers_sig_pks, 0, sizeof(peers_sig_pks));
  uint8_t peers_noise_pks[peers[1].n][crypto_scalarmult_BYTES];
  Noise_XK_session_t *noise_outs[n][n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n][n];
  memset(noise_ins, 0, sizeof noise_ins);
  TOPRF_Share ishares[peers[1].n][peers[1].n];
  memset(ishares, 0, sizeof ishares);
  TOPRF_Share xshares[peers[1].n][peers[1].n];
  memset(xshares, 0, sizeof xshares);
  uint8_t commitments[peers[1].n][peers[1].n *peers[1].t][crypto_core_ristretto255_BYTES];
  memset(commitments, 0, sizeof commitments);
  uint16_t peer_complaints[peers[1].n][peers[1].n*peers[1].n];
  memset(peer_complaints, 0, sizeof peer_complaints);
  uint8_t peer_my_complaints[peers[1].n][peers[1].n];
  memset(peer_my_complaints, 0, sizeof peer_my_complaints);
  uint64_t peer_last_ts[n][n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  fprintf(stderr, "done\n");

  for(uint8_t i=0;i<n;i++) {
    // in a real deployment peers do not share the same pks buffers
    tpdkg_peer_set_bufs(&peers[i], &peers_sig_pks, &peers_noise_pks,
                        &noise_outs[i], &noise_ins[i],
                        &ishares[i], &xshares[i],
                        &commitments[i],
                        peer_complaints[i], peer_my_complaints[i],
                        peer_last_ts[i]);
  }


  // simulate network.
  uint8_t network_buf[n+1][NETWORK_BUF_SIZE];
  size_t pkt_len[n+1];
  memset(pkt_len,0,sizeof pkt_len);

  // this is the mainloop - normally only one tp or one peer, but here
  // for demo purposes mixed.
  // end condition for peers is tpdkg_peer_not_done(&peer)
  while(tpdkg_tp_not_done(&tp)) {

    // doing vla - but avoiding 0 sized ones is ugly
    const size_t tp_out_size = tpdkg_tp_output_size(&tp);
    uint8_t tp_out_buf[tp_out_size==0?1:tp_out_size], *tp_out;
    if(tp_out_size==0) tp_out = NULL;
    else tp_out = tp_out_buf;

    // avoiding zero-sized vla is still ugly
    const size_t tp_in_size = tpdkg_tp_input_size(&tp);
    uint8_t tp_in_buf[tp_in_size==0?1:tp_in_size], *tp_in;
    if(tp_in_size==0) tp_in = NULL;
    else tp_in = tp_in_buf;

    _recv(network_buf[0], &pkt_len[0], tp_in, tp_in_size);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(FUZZ_PEER)
    ret = fuzz_loop(step, &tp, peers, network_buf, pkt_len);
    if(0!=ret) return ret;
#endif
#if defined(FUZZ_DUMP) && !defined(FUZZ_PEER)
    fuzz_dump(step, &tp, tp_in, tp_in_size, argv, argc);
#endif

    ret = tpdkg_tp_next(&tp, tp_in, tp_in_size, tp_out, tp_out_size);
    if(0!=ret) {
      // clean up peers
      for(uint8_t i=0;i<n;i++) tpdkg_peer_free(&peers[i]);
      if(tp.cheater_len > 0) break;
      return ret;
    }

    for(uint8_t i=0;i<tp.n;i++) {
      const uint8_t *msg;
      size_t len;
      if(0!=tpdkg_tp_peer_msg(&tp, tp_out, tp_out_size, i, &msg, &len)) {
        return 1;
      }
      _send(network_buf[i+1], &pkt_len[i+1], msg, len);
    }

    while(pkt_len[0]==0 && tpdkg_peer_not_done(&peers[1])) {
      for(uint8_t i=0;i<n;i++) {
        // 0sized vla meh
        const size_t peer_out_size = tpdkg_peer_output_size(&peers[i]);
        uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
        if(peer_out_size==0) peers_out = NULL;
        else peers_out = peers_out_buf;

        // 0sized vla meh for the last time..
        const size_t peer_in_size = tpdkg_peer_input_size(&peers[i]);
        uint8_t peer_in_buf[peer_in_size==0?1:peer_in_size], *peer_in;
        if(peer_in_size==0) peer_in = NULL;
        else peer_in = peer_in_buf;

        _recv(network_buf[i+1], &pkt_len[i+1], peer_in, peer_in_size);

#if defined(FUZZ_DUMP) && defined(FUZZ_PEER)
        if(i==0) fuzz_dump(step, &peers[i], peer_in, peer_in_size, argv, argc);
#endif
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && defined(FUZZ_PEER)
        ret = fuzz_loop(step, &tp, peers, network_buf, pkt_len);
        if(0!=ret) return ret;
#endif
        ret = tpdkg_peer_next(&peers[i],
                              peer_in, peer_in_size,
                              peers_out, peer_out_size);

        if(0!=ret) {
          // clean up peers
          for(uint8_t i=0;i<n;i++) tpdkg_peer_free(&peers[i]);
          return ret;
        }

        _send(network_buf[0], &pkt_len[0], peers_out, peer_out_size);
      }
    }
  }

  // we are done. let's check the shares...
  TOPRF_Share shares[n];
  if(tp.cheater_len == 0) {
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
    for(int i=0;i<tp.cheater_len;i++) {
      char err[dkg_max_err_SIZE];
      uint8_t p = tpdkg_cheater_msg(&(*tp.cheaters)[i], err, sizeof(err));
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
  for(uint8_t i=0;i<n;i++) tpdkg_peer_free(&peers[i]);

  fprintf(stderr, "\e[0;32meverything correct!\e[0m\n");
  return 0;
}
