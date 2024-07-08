#include <stdint.h>
#include <unistd.h>
#include "tp-dkg.h"

// afl-clang-fast -o peer-start peer-start.c -I../.. -I../../noise_xk/include -I../../noise_xk/include/karmel -I../../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf

__AFL_FUZZ_INIT();

int main() {

  // anything else here, e.g. command line arguments, initialization, etc.
  uint8_t peer_lt_sks[32]={250};
  TP_DKG_PeerState peer;

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

    if (len < sizeof(TP_DKG_Message)) continue;  // check for a required/useful minimum input length

    /* Setup function call, e.g. struct target *tmp = libtarget_init() */
    /* Call function to be fuzzed, e.g.: */
    tpdkg_start_peer(&peer, 10, peer_lt_sks, (TP_DKG_Message*) buf);

    /* Reset state. e.g. libtarget_free(tmp) */
  }

  return 0;

}
