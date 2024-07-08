#include "tp-dkg.h"
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>
#include <unistd.h>

// gcc -o tpdkg-msg0 msg0.c -I.. -I../noise_xk/include -I../noise_xk/include/karmel -I../noise_xk/include/karmel/minimal -D_BSD_SOURCE -D_DEFAULT_SOURCE -DWITH_SODIUM -lsodium -loprf

#define tpdkg_freshness_TIMEOUT 10

int main(void) {
  uint8_t n=3, t=2;
  uint8_t peer_lt_pks[crypto_sign_PUBLICKEYBYTES];
  // only known by corresponding peer
  uint8_t peer_lt_sks[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(peer_lt_pks, peer_lt_sks);

  TP_DKG_TPState tp;
  uint8_t msg0[tpdkg_msg0_SIZE];
  int ret = tpdkg_start_tp(&tp, tpdkg_freshness_TIMEOUT, n, t, "proto test", 10, sizeof msg0, (TP_DKG_Message*) &msg0);
  if(0!=ret) return ret;
  write(1, msg0, tpdkg_msg0_SIZE);
  return 0;
}
