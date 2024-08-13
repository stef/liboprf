#ifndef noise_xk_private_h
#define noise_xk_private_h
#include <stdint.h>
#include "XK.h"

#undef Noise_XK_init_state_t_s
typedef struct Noise_XK_init_state_t_s {
  Noise_XK_init_state_t_tags tag;
  union {
    struct {
      uint32_t step;
      uint8_t *cipher_key;
      uint8_t *chaining_key;
      uint8_t *h;
      uint8_t *spriv;
      uint8_t *spub;
      uint8_t *epriv;
      uint8_t *epub;
      uint8_t *rs;
      uint8_t *re;
    } case_IMS_Handshake;
    struct {
      uint8_t *h;
      bool recv_transport_message;
      uint8_t *send_key;
      uint64_t send_nonce;
      uint8_t *receive_key;
      uint64_t receive_nonce;
    } case_IMS_Transport;
  } val;
} Noise_XK_init_state_t;

#undef Noise_XK_resp_state_t_s
typedef struct Noise_XK_resp_state_t_s {
  Noise_XK_init_state_t_tags tag;
  union {
    struct {
      uint32_t step;
      uint8_t *cipher_key;
      uint8_t *chaining_key;
      uint8_t *h;
      uint8_t *spriv;
      uint8_t *spub;
      uint8_t *epriv;
      uint8_t *epub;
      uint8_t *rs;
      uint8_t *re;
    } case_IMS_Handshake;
    struct {
      uint8_t *h;
      uint8_t *send_key;
      uint64_t send_nonce;
      uint8_t *receive_key;
      uint64_t receive_nonce;
    } case_IMS_Transport;
  } val;
} Noise_XK_resp_state_t;

#undef Noise_XK_session_t_s
typedef struct Noise_XK_session_t_s {
  Noise_XK_session_t_tags tag;
  union {
    struct {
      Noise_XK_init_state_t state;
      uint32_t id;
      Noise_XK_noise_string *info;
      uint8_t *spriv;
      uint8_t *spub;
      uint32_t pid;
      Noise_XK_noise_string *pinfo;
      Noise_XK_device_t *dv;
    } case_DS_Initiator;
    struct {
      Noise_XK_resp_state_t state;
      uint32_t id;
      Noise_XK_noise_string *info;
      uint8_t *spriv;
      uint8_t *spub;
      uint32_t pid;
      Noise_XK_noise_string *pinfo;
      Noise_XK_device_t *dv;
    } case_DS_Responder;
  } val;
} Noise_XK_session_t;

#endif // noise_xk_private_h
