/** This file was automatically generated */


#include "XK.h"

bool Noise_XK_uu___is_Success(Noise_XK_rcode projectee)
{
  if (projectee.tag == Noise_XK_Success)
    return true;
  else
    return false;
}

bool Noise_XK_uu___is_Error(Noise_XK_rcode projectee)
{
  if (projectee.tag == Noise_XK_Error)
    return true;
  else
    return false;
}

Noise_XK_error_code Noise_XK___proj__Error__item___0(Noise_XK_rcode projectee)
{
  if (projectee.tag == Noise_XK_Error)
    return projectee.val.case_Error;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

bool Noise_XK_uu___is_Stuck(Noise_XK_rcode projectee)
{
  if (projectee.tag == Noise_XK_Stuck)
    return true;
  else
    return false;
}

Noise_XK_error_code Noise_XK___proj__Stuck__item___0(Noise_XK_rcode projectee)
{
  if (projectee.tag == Noise_XK_Stuck)
    return projectee.val.case_Stuck;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

bool Noise_XK_uu___is_Auth_level(Noise_XK_ac_level_t projectee)
{
  if (projectee.tag == Noise_XK_Auth_level)
    return true;
  else
    return false;
}

uint8_t Noise_XK___proj__Auth_level__item__l(Noise_XK_ac_level_t projectee)
{
  if (projectee.tag == Noise_XK_Auth_level)
    return projectee.val.case_Auth_level;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

bool Noise_XK_uu___is_Conf_level(Noise_XK_ac_level_t projectee)
{
  if (projectee.tag == Noise_XK_Conf_level)
    return true;
  else
    return false;
}

uint8_t Noise_XK___proj__Conf_level__item__l(Noise_XK_ac_level_t projectee)
{
  if (projectee.tag == Noise_XK_Conf_level)
    return projectee.val.case_Conf_level;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

bool Noise_XK_uu___is_No_level(Noise_XK_ac_level_t projectee)
{
  if (projectee.tag == Noise_XK_No_level)
    return true;
  else
    return false;
}

typedef struct Noise_XK_encap_message_t_s
{
  Noise_XK_ac_level_t em_ac_level;
  uint32_t em_message_len;
  uint8_t *em_message;
}
Noise_XK_encap_message_t;

Noise_XK_encap_message_t
*Noise_XK___proj__Mkencap_message_p_or_null__item__emp(Noise_XK_encap_message_t *projectee)
{
  return projectee;
}

bool Noise_XK_encap_message_p_is_null(Noise_XK_encap_message_t *emp)
{
  return emp == NULL;
}

void Noise_XK_encap_message_p_free(Noise_XK_encap_message_t *emp)
{
  Noise_XK_encap_message_t em = emp[0U];
  if (!(em.em_message == NULL))
    KRML_HOST_FREE(em.em_message);
  KRML_HOST_FREE(emp);
}

Noise_XK_encap_message_t
*Noise_XK_pack_message_with_conf_level(
  uint8_t requested_conf_level,
  uint32_t msg_len,
  uint8_t *msg
)
{
  uint8_t *msg_;
  if (msg_len > (uint32_t)0U)
  {
    KRML_CHECK_SIZE(sizeof (uint8_t), msg_len);
    uint8_t *o = KRML_HOST_CALLOC(msg_len, sizeof (uint8_t));
    memcpy(o, msg, msg_len * sizeof (uint8_t));
    msg_ = o;
  }
  else
    msg_ = NULL;
  KRML_CHECK_SIZE(sizeof (Noise_XK_encap_message_t), (uint32_t)1U);
  Noise_XK_encap_message_t *emp_p = KRML_HOST_MALLOC(sizeof (Noise_XK_encap_message_t));
  emp_p[0U]
  =
    (
      (Noise_XK_encap_message_t){
        .em_ac_level = {
          .tag = Noise_XK_Conf_level,
          .val = { .case_Conf_level = requested_conf_level }
        },
        .em_message_len = msg_len,
        .em_message = msg_
      }
    );
  return emp_p;
}

Noise_XK_encap_message_t *Noise_XK_pack_message(uint32_t msg_len, uint8_t *msg)
{
  return Noise_XK_pack_message_with_conf_level(NOISE_XK_MAX_CONF_LEVEL, msg_len, msg);
}

bool
Noise_XK_unpack_message_with_auth_level(
  uint32_t *out_msg_len,
  uint8_t **out_msg,
  uint8_t requested_auth_level,
  Noise_XK_encap_message_t *emp
)
{
  Noise_XK_encap_message_t em = emp[0U];
  bool ok;
  if (em.em_message_len == (uint32_t)0U)
    ok = true;
  else if (em.em_ac_level.tag == Noise_XK_Auth_level)
  {
    uint8_t l = em.em_ac_level.val.case_Auth_level;
    ok = l >= requested_auth_level;
  }
  else
    ok = false;
  if (ok)
  {
    uint8_t *msg;
    if (em.em_message_len > (uint32_t)0U)
    {
      KRML_CHECK_SIZE(sizeof (uint8_t), em.em_message_len);
      uint8_t *o = KRML_HOST_CALLOC(em.em_message_len, sizeof (uint8_t));
      memcpy(o, em.em_message, em.em_message_len * sizeof (uint8_t));
      msg = o;
    }
    else
      msg = NULL;
    out_msg_len[0U] = em.em_message_len;
    out_msg[0U] = msg;
    return true;
  }
  else
  {
    out_msg[0U] = NULL;
    return false;
  }
}

bool
Noise_XK_unpack_message(
  uint32_t *out_msg_len,
  uint8_t **out_msg,
  Noise_XK_encap_message_t *emp
)
{
  return
    Noise_XK_unpack_message_with_auth_level(out_msg_len,
      out_msg,
      NOISE_XK_MAX_AUTH_LEVEL,
      emp);
}

void
Noise_XK_unsafe_unpack_message(
  Noise_XK_ac_level_t *out_ac_level,
  uint32_t *out_msg_len,
  uint8_t **out_msg,
  Noise_XK_encap_message_t *emp
)
{
  Noise_XK_encap_message_t em = emp[0U];
  uint8_t *msg;
  if (em.em_message_len > (uint32_t)0U)
  {
    KRML_CHECK_SIZE(sizeof (uint8_t), em.em_message_len);
    uint8_t *o = KRML_HOST_CALLOC(em.em_message_len, sizeof (uint8_t));
    memcpy(o, em.em_message, em.em_message_len * sizeof (uint8_t));
    msg = o;
  }
  else
    msg = NULL;
  out_ac_level[0U] = em.em_ac_level;
  out_msg_len[0U] = em.em_message_len;
  out_msg[0U] = msg;
}

Prims_int Noise_XK_num_pattern_messages = (krml_checked_int_t)3;

bool Noise_XK_rcode_is_success(Noise_XK_rcode c)
{
  if (c.tag == Noise_XK_Success)
    return true;
  else
    return false;
}

bool Noise_XK_rcode_is_error(Noise_XK_rcode c)
{
  if (c.tag == Noise_XK_Error)
    return true;
  else
    return false;
}

bool Noise_XK_rcode_is_stuck(Noise_XK_rcode c)
{
  if (c.tag == Noise_XK_Stuck)
    return true;
  else
    return false;
}

typedef struct Noise_XK_init_state_t_s
{
  Noise_XK_init_state_t_tags tag;
  union {
    struct 
    {
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
    }
    case_IMS_Handshake;
    struct 
    {
      uint8_t *h;
      bool recv_transport_message;
      uint8_t *send_key;
      uint64_t send_nonce;
      uint8_t *receive_key;
      uint64_t receive_nonce;
    }
    case_IMS_Transport;
  }
  val;
}
Noise_XK_init_state_t;

typedef struct Noise_XK_peer_t_s
{
  uint32_t p_id;
  Noise_XK_noise_string *p_info;
  uint8_t *p_s;
}
Noise_XK_peer_t;

typedef Noise_XK_peer_t *peer_p;

typedef Noise_XK_cell **t___Impl_Noise_API_Instances_X1N_25519_AESGCM_BLAKE2b_peer_p;

typedef struct Noise_XK_device_t_s
{
  Noise_XK_noise_string *dv_info;
  uint8_t *dv_sk;
  uint8_t *dv_spriv;
  uint8_t *dv_spub;
  Noise_XK_sized_buffer dv_prologue;
  uint32_t dv_states_counter;
  Noise_XK_cell **dv_peers;
  uint32_t dv_peers_counter;
}
Noise_XK_device_t;

typedef Noise_XK_device_t *device_p;

typedef struct Noise_XK_resp_state_t_s
{
  Noise_XK_init_state_t_tags tag;
  union {
    struct 
    {
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
    }
    case_IMS_Handshake;
    struct 
    {
      uint8_t *h;
      uint8_t *send_key;
      uint64_t send_nonce;
      uint8_t *receive_key;
      uint64_t receive_nonce;
    }
    case_IMS_Transport;
  }
  val;
}
Noise_XK_resp_state_t;

typedef struct Noise_XK_session_t_s
{
  Noise_XK_session_t_tags tag;
  union {
    struct 
    {
      Noise_XK_init_state_t state;
      uint32_t id;
      Noise_XK_noise_string *info;
      uint8_t *spriv;
      uint8_t *spub;
      uint32_t pid;
      Noise_XK_noise_string *pinfo;
      Noise_XK_device_t *dv;
    }
    case_DS_Initiator;
    struct 
    {
      Noise_XK_resp_state_t state;
      uint32_t id;
      Noise_XK_noise_string *info;
      uint8_t *spriv;
      uint8_t *spub;
      uint32_t pid;
      Noise_XK_noise_string *pinfo;
      Noise_XK_device_t *dv;
    }
    case_DS_Responder;
  }
  val;
}
Noise_XK_session_t;

typedef Noise_XK_session_t *session_p;

/*
  Create a device.
 
  Parameters:
  * `prlg`: Prologue for session initialization
  * `info`: Device name
  * `sk`: (if present) symmetric key used to serialize/deserialize private data
  * `spriv`: (if present) static private key
 
  May fail and return NULL if provided unvalid keys.
*/
Noise_XK_device_t
*Noise_XK_device_create(
  uint32_t prlg_len,
  uint8_t *prlg,
  uint8_t *info,
  uint8_t *sk,
  uint8_t *spriv
)
{
  uint8_t *o0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
  memcpy(o0, sk, (uint32_t)32U * sizeof (uint8_t));
  uint8_t *sk_ = o0;
  uint8_t *o1 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
  memcpy(o1, spriv, (uint32_t)32U * sizeof (uint8_t));
  uint8_t *spriv_ = o1;
  uint8_t *spub_ = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
  Noise_XK_error_code res = Noise_XK_dh_secret_to_public(spub_, spriv_);
  switch (res)
  {
    case Noise_XK_CSuccess:
      {
        uint8_t *prlg_;
        if (prlg_len > (uint32_t)0U)
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), prlg_len);
          uint8_t *o = KRML_HOST_CALLOC(prlg_len, sizeof (uint8_t));
          memcpy(o, prlg, prlg_len * sizeof (uint8_t));
          prlg_ = o;
        }
        else
          prlg_ = NULL;
        Noise_XK_sized_buffer prlg_1 = { .size = prlg_len, .buffer = prlg_ };
        bool b = info == NULL;
        uint8_t *out_str;
        if (b)
          out_str = NULL;
        else
        {
          uint32_t ip = (uint32_t)0U;
          uint32_t i0 = ip;
          uint8_t c0 = info[i0];
          bool cond = c0 != (uint8_t)0U;
          while (cond)
          {
            uint32_t i = ip;
            ip = i + (uint32_t)1U;
            uint32_t i0 = ip;
            uint8_t c = info[i0];
            cond = c != (uint8_t)0U;
          }
          uint32_t len = ip;
          if (len == (uint32_t)0U)
            out_str = NULL;
          else
          {
            KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
            uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
            uint32_t np = (uint32_t)0U;
            uint32_t n0 = np;
            uint8_t c0 = info[n0];
            bool cond = c0 != (uint8_t)0U;
            while (cond)
            {
              uint32_t n = np;
              uint8_t c = info[n];
              out_str0[n] = c;
              np = n + (uint32_t)1U;
              uint32_t n0 = np;
              uint8_t c0 = info[n0];
              cond = c0 != (uint8_t)0U;
            }
            uint32_t n = np;
            out_str0[n] = (uint8_t)0U;
            uint8_t *out_str1 = out_str0;
            out_str = out_str1;
          }
        }
        KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
        uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
        out_ptr[0U] = out_str;
        Noise_XK_noise_string *info_ = out_ptr;
        KRML_CHECK_SIZE(sizeof (Noise_XK_cell *), (uint32_t)1U);
        Noise_XK_cell **ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_cell *));
        ptr[0U] = NULL;
        Noise_XK_cell **peers = ptr;
        Noise_XK_device_t
        dv =
          {
            .dv_info = info_, .dv_sk = sk_, .dv_spriv = spriv_, .dv_spub = spub_,
            .dv_prologue = prlg_1, .dv_states_counter = (uint32_t)1U, .dv_peers = peers,
            .dv_peers_counter = (uint32_t)1U
          };
        KRML_CHECK_SIZE(sizeof (Noise_XK_device_t), (uint32_t)1U);
        Noise_XK_device_t *dvp = KRML_HOST_MALLOC(sizeof (Noise_XK_device_t));
        dvp[0U] = dv;
        return dvp;
      }
    default:
      {
        return NULL;
      }
  }
}

typedef struct __uint32_t__uint8_t__s
{
  uint32_t fst;
  uint8_t *snd;
}
__uint32_t__uint8_t_;

/*
  Create a device.

  Takes as arguments a symmetric key `sk` for secret data serialization/
  deserialization, and an encrypted static private key `spriv`. The device
  name `info` is used as authentication data to encrypt/decrypt the device
  private key.

  May fail and return NULL if provided unvalid keys.
*/
Noise_XK_device_t
*Noise_XK_device_create_from_secret(
  uint32_t prlg_len,
  uint8_t *prlg,
  uint8_t *info,
  uint8_t *sk,
  uint8_t *spriv
)
{
  uint8_t *spriv_ = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
  __uint32_t__uint8_t_ scrut;
  if (info == NULL)
    scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
  else
  {
    uint32_t ip = (uint32_t)0U;
    uint32_t i0 = ip;
    uint8_t c = info[i0];
    bool cond = c != (uint8_t)0U;
    while (cond)
    {
      uint32_t i = ip;
      ip = i + (uint32_t)1U;
      uint32_t i0 = ip;
      uint8_t c = info[i0];
      cond = c != (uint8_t)0U;
    }
    uint32_t l = ip;
    if (l == (uint32_t)0U)
      scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
    else
    {
      uint8_t *s = info;
      scrut = ((__uint32_t__uint8_t_){ .fst = l, .snd = s });
    }
  }
  uint32_t name_raw_len = scrut.fst;
  uint8_t *name_raw = scrut.snd;
  uint8_t *n8 = spriv;
  uint8_t *c0 = spriv + (uint32_t)8U;
  uint64_t n0 = Noise_XK_bytes_to_nonce(n8);
  Noise_XK_error_code
  res0 = Noise_XK_aead_decrypt(sk, n0, name_raw_len, name_raw, (uint32_t)32U, spriv_, c0);
  if (!(res0 == Noise_XK_CSuccess))
  {
    KRML_HOST_FREE(spriv_);
    return NULL;
  }
  else
  {
    uint8_t *o0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    memcpy(o0, sk, (uint32_t)32U * sizeof (uint8_t));
    uint8_t *sk_ = o0;
    uint8_t *spub_ = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    Noise_XK_error_code res1 = Noise_XK_dh_secret_to_public(spub_, spriv_);
    uint8_t *prlg_;
    if (prlg_len > (uint32_t)0U)
    {
      KRML_CHECK_SIZE(sizeof (uint8_t), prlg_len);
      uint8_t *o = KRML_HOST_CALLOC(prlg_len, sizeof (uint8_t));
      memcpy(o, prlg, prlg_len * sizeof (uint8_t));
      prlg_ = o;
    }
    else
      prlg_ = NULL;
    Noise_XK_sized_buffer prlg_1 = { .size = prlg_len, .buffer = prlg_ };
    bool b = info == NULL;
    uint8_t *out_str;
    if (b)
      out_str = NULL;
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c0 = info[i0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = info[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t len = ip;
      if (len == (uint32_t)0U)
        out_str = NULL;
      else
      {
        KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
        uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
        uint32_t np = (uint32_t)0U;
        uint32_t n0 = np;
        uint8_t c0 = info[n0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t n = np;
          uint8_t c = info[n];
          out_str0[n] = c;
          np = n + (uint32_t)1U;
          uint32_t n0 = np;
          uint8_t c0 = info[n0];
          cond = c0 != (uint8_t)0U;
        }
        uint32_t n = np;
        out_str0[n] = (uint8_t)0U;
        uint8_t *out_str1 = out_str0;
        out_str = out_str1;
      }
    }
    KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
    uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
    out_ptr[0U] = out_str;
    Noise_XK_noise_string *info_ = out_ptr;
    KRML_CHECK_SIZE(sizeof (Noise_XK_cell *), (uint32_t)1U);
    Noise_XK_cell **ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_cell *));
    ptr[0U] = NULL;
    Noise_XK_cell **peers = ptr;
    Noise_XK_device_t
    dv =
      {
        .dv_info = info_, .dv_sk = sk_, .dv_spriv = spriv_, .dv_spub = spub_, .dv_prologue = prlg_1,
        .dv_states_counter = (uint32_t)1U, .dv_peers = peers, .dv_peers_counter = (uint32_t)1U
      };
    KRML_CHECK_SIZE(sizeof (Noise_XK_device_t), (uint32_t)1U);
    Noise_XK_device_t *dvp = KRML_HOST_MALLOC(sizeof (Noise_XK_device_t));
    dvp[0U] = dv;
    return dvp;
  }
}

static void
free___Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(
  Noise_XK_cell *l
)
{
  if (!(l == NULL))
  {
    free___Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____((*l).next);
    KRML_HOST_FREE(l);
  }
}

static void
free__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(
  Noise_XK_cell **pl
)
{
  free___Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(*pl);
  *pl = NULL;
}

/*
  Free a device.

  Take care to free the device **AFTER** having freed all the sessions created
  from this device.
*/
void Noise_XK_device_free(Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  uint8_t *str = dv.dv_info[0U];
  if (!(str == NULL))
    KRML_HOST_FREE(str);
  KRML_HOST_FREE(dv.dv_info);
  free__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(dv.dv_peers);
  KRML_HOST_FREE(dv.dv_peers);
  KRML_HOST_FREE(dv.dv_spriv);
  KRML_HOST_FREE(dv.dv_spub);
  if (!(dv.dv_prologue.buffer == NULL))
    KRML_HOST_FREE(dv.dv_prologue.buffer);
  KRML_HOST_FREE(dvp);
}

/*
  Encrypt and derialize a device's secret.

  Uses the device symmetric key to encrypt the device's secret key. Uses
  a randomly generated nonce together with the device name as authentication data.
*/
void Noise_XK_serialize_device_secret(uint32_t *outlen, uint8_t **out, Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  uint8_t *outb = KRML_HOST_CALLOC((uint32_t)56U, sizeof (uint8_t));
  uint8_t *name = dv.dv_info[0U];
  __uint32_t__uint8_t_ scrut;
  if (name == NULL)
    scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
  else
  {
    uint32_t ip = (uint32_t)0U;
    uint32_t i0 = ip;
    uint8_t c = name[i0];
    bool cond = c != (uint8_t)0U;
    while (cond)
    {
      uint32_t i = ip;
      ip = i + (uint32_t)1U;
      uint32_t i0 = ip;
      uint8_t c = name[i0];
      cond = c != (uint8_t)0U;
    }
    uint32_t l = ip;
    if (l == (uint32_t)0U)
      scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
    else
    {
      uint8_t *s = name;
      scrut = ((__uint32_t__uint8_t_){ .fst = l, .snd = s });
    }
  }
  uint32_t name_raw_len = scrut.fst;
  uint8_t *name_raw = scrut.snd;
  uint8_t *n8 = outb;
  uint8_t *c = outb + (uint32_t)8U;
#ifdef WITH_SODIUM
  randombytes_buf(n8, (uint32_t)8U);
#else // WITH_SODIUM
  Lib_RandomBuffer_System_crypto_random(n8, (uint32_t)8U);
#endif // WITH_SODIUM
  uint64_t n = Noise_XK_bytes_to_nonce(n8);
  Noise_XK_aead_encrypt(dv.dv_sk, n, name_raw_len, name_raw, (uint32_t)32U, dv.dv_spriv, c);
  out[0U] = outb;
  outlen[0U] = (uint32_t)56U;
}

static void
push__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(
  Noise_XK_cell **pl,
  Noise_XK_peer_t *x
)
{
  Noise_XK_cell *l = *pl;
  Noise_XK_cell c = { .next = l, .data = x };
  KRML_CHECK_SIZE(sizeof (Noise_XK_cell), (uint32_t)1U);
  Noise_XK_cell *pc = KRML_HOST_MALLOC(sizeof (Noise_XK_cell));
  pc[0U] = c;
  *pl = pc;
}

/*
  Add a peer to the device and return a pointer to the newly created peer.

  May fail and return NULL if the device already contains a peer with the same
  public static key.

  Note that the peer is owned by the device: we don't provide any way of freeing it
  on the user side, and it might be invalidated after a removal operation.
  For this reason, we advise to immediately use the returned pointer (to retrieve
  the peer id for instance), then forget it.
*/
Noise_XK_peer_t *Noise_XK_device_add_peer(Noise_XK_device_t *dvp, uint8_t *pinfo, uint8_t *rs)
{
  Noise_XK_device_t dv = dvp[0U];
  uint32_t pcounter = dv.dv_peers_counter;
  bool b1 = pcounter == (uint32_t)4294967295U;
  Noise_XK_cell *llt = *dv.dv_peers;
  Noise_XK_cell *lltp = llt;
  Noise_XK_cell *llt10 = lltp;
  bool b0;
  if (llt10 == NULL)
    b0 = false;
  else
  {
    Noise_XK_cell c = llt10[0U];
    Noise_XK_peer_t x = c.data[0U];
    bool b = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, rs);
    bool b1 = b;
    b0 = !b1;
  }
  bool cond = b0;
  while (cond)
  {
    Noise_XK_cell *llt1 = lltp;
    Noise_XK_cell c0 = llt1[0U];
    lltp = c0.next;
    Noise_XK_cell *llt10 = lltp;
    bool b;
    if (llt10 == NULL)
      b = false;
    else
    {
      Noise_XK_cell c = llt10[0U];
      Noise_XK_peer_t x = c.data[0U];
      bool b0 = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, rs);
      bool b1 = b0;
      b = !b1;
    }
    cond = b;
  }
  Noise_XK_cell *llt1 = *&lltp;
  Noise_XK_peer_t *res;
  if (llt1 == NULL)
    res = NULL;
  else
  {
    Noise_XK_cell c = *llt1;
    res = c.data;
  }
  bool b2 = !(res == NULL);
  if (b1 || b2)
    return NULL;
  else
  {
    Noise_XK_noise_string *info1 = dv.dv_info;
    uint8_t *sk1 = dv.dv_sk;
    uint8_t *spriv1 = dv.dv_spriv;
    uint8_t *spub1 = dv.dv_spub;
    Noise_XK_sized_buffer prologue1 = dv.dv_prologue;
    uint32_t scounter1 = dv.dv_states_counter;
    Noise_XK_cell **peers1 = dv.dv_peers;
    uint32_t pcounter1 = dv.dv_peers_counter;
    uint8_t *rs1 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    memcpy(rs1, rs, (uint32_t)32U * sizeof (uint8_t));
    bool b = pinfo == NULL;
    uint8_t *out_str;
    if (b)
      out_str = NULL;
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c0 = pinfo[i0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = pinfo[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t len = ip;
      if (len == (uint32_t)0U)
        out_str = NULL;
      else
      {
        KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
        uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
        uint32_t np = (uint32_t)0U;
        uint32_t n0 = np;
        uint8_t c0 = pinfo[n0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t n = np;
          uint8_t c = pinfo[n];
          out_str0[n] = c;
          np = n + (uint32_t)1U;
          uint32_t n0 = np;
          uint8_t c0 = pinfo[n0];
          cond = c0 != (uint8_t)0U;
        }
        uint32_t n = np;
        out_str0[n] = (uint8_t)0U;
        uint8_t *out_str1 = out_str0;
        out_str = out_str1;
      }
    }
    KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
    uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
    out_ptr[0U] = out_str;
    Noise_XK_noise_string *pinfo1 = out_ptr;
    Noise_XK_peer_t x_ = { .p_id = pcounter1, .p_info = pinfo1, .p_s = rs1 };
    KRML_CHECK_SIZE(sizeof (Noise_XK_peer_t), (uint32_t)1U);
    Noise_XK_peer_t *xp_ = KRML_HOST_MALLOC(sizeof (Noise_XK_peer_t));
    xp_[0U] = x_;
    Noise_XK_peer_t *x = xp_;
    push__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(peers1,
      x);
    Noise_XK_peer_t *pp = x;
    dvp[0U] =
      (
        (Noise_XK_device_t){
          .dv_info = info1,
          .dv_sk = sk1,
          .dv_spriv = spriv1,
          .dv_spub = spub1,
          .dv_prologue = prologue1,
          .dv_states_counter = scounter1,
          .dv_peers = peers1,
          .dv_peers_counter = pcounter1 + (uint32_t)1U
        }
      );
    Noise_XK_peer_t *pp0 = pp;
    return pp0;
  }
}

static Noise_XK_peer_t
*pop__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(
  Noise_XK_cell **pl
)
{
  Noise_XK_cell *l = *pl;
  Noise_XK_peer_t *r1 = (*l).data;
  Noise_XK_cell *next = (*l).next;
  *pl = next;
  KRML_HOST_FREE(l);
  return r1;
}

/*
  Remove a peer designated by its unique identifier.
*/
void Noise_XK_device_remove_peer(Noise_XK_device_t *dvp, uint32_t pid)
{
  if (!(pid == (uint32_t)0U))
  {
    Noise_XK_device_t dv = dvp[0U];
    Noise_XK_cell *llt = *dv.dv_peers;
    if (!(llt == NULL))
    {
      Noise_XK_cell c0 = *llt;
      Noise_XK_peer_t x = c0.data[0U];
      if (x.p_id != pid)
      {
        Noise_XK_cell *llt1 = *dv.dv_peers;
        Noise_XK_cell *lltp = llt1;
        Noise_XK_cell *llt20 = lltp;
        Noise_XK_cell *next = llt20->next;
        bool b0;
        if (next == NULL)
          b0 = false;
        else
        {
          Noise_XK_cell c = next[0U];
          Noise_XK_peer_t x = c.data[0U];
          b0 = x.p_id != pid;
        }
        bool cond = b0;
        while (cond)
        {
          Noise_XK_cell *llt2 = lltp;
          Noise_XK_cell c0 = llt2[0U];
          lltp = c0.next;
          Noise_XK_cell *llt20 = lltp;
          Noise_XK_cell *next = llt20->next;
          bool b;
          if (next == NULL)
            b = false;
          else
          {
            Noise_XK_cell c = next[0U];
            Noise_XK_peer_t x = c.data[0U];
            b = x.p_id != pid;
          }
          cond = b;
        }
        Noise_XK_cell *llt2 = *&lltp;
        Noise_XK_cell c01 = *llt2;
        if (!(c01.next == NULL))
        {
          Noise_XK_cell c1 = *c01.next;
          llt2[0U] = ((Noise_XK_cell){ .next = c1.next, .data = c01.data });
          Noise_XK_peer_t p = c1.data[0U];
          uint8_t *str = p.p_info[0U];
          if (!(str == NULL))
            KRML_HOST_FREE(str);
          KRML_HOST_FREE(p.p_info);
#ifdef WITH_SODIUM
          sodium_memzero(p.p_s, (uint32_t)32U * sizeof (p.p_s[0U]));
#else // WITH_SODIUM
          Lib_Memzero0_memzero(p.p_s, (uint32_t)32U * sizeof (p.p_s[0U]));
#endif // WITH_SODIUM
          KRML_HOST_FREE(p.p_s);
          KRML_HOST_FREE(c1.data);
          KRML_HOST_FREE(c01.next);
        }
      }
      else
      {
        Noise_XK_peer_t
        *elem1 =
          pop__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(dv.dv_peers);
        Noise_XK_peer_t p = elem1[0U];
        uint8_t *str = p.p_info[0U];
        if (!(str == NULL))
          KRML_HOST_FREE(str);
        KRML_HOST_FREE(p.p_info);
#ifdef WITH_SODIUM
        sodium_memzero(p.p_s, (uint32_t)32U * sizeof (p.p_s[0U]));
#else // WITH_SODIUM
        Lib_Memzero0_memzero(p.p_s, (uint32_t)32U * sizeof (p.p_s[0U]));
#endif // WITH_SODIUM
        KRML_HOST_FREE(p.p_s);
        KRML_HOST_FREE(elem1);
      }
    }
  }
}

/*
  Encrypt and serialize a peer's key(s).

  Uses the device symmetric key to encrypt the peer's key(s). Uses
  a randomly generated nonce together with the peer name as authentication
  data.
*/
void
Noise_XK_serialize_peer_secret(
  uint32_t *outlen,
  uint8_t **out,
  Noise_XK_device_t *dvp,
  Noise_XK_peer_t *peer
)
{
  if (peer == NULL)
  {
    outlen[0U] = (uint32_t)0U;
    out[0U] = NULL;
  }
  else
  {
    Noise_XK_device_t dv = dvp[0U];
    Noise_XK_peer_t p = peer[0U];
    uint8_t *concat_keys = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    uint8_t *outb = KRML_HOST_CALLOC((uint32_t)56U, sizeof (uint8_t));
    memcpy(concat_keys, p.p_s, (uint32_t)32U * sizeof (uint8_t));
    uint8_t *name = p.p_info[0U];
    __uint32_t__uint8_t_ scrut;
    if (name == NULL)
      scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c = name[i0];
      bool cond = c != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = name[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t l = ip;
      if (l == (uint32_t)0U)
        scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
      else
      {
        uint8_t *s = name;
        scrut = ((__uint32_t__uint8_t_){ .fst = l, .snd = s });
      }
    }
    uint32_t name_raw_len = scrut.fst;
    uint8_t *name_raw = scrut.snd;
    uint8_t *n8 = outb;
    uint8_t *c = outb + (uint32_t)8U;
#ifdef WITH_SODIUM
    randombytes_buf(n8, (uint32_t)8U);
#else // WITH_SODIUM
    Lib_RandomBuffer_System_crypto_random(n8, (uint32_t)8U);
#endif // WITH_SODIUM
    uint64_t n = Noise_XK_bytes_to_nonce(n8);
    Noise_XK_aead_encrypt(dv.dv_sk, n, name_raw_len, name_raw, (uint32_t)32U, concat_keys, c);
    out[0U] = outb;
    outlen[0U] = (uint32_t)56U;
    KRML_HOST_FREE(concat_keys);
  }
}

/*
  Decrypt and deserialize a peer's secret data and add it to the device.
*/
Noise_XK_peer_t
*Noise_XK_deserialize_peer_secret(
  Noise_XK_device_t *dvp,
  uint8_t *peer_name,
  uint32_t inlen,
  uint8_t *enc_keys
)
{
  Noise_XK_device_t dv = dvp[0U];
  if ((uint32_t)56U != inlen)
    return NULL;
  else
  {
    uint8_t *concat_keys = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    __uint32_t__uint8_t_ scrut;
    if (peer_name == NULL)
      scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c = peer_name[i0];
      bool cond = c != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = peer_name[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t l = ip;
      if (l == (uint32_t)0U)
        scrut = ((__uint32_t__uint8_t_){ .fst = (uint32_t)0U, .snd = NULL });
      else
      {
        uint8_t *s = peer_name;
        scrut = ((__uint32_t__uint8_t_){ .fst = l, .snd = s });
      }
    }
    uint32_t name_raw_len = scrut.fst;
    uint8_t *name_raw = scrut.snd;
    uint8_t *n8 = enc_keys;
    uint8_t *c0 = enc_keys + (uint32_t)8U;
    uint64_t n0 = Noise_XK_bytes_to_nonce(n8);
    Noise_XK_error_code
    res =
      Noise_XK_aead_decrypt(dv.dv_sk,
        n0,
        name_raw_len,
        name_raw,
        (uint32_t)32U,
        concat_keys,
        c0);
    if (res == Noise_XK_CSuccess)
    {
      uint8_t *p_s = concat_keys;
      Noise_XK_device_t dv1 = dvp[0U];
      uint32_t pcounter = dv1.dv_peers_counter;
      bool b1 = pcounter == (uint32_t)4294967295U;
      Noise_XK_cell *llt = *dv1.dv_peers;
      Noise_XK_cell *lltp = llt;
      Noise_XK_cell *llt10 = lltp;
      bool b0;
      if (llt10 == NULL)
        b0 = false;
      else
      {
        Noise_XK_cell c = llt10[0U];
        Noise_XK_peer_t x = c.data[0U];
        bool b = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, p_s);
        bool b1 = b;
        b0 = !b1;
      }
      bool cond = b0;
      while (cond)
      {
        Noise_XK_cell *llt1 = lltp;
        Noise_XK_cell c0 = llt1[0U];
        lltp = c0.next;
        Noise_XK_cell *llt10 = lltp;
        bool b;
        if (llt10 == NULL)
          b = false;
        else
        {
          Noise_XK_cell c = llt10[0U];
          Noise_XK_peer_t x = c.data[0U];
          bool b0 = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, p_s);
          bool b1 = b0;
          b = !b1;
        }
        cond = b;
      }
      Noise_XK_cell *llt1 = *&lltp;
      Noise_XK_peer_t *res1;
      if (llt1 == NULL)
        res1 = NULL;
      else
      {
        Noise_XK_cell c = *llt1;
        res1 = c.data;
      }
      bool b2 = !(res1 == NULL);
      Noise_XK_peer_t *peer;
      if (b1 || b2)
        peer = NULL;
      else
      {
        Noise_XK_noise_string *info1 = dv1.dv_info;
        uint8_t *sk1 = dv1.dv_sk;
        uint8_t *spriv1 = dv1.dv_spriv;
        uint8_t *spub1 = dv1.dv_spub;
        Noise_XK_sized_buffer prologue1 = dv1.dv_prologue;
        uint32_t scounter1 = dv1.dv_states_counter;
        Noise_XK_cell **peers1 = dv1.dv_peers;
        uint32_t pcounter1 = dv1.dv_peers_counter;
        uint8_t *rs = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
        memcpy(rs, p_s, (uint32_t)32U * sizeof (uint8_t));
        bool b = peer_name == NULL;
        uint8_t *out_str;
        if (b)
          out_str = NULL;
        else
        {
          uint32_t ip = (uint32_t)0U;
          uint32_t i0 = ip;
          uint8_t c0 = peer_name[i0];
          bool cond = c0 != (uint8_t)0U;
          while (cond)
          {
            uint32_t i = ip;
            ip = i + (uint32_t)1U;
            uint32_t i0 = ip;
            uint8_t c = peer_name[i0];
            cond = c != (uint8_t)0U;
          }
          uint32_t len = ip;
          if (len == (uint32_t)0U)
            out_str = NULL;
          else
          {
            KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
            uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
            uint32_t np = (uint32_t)0U;
            uint32_t n0 = np;
            uint8_t c0 = peer_name[n0];
            bool cond = c0 != (uint8_t)0U;
            while (cond)
            {
              uint32_t n = np;
              uint8_t c = peer_name[n];
              out_str0[n] = c;
              np = n + (uint32_t)1U;
              uint32_t n0 = np;
              uint8_t c0 = peer_name[n0];
              cond = c0 != (uint8_t)0U;
            }
            uint32_t n = np;
            out_str0[n] = (uint8_t)0U;
            uint8_t *out_str1 = out_str0;
            out_str = out_str1;
          }
        }
        KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
        uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
        out_ptr[0U] = out_str;
        Noise_XK_noise_string *pinfo = out_ptr;
        Noise_XK_peer_t x_ = { .p_id = pcounter1, .p_info = pinfo, .p_s = rs };
        KRML_CHECK_SIZE(sizeof (Noise_XK_peer_t), (uint32_t)1U);
        Noise_XK_peer_t *xp_ = KRML_HOST_MALLOC(sizeof (Noise_XK_peer_t));
        xp_[0U] = x_;
        Noise_XK_peer_t *x = xp_;
        push__Impl_Noise_API_Device_raw_peer_p_or_null_raw_Impl_Noise_API_Device_raw_peer_t_raw_uint32_t_Impl_Noise_String_hstring__uint8_t____(peers1,
          x);
        Noise_XK_peer_t *pp = x;
        dvp[0U] =
          (
            (Noise_XK_device_t){
              .dv_info = info1,
              .dv_sk = sk1,
              .dv_spriv = spriv1,
              .dv_spub = spub1,
              .dv_prologue = prologue1,
              .dv_states_counter = scounter1,
              .dv_peers = peers1,
              .dv_peers_counter = pcounter1 + (uint32_t)1U
            }
          );
        Noise_XK_peer_t *pp0 = pp;
        peer = pp0;
      }
      KRML_HOST_FREE(concat_keys);
      return peer;
    }
    else
    {
      KRML_HOST_FREE(concat_keys);
      return NULL;
    }
  }
}

/*
  Lookup a peer by using its unique identifier.

  Return NULL is no peer was found.

  Note that the peer is owned by the device: we don't provide any way of freeing it
  on the user side, and it might be invalidated after a removal operation.
  For this reason, we advise to immediately use the returned pointer (to retrieve
  the peer name, etc.), then forget it.
*/
Noise_XK_peer_t *Noise_XK_device_lookup_peer_by_id(Noise_XK_device_t *dvp, uint32_t id)
{
  Noise_XK_device_t dv = dvp[0U];
  if (id == (uint32_t)0U)
    return NULL;
  else
  {
    Noise_XK_cell *llt = *dv.dv_peers;
    Noise_XK_cell *lltp = llt;
    Noise_XK_cell *llt10 = lltp;
    bool b0;
    if (llt10 == NULL)
      b0 = false;
    else
    {
      Noise_XK_cell c = llt10[0U];
      Noise_XK_peer_t x = c.data[0U];
      bool b = x.p_id == id;
      b0 = !b;
    }
    bool cond = b0;
    while (cond)
    {
      Noise_XK_cell *llt1 = lltp;
      Noise_XK_cell c0 = llt1[0U];
      lltp = c0.next;
      Noise_XK_cell *llt10 = lltp;
      bool b;
      if (llt10 == NULL)
        b = false;
      else
      {
        Noise_XK_cell c = llt10[0U];
        Noise_XK_peer_t x = c.data[0U];
        bool b0 = x.p_id == id;
        b = !b0;
      }
      cond = b;
    }
    Noise_XK_cell *llt1 = *&lltp;
    if (llt1 == NULL)
      return NULL;
    else
    {
      Noise_XK_cell c = *llt1;
      return c.data;
    }
  }
}

/*
  Lookup a peer by using its static public key.

  Return NULL is no peer was found.

  Note that the peer is owned by the device: we don't provide any way of freeing it
  on the user side, and it might be invalidated after a removal operation.
  For this reason, we advise to immediately use the returned pointer (to retrieve
  the peer name, etc.), then forget it.
*/
Noise_XK_peer_t *Noise_XK_device_lookup_peer_by_static(Noise_XK_device_t *dvp, uint8_t *s)
{
  Noise_XK_device_t dv = dvp[0U];
  Noise_XK_cell *llt = *dv.dv_peers;
  Noise_XK_cell *lltp = llt;
  Noise_XK_cell *llt10 = lltp;
  bool b0;
  if (llt10 == NULL)
    b0 = false;
  else
  {
    Noise_XK_cell c = llt10[0U];
    Noise_XK_peer_t x = c.data[0U];
    bool b = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, s);
    bool b1 = b;
    b0 = !b1;
  }
  bool cond = b0;
  while (cond)
  {
    Noise_XK_cell *llt1 = lltp;
    Noise_XK_cell c0 = llt1[0U];
    lltp = c0.next;
    Noise_XK_cell *llt10 = lltp;
    bool b;
    if (llt10 == NULL)
      b = false;
    else
    {
      Noise_XK_cell c = llt10[0U];
      Noise_XK_peer_t x = c.data[0U];
      bool b0 = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, s);
      bool b1 = b0;
      b = !b1;
    }
    cond = b;
  }
  Noise_XK_cell *llt1 = *&lltp;
  if (llt1 == NULL)
    return NULL;
  else
  {
    Noise_XK_cell c = *llt1;
    return c.data;
  }
}

/*
  Copy the peer information to the user provided pointer.
*/
void Noise_XK_device_get_info(Noise_XK_noise_string *out, Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  uint8_t *input_str = dv.dv_info[0U];
  bool b = input_str == NULL;
  uint8_t *out_str;
  if (b)
    out_str = NULL;
  else
  {
    uint32_t ip = (uint32_t)0U;
    uint32_t i0 = ip;
    uint8_t c0 = input_str[i0];
    bool cond = c0 != (uint8_t)0U;
    while (cond)
    {
      uint32_t i = ip;
      ip = i + (uint32_t)1U;
      uint32_t i0 = ip;
      uint8_t c = input_str[i0];
      cond = c != (uint8_t)0U;
    }
    uint32_t len = ip;
    if (len == (uint32_t)0U)
      out_str = NULL;
    else
    {
      KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
      uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
      uint32_t np = (uint32_t)0U;
      uint32_t n0 = np;
      uint8_t c0 = input_str[n0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t n = np;
        uint8_t c = input_str[n];
        out_str0[n] = c;
        np = n + (uint32_t)1U;
        uint32_t n0 = np;
        uint8_t c0 = input_str[n0];
        cond = c0 != (uint8_t)0U;
      }
      uint32_t n = np;
      out_str0[n] = (uint8_t)0U;
      uint8_t *out_str1 = out_str0;
      out_str = out_str1;
    }
  }
  out[0U] = out_str;
}

/*
  Return the current value of the sessions counter.

  The device keeps track of the number of sessions created so far, in order
  to give them unique identifiers.
*/
uint32_t Noise_XK_device_get_sessions_counter(Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  return dv.dv_states_counter;
}

/*
  Return true if the sessions counter is saturated.

  It is not possible to create any more sessions if the counter is saturated.
*/
bool Noise_XK_device_sessions_counter_is_saturated(Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  uint32_t cnt = dv.dv_states_counter;
  return cnt == (uint32_t)4294967295U;
}

/*
  Return the current value of the peers counter.

  The device keeps track of the number of peers created so far, in order
  to give them unique identifiers.
*/
uint32_t Noise_XK_device_get_peers_counter(Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  return dv.dv_peers_counter;
}

/*
  Return true if the peers counter is saturated.

  It is not possible to add any more peers to the device if the counter is saturated.
*/
bool Noise_XK_device_peers_counter_is_saturated(Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  uint32_t cnt = dv.dv_peers_counter;
  return cnt == (uint32_t)4294967295U;
}

/*
  Copy the device static private key to the user provided buffer.
*/
void Noise_XK_device_get_static_priv(uint8_t *out, Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  memcpy(out, dv.dv_spriv, (uint32_t)32U * sizeof (uint8_t));
}

/*
  Copy the device static public key to the user provided buffer.
*/
void Noise_XK_device_get_static_pub(uint8_t *out, Noise_XK_device_t *dvp)
{
  Noise_XK_device_t dv = dvp[0U];
  memcpy(out, dv.dv_spub, (uint32_t)32U * sizeof (uint8_t));
}

/*
  Return the unique peer identifier.
*/
uint32_t Noise_XK_peer_get_id(Noise_XK_peer_t *pp)
{
  Noise_XK_peer_t p = pp[0U];
  return p.p_id;
}

/*
  Copy the peer information to the user provided pointer.
*/
void Noise_XK_peer_get_info(Noise_XK_noise_string *out, Noise_XK_peer_t *pp)
{
  Noise_XK_peer_t p = pp[0U];
  uint8_t *input_str = p.p_info[0U];
  bool b = input_str == NULL;
  uint8_t *out_str;
  if (b)
    out_str = NULL;
  else
  {
    uint32_t ip = (uint32_t)0U;
    uint32_t i0 = ip;
    uint8_t c0 = input_str[i0];
    bool cond = c0 != (uint8_t)0U;
    while (cond)
    {
      uint32_t i = ip;
      ip = i + (uint32_t)1U;
      uint32_t i0 = ip;
      uint8_t c = input_str[i0];
      cond = c != (uint8_t)0U;
    }
    uint32_t len = ip;
    if (len == (uint32_t)0U)
      out_str = NULL;
    else
    {
      KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
      uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
      uint32_t np = (uint32_t)0U;
      uint32_t n0 = np;
      uint8_t c0 = input_str[n0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t n = np;
        uint8_t c = input_str[n];
        out_str0[n] = c;
        np = n + (uint32_t)1U;
        uint32_t n0 = np;
        uint8_t c0 = input_str[n0];
        cond = c0 != (uint8_t)0U;
      }
      uint32_t n = np;
      out_str0[n] = (uint8_t)0U;
      uint8_t *out_str1 = out_str0;
      out_str = out_str1;
    }
  }
  out[0U] = out_str;
}

/*
  Copy the peer static public key to the user provided buffer.
*/
void Noise_XK_peer_get_static(uint8_t *out, Noise_XK_peer_t *pp)
{
  Noise_XK_peer_t p = pp[0U];
  memcpy(out, p.p_s, (uint32_t)32U * sizeof (uint8_t));
}

typedef struct _________________s {  } ________________;

#define Res 0
#define Fail 1

typedef uint8_t result_session_t_tags;

typedef struct result_session_t_s
{
  result_session_t_tags tag;
  union {
    Noise_XK_session_t case_Res;
    Noise_XK_error_code case_Fail;
  }
  val;
}
result_session_t;

typedef struct ______________s {  } _____________;

typedef struct ________s {  } _______;

/*
  Create an initiator session.

  May fail and return NULL in case of invalid keys, unknown peer, etc.
*/
Noise_XK_session_t *Noise_XK_session_create_initiator(Noise_XK_device_t *dvp, uint32_t pid)
{
  uint8_t epriv[32U] = { 0U };
  uint8_t epub[32U] = { 0U };
#ifdef WITH_SODIUM
  randombytes_buf(epriv, (uint32_t)32U);
#else // WITH_SODIUM
  Lib_RandomBuffer_System_crypto_random(epriv, (uint32_t)32U);
#endif // WITH_SODIUM
  Noise_XK_error_code res0 = Noise_XK_dh_secret_to_public(epub, epriv);
  Noise_XK_session_t *res;
  switch (res0)
  {
    case Noise_XK_CSuccess:
      {
        Noise_XK_device_t dv = dvp[0U];
        result_session_t res10;
        if (dv.dv_states_counter == (uint32_t)4294967295U)
          res10 =
            (
              (result_session_t){
                .tag = Fail,
                .val = { .case_Fail = Noise_XK_CIncorrect_transition }
              }
            );
        else
        {
          Noise_XK_device_t dv1 = dvp[0U];
          Noise_XK_peer_t *peer_ptr;
          if (pid == (uint32_t)0U)
            peer_ptr = NULL;
          else
          {
            Noise_XK_cell *llt = *dv1.dv_peers;
            Noise_XK_cell *lltp = llt;
            Noise_XK_cell *llt10 = lltp;
            bool b0;
            if (llt10 == NULL)
              b0 = false;
            else
            {
              Noise_XK_cell c = llt10[0U];
              Noise_XK_peer_t x = c.data[0U];
              bool b = x.p_id == pid;
              b0 = !b;
            }
            bool cond = b0;
            while (cond)
            {
              Noise_XK_cell *llt1 = lltp;
              Noise_XK_cell c0 = llt1[0U];
              lltp = c0.next;
              Noise_XK_cell *llt10 = lltp;
              bool b;
              if (llt10 == NULL)
                b = false;
              else
              {
                Noise_XK_cell c = llt10[0U];
                Noise_XK_peer_t x = c.data[0U];
                bool b0 = x.p_id == pid;
                b = !b0;
              }
              cond = b;
            }
            Noise_XK_cell *llt1 = *&lltp;
            Noise_XK_peer_t *res1;
            if (llt1 == NULL)
              res1 = NULL;
            else
            {
              Noise_XK_cell c = *llt1;
              res1 = c.data;
            }
            peer_ptr = res1;
          }
          bool p_is_null = peer_ptr == NULL;
          if (p_is_null)
            res10 =
              ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CUnknown_peer_id } });
          else
          {
            uint8_t *o0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            memcpy(o0, dv.dv_spriv, (uint32_t)32U * sizeof (uint8_t));
            uint8_t *st_spriv = o0;
            uint8_t *o = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            memcpy(o, dv.dv_spub, (uint32_t)32U * sizeof (uint8_t));
            uint8_t *st_spub = o;
            uint8_t *str0 = dv.dv_info[0U];
            bool b0 = str0 == NULL;
            uint8_t *out_str0;
            if (b0)
              out_str0 = NULL;
            else
            {
              uint32_t ip = (uint32_t)0U;
              uint32_t i0 = ip;
              uint8_t c0 = str0[i0];
              bool cond = c0 != (uint8_t)0U;
              while (cond)
              {
                uint32_t i = ip;
                ip = i + (uint32_t)1U;
                uint32_t i0 = ip;
                uint8_t c = str0[i0];
                cond = c != (uint8_t)0U;
              }
              uint32_t len = ip;
              if (len == (uint32_t)0U)
                out_str0 = NULL;
              else
              {
                KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
                uint8_t *out_str = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
                uint32_t np = (uint32_t)0U;
                uint32_t n0 = np;
                uint8_t c0 = str0[n0];
                bool cond = c0 != (uint8_t)0U;
                while (cond)
                {
                  uint32_t n = np;
                  uint8_t c = str0[n];
                  out_str[n] = c;
                  np = n + (uint32_t)1U;
                  uint32_t n0 = np;
                  uint8_t c0 = str0[n0];
                  cond = c0 != (uint8_t)0U;
                }
                uint32_t n = np;
                out_str[n] = (uint8_t)0U;
                uint8_t *out_str1 = out_str;
                out_str0 = out_str1;
              }
            }
            KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
            uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
            out_ptr[0U] = out_str0;
            Noise_XK_noise_string *st_info = out_ptr;
            Noise_XK_peer_t peer = peer_ptr[0U];
            uint8_t *str = peer.p_info[0U];
            bool b = str == NULL;
            uint8_t *out_str;
            if (b)
              out_str = NULL;
            else
            {
              uint32_t ip = (uint32_t)0U;
              uint32_t i0 = ip;
              uint8_t c0 = str[i0];
              bool cond = c0 != (uint8_t)0U;
              while (cond)
              {
                uint32_t i = ip;
                ip = i + (uint32_t)1U;
                uint32_t i0 = ip;
                uint8_t c = str[i0];
                cond = c != (uint8_t)0U;
              }
              uint32_t len = ip;
              if (len == (uint32_t)0U)
                out_str = NULL;
              else
              {
                KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
                uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
                uint32_t np = (uint32_t)0U;
                uint32_t n0 = np;
                uint8_t c0 = str[n0];
                bool cond = c0 != (uint8_t)0U;
                while (cond)
                {
                  uint32_t n = np;
                  uint8_t c = str[n];
                  out_str0[n] = c;
                  np = n + (uint32_t)1U;
                  uint32_t n0 = np;
                  uint8_t c0 = str[n0];
                  cond = c0 != (uint8_t)0U;
                }
                uint32_t n = np;
                out_str0[n] = (uint8_t)0U;
                uint8_t *out_str1 = out_str0;
                out_str = out_str1;
              }
            }
            KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
            uint8_t **out_ptr0 = KRML_HOST_MALLOC(sizeof (uint8_t *));
            out_ptr0[0U] = out_str;
            Noise_XK_noise_string *st_pinfo = out_ptr0;
            uint8_t *rs = peer.p_s;
            dvp[0U] =
              (
                (Noise_XK_device_t){
                  .dv_info = dv.dv_info,
                  .dv_sk = dv.dv_sk,
                  .dv_spriv = dv.dv_spriv,
                  .dv_spub = dv.dv_spub,
                  .dv_prologue = dv.dv_prologue,
                  .dv_states_counter = dv.dv_states_counter + (uint32_t)1U,
                  .dv_peers = dv.dv_peers,
                  .dv_peers_counter = dv.dv_peers_counter
                }
              );
            uint8_t *st_k = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            uint8_t *st_ck0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
            uint8_t *st_h0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
            uint8_t *st_spriv1 = st_spriv;
            uint8_t *st_spub1 = st_spub;
            uint8_t *st_epriv0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            uint8_t *st_epub0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            uint8_t *st_rs0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            uint8_t *st_re = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
            Noise_XK_init_state_t
            st =
              {
                .tag = Noise_XK_IMS_Handshake,
                .val = {
                  .case_IMS_Handshake = {
                    .step = (uint32_t)0U, .cipher_key = st_k, .chaining_key = st_ck0, .h = st_h0,
                    .spriv = st_spriv1, .spub = st_spub1, .epriv = st_epriv0, .epub = st_epub0,
                    .rs = st_rs0, .re = st_re
                  }
                }
              };
            uint8_t
            pname[33U] =
              {
                (uint8_t)78U, (uint8_t)111U, (uint8_t)105U, (uint8_t)115U, (uint8_t)101U,
                (uint8_t)95U, (uint8_t)88U, (uint8_t)75U, (uint8_t)95U, (uint8_t)50U, (uint8_t)53U,
                (uint8_t)53U, (uint8_t)49U, (uint8_t)57U, (uint8_t)95U, (uint8_t)67U, (uint8_t)104U,
                (uint8_t)97U, (uint8_t)67U, (uint8_t)104U, (uint8_t)97U, (uint8_t)80U, (uint8_t)111U,
                (uint8_t)108U, (uint8_t)121U, (uint8_t)95U, (uint8_t)66U, (uint8_t)76U, (uint8_t)65U,
                (uint8_t)75U, (uint8_t)69U, (uint8_t)50U, (uint8_t)98U
              };
            if (st.tag == Noise_XK_IMS_Handshake)
            {
              uint8_t *st_rs = st.val.case_IMS_Handshake.rs;
              uint8_t *st_epub = st.val.case_IMS_Handshake.epub;
              uint8_t *st_epriv = st.val.case_IMS_Handshake.epriv;
              uint8_t *st_h = st.val.case_IMS_Handshake.h;
              uint8_t *st_ck = st.val.case_IMS_Handshake.chaining_key;
              if ((uint32_t)33U <= (uint32_t)64U)
                memcpy(st_h, pname, (uint32_t)33U * sizeof (uint8_t));
              else
                Noise_XK_hash(st_h, (uint32_t)33U, pname);
              memcpy(st_ck, st_h, (uint32_t)64U * sizeof (uint8_t));
              Noise_XK_mix_hash(st_h, dv.dv_prologue.size, dv.dv_prologue.buffer);
              memcpy(st_epriv, epriv, (uint32_t)32U * sizeof (uint8_t));
              memcpy(st_epub, epub, (uint32_t)32U * sizeof (uint8_t));
              memcpy(st_rs, rs, (uint32_t)32U * sizeof (uint8_t));
              Noise_XK_mix_hash(st_h, (uint32_t)32U, rs);
            }
            else
            {
              KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
                __FILE__,
                __LINE__,
                "unreachable (pattern matches are exhaustive in F*)");
              KRML_HOST_EXIT(255U);
            }
            Noise_XK_init_state_t st0 = st;
            result_session_t
            res1 =
              {
                .tag = Res,
                .val = {
                  .case_Res = {
                    .tag = Noise_XK_DS_Initiator,
                    .val = {
                      .case_DS_Initiator = {
                        .state = st0, .id = dv.dv_states_counter, .info = st_info, .spriv = st_spriv,
                        .spub = st_spub, .pid = pid, .pinfo = st_pinfo, .dv = dvp
                      }
                    }
                  }
                }
              };
            res10 = res1;
          }
        }
        Noise_XK_session_t *res1;
        if (res10.tag == Fail)
          res1 = NULL;
        else if (res10.tag == Res)
        {
          Noise_XK_session_t st = res10.val.case_Res;
          KRML_CHECK_SIZE(sizeof (Noise_XK_session_t), (uint32_t)1U);
          Noise_XK_session_t *ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_session_t));
          ptr[0U] = st;
          res1 = ptr;
        }
        else
          res1 =
            KRML_EABORT(Noise_XK_session_t *,
              "unreachable (pattern matches are exhaustive in F*)");
        res = res1;
        break;
      }
    default:
      {
        res = NULL;
      }
  }
#ifdef WITH_SODIUM
  sodium_memzero(epriv, (uint32_t)32U * sizeof (epriv[0U]));
  sodium_memzero(epub, (uint32_t)32U * sizeof (epub[0U]));
#else // WITH_SODIUM
  Lib_Memzero0_memzero(epriv, (uint32_t)32U * sizeof (epriv[0U]));
  Lib_Memzero0_memzero(epub, (uint32_t)32U * sizeof (epub[0U]));
#endif // WITH_SODIUM
  Noise_XK_session_t *res1 = res;
  return res1;
}

/*
  Create a responder session.

  May fail and return NULL in case of invalid keys, unknown peer, etc.
*/
Noise_XK_session_t *Noise_XK_session_create_responder(Noise_XK_device_t *dvp)
{
  uint8_t epriv[32U] = { 0U };
  uint8_t epub[32U] = { 0U };
#ifdef WITH_SODIUM
  randombytes_buf(epriv, (uint32_t)32U);
#else // WITH_SODIUM
  Lib_RandomBuffer_System_crypto_random(epriv, (uint32_t)32U);
#endif // WITH_SODIUM
  Noise_XK_error_code res0 = Noise_XK_dh_secret_to_public(epub, epriv);
  Noise_XK_session_t *res;
  switch (res0)
  {
    case Noise_XK_CSuccess:
      {
        Noise_XK_device_t dv = dvp[0U];
        result_session_t res10;
        if (dv.dv_states_counter == (uint32_t)4294967295U)
          res10 =
            (
              (result_session_t){
                .tag = Fail,
                .val = { .case_Fail = Noise_XK_CIncorrect_transition }
              }
            );
        else
        {
          uint8_t *o0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          memcpy(o0, dv.dv_spriv, (uint32_t)32U * sizeof (uint8_t));
          uint8_t *st_spriv = o0;
          uint8_t *o = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          memcpy(o, dv.dv_spub, (uint32_t)32U * sizeof (uint8_t));
          uint8_t *st_spub = o;
          uint8_t *str = dv.dv_info[0U];
          bool b = str == NULL;
          uint8_t *out_str;
          if (b)
            out_str = NULL;
          else
          {
            uint32_t ip = (uint32_t)0U;
            uint32_t i0 = ip;
            uint8_t c0 = str[i0];
            bool cond = c0 != (uint8_t)0U;
            while (cond)
            {
              uint32_t i = ip;
              ip = i + (uint32_t)1U;
              uint32_t i0 = ip;
              uint8_t c = str[i0];
              cond = c != (uint8_t)0U;
            }
            uint32_t len = ip;
            if (len == (uint32_t)0U)
              out_str = NULL;
            else
            {
              KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
              uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
              uint32_t np = (uint32_t)0U;
              uint32_t n0 = np;
              uint8_t c0 = str[n0];
              bool cond = c0 != (uint8_t)0U;
              while (cond)
              {
                uint32_t n = np;
                uint8_t c = str[n];
                out_str0[n] = c;
                np = n + (uint32_t)1U;
                uint32_t n0 = np;
                uint8_t c0 = str[n0];
                cond = c0 != (uint8_t)0U;
              }
              uint32_t n = np;
              out_str0[n] = (uint8_t)0U;
              uint8_t *out_str1 = out_str0;
              out_str = out_str1;
            }
          }
          KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
          uint8_t **out_ptr0 = KRML_HOST_MALLOC(sizeof (uint8_t *));
          out_ptr0[0U] = out_str;
          Noise_XK_noise_string *st_info = out_ptr0;
          KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
          uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
          out_ptr[0U] = NULL;
          Noise_XK_noise_string *st_pinfo = out_ptr;
          dvp[0U] =
            (
              (Noise_XK_device_t){
                .dv_info = dv.dv_info,
                .dv_sk = dv.dv_sk,
                .dv_spriv = dv.dv_spriv,
                .dv_spub = dv.dv_spub,
                .dv_prologue = dv.dv_prologue,
                .dv_states_counter = dv.dv_states_counter + (uint32_t)1U,
                .dv_peers = dv.dv_peers,
                .dv_peers_counter = dv.dv_peers_counter
              }
            );
          uint8_t *st_k = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          uint8_t *st_ck0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
          uint8_t *st_h0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
          uint8_t *st_spriv1 = st_spriv;
          uint8_t *st_spub10 = st_spub;
          uint8_t *st_epriv0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          uint8_t *st_epub0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          uint8_t *st_rs = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          uint8_t *st_re = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
          Noise_XK_resp_state_t
          st =
            {
              .tag = Noise_XK_IMS_Handshake,
              .val = {
                .case_IMS_Handshake = {
                  .step = (uint32_t)0U, .cipher_key = st_k, .chaining_key = st_ck0, .h = st_h0,
                  .spriv = st_spriv1, .spub = st_spub10, .epriv = st_epriv0, .epub = st_epub0,
                  .rs = st_rs, .re = st_re
                }
              }
            };
          uint8_t
          pname[33U] =
            {
              (uint8_t)78U, (uint8_t)111U, (uint8_t)105U, (uint8_t)115U, (uint8_t)101U, (uint8_t)95U,
              (uint8_t)88U, (uint8_t)75U, (uint8_t)95U, (uint8_t)50U, (uint8_t)53U, (uint8_t)53U,
              (uint8_t)49U, (uint8_t)57U, (uint8_t)95U, (uint8_t)67U, (uint8_t)104U, (uint8_t)97U,
              (uint8_t)67U, (uint8_t)104U, (uint8_t)97U, (uint8_t)80U, (uint8_t)111U, (uint8_t)108U,
              (uint8_t)121U, (uint8_t)95U, (uint8_t)66U, (uint8_t)76U, (uint8_t)65U, (uint8_t)75U,
              (uint8_t)69U, (uint8_t)50U, (uint8_t)98U
            };
          if (st.tag == Noise_XK_IMS_Handshake)
          {
            uint8_t *st_epub = st.val.case_IMS_Handshake.epub;
            uint8_t *st_epriv = st.val.case_IMS_Handshake.epriv;
            uint8_t *st_spub1 = st.val.case_IMS_Handshake.spub;
            uint8_t *st_h = st.val.case_IMS_Handshake.h;
            uint8_t *st_ck = st.val.case_IMS_Handshake.chaining_key;
            if ((uint32_t)33U <= (uint32_t)64U)
              memcpy(st_h, pname, (uint32_t)33U * sizeof (uint8_t));
            else
              Noise_XK_hash(st_h, (uint32_t)33U, pname);
            memcpy(st_ck, st_h, (uint32_t)64U * sizeof (uint8_t));
            Noise_XK_mix_hash(st_h, dv.dv_prologue.size, dv.dv_prologue.buffer);
            memcpy(st_epriv, epriv, (uint32_t)32U * sizeof (uint8_t));
            memcpy(st_epub, epub, (uint32_t)32U * sizeof (uint8_t));
            Noise_XK_mix_hash(st_h, (uint32_t)32U, st_spub1);
          }
          else
          {
            KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
              __FILE__,
              __LINE__,
              "unreachable (pattern matches are exhaustive in F*)");
            KRML_HOST_EXIT(255U);
          }
          Noise_XK_resp_state_t st0 = st;
          result_session_t
          res1 =
            {
              .tag = Res,
              .val = {
                .case_Res = {
                  .tag = Noise_XK_DS_Responder,
                  .val = {
                    .case_DS_Responder = {
                      .state = st0, .id = dv.dv_states_counter, .info = st_info, .spriv = st_spriv,
                      .spub = st_spub, .pid = (uint32_t)0U, .pinfo = st_pinfo, .dv = dvp
                    }
                  }
                }
              }
            };
          res10 = res1;
        }
        Noise_XK_session_t *res1;
        if (res10.tag == Fail)
          res1 = NULL;
        else if (res10.tag == Res)
        {
          Noise_XK_session_t st = res10.val.case_Res;
          KRML_CHECK_SIZE(sizeof (Noise_XK_session_t), (uint32_t)1U);
          Noise_XK_session_t *ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_session_t));
          ptr[0U] = st;
          res1 = ptr;
        }
        else
          res1 =
            KRML_EABORT(Noise_XK_session_t *,
              "unreachable (pattern matches are exhaustive in F*)");
        res = res1;
        break;
      }
    default:
      {
        res = NULL;
      }
  }
#ifdef WITH_SODIUM
  sodium_memzero(epriv, (uint32_t)32U * sizeof (epriv[0U]));
  sodium_memzero(epub, (uint32_t)32U * sizeof (epub[0U]));
#else //WITH_SODIUM
  Lib_Memzero0_memzero(epriv, (uint32_t)32U * sizeof (epriv[0U]));
  Lib_Memzero0_memzero(epub, (uint32_t)32U * sizeof (epub[0U]));
#endif //WITH_SODIUM
  Noise_XK_session_t *res1 = res;
  return res1;
}

/*
  Free a session.

  Be sure to free all sessions before freeing the device used to create
  those sessions.
*/
void Noise_XK_session_free(Noise_XK_session_t *sn)
{
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_noise_string *pinfo = st.val.case_DS_Initiator.pinfo;
    uint8_t *spub = st.val.case_DS_Initiator.spub;
    uint8_t *spriv = st.val.case_DS_Initiator.spriv;
    Noise_XK_noise_string *info = st.val.case_DS_Initiator.info;
    Noise_XK_init_state_t state = st.val.case_DS_Initiator.state;
    if (state.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_re = state.val.case_IMS_Handshake.re;
      uint8_t *st_rs = state.val.case_IMS_Handshake.rs;
      uint8_t *st_epub = state.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = state.val.case_IMS_Handshake.epriv;
      uint8_t *st_h = state.val.case_IMS_Handshake.h;
      uint8_t *st_ck = state.val.case_IMS_Handshake.chaining_key;
      uint8_t *st_k = state.val.case_IMS_Handshake.cipher_key;
      KRML_HOST_FREE(st_k);
      KRML_HOST_FREE(st_ck);
      KRML_HOST_FREE(st_h);
      KRML_HOST_FREE(st_epriv);
      KRML_HOST_FREE(st_epub);
      KRML_HOST_FREE(st_rs);
      KRML_HOST_FREE(st_re);
    }
    else if (state.tag == Noise_XK_IMS_Transport)
    {
      uint8_t *receive_key = state.val.case_IMS_Transport.receive_key;
      uint8_t *send_key = state.val.case_IMS_Transport.send_key;
      uint8_t *st_h = state.val.case_IMS_Transport.h;
      KRML_HOST_FREE(st_h);
      KRML_HOST_FREE(send_key);
      KRML_HOST_FREE(receive_key);
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
    uint8_t *str = info[0U];
    if (!(str == NULL))
      KRML_HOST_FREE(str);
    KRML_HOST_FREE(info);
    uint8_t *str0 = pinfo[0U];
    if (!(str0 == NULL))
      KRML_HOST_FREE(str0);
    KRML_HOST_FREE(pinfo);
    KRML_HOST_FREE(spriv);
    KRML_HOST_FREE(spub);
  }
  else if (st.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_noise_string *pinfo = st.val.case_DS_Responder.pinfo;
    uint8_t *spub = st.val.case_DS_Responder.spub;
    uint8_t *spriv = st.val.case_DS_Responder.spriv;
    Noise_XK_noise_string *info = st.val.case_DS_Responder.info;
    Noise_XK_resp_state_t state = st.val.case_DS_Responder.state;
    if (state.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_re = state.val.case_IMS_Handshake.re;
      uint8_t *st_rs = state.val.case_IMS_Handshake.rs;
      uint8_t *st_epub = state.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = state.val.case_IMS_Handshake.epriv;
      uint8_t *st_h = state.val.case_IMS_Handshake.h;
      uint8_t *st_ck = state.val.case_IMS_Handshake.chaining_key;
      uint8_t *st_k = state.val.case_IMS_Handshake.cipher_key;
      KRML_HOST_FREE(st_k);
      KRML_HOST_FREE(st_ck);
      KRML_HOST_FREE(st_h);
      KRML_HOST_FREE(st_epriv);
      KRML_HOST_FREE(st_epub);
      KRML_HOST_FREE(st_rs);
      KRML_HOST_FREE(st_re);
    }
    else if (state.tag == Noise_XK_IMS_Transport)
    {
      uint8_t *receive_key = state.val.case_IMS_Transport.receive_key;
      uint8_t *send_key = state.val.case_IMS_Transport.send_key;
      uint8_t *st_h = state.val.case_IMS_Transport.h;
      KRML_HOST_FREE(st_h);
      KRML_HOST_FREE(send_key);
      KRML_HOST_FREE(receive_key);
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
    uint8_t *str = info[0U];
    if (!(str == NULL))
      KRML_HOST_FREE(str);
    KRML_HOST_FREE(info);
    uint8_t *str0 = pinfo[0U];
    if (!(str0 == NULL))
      KRML_HOST_FREE(str0);
    KRML_HOST_FREE(pinfo);
    KRML_HOST_FREE(spriv);
    KRML_HOST_FREE(spub);
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
  KRML_HOST_FREE(sn);
}

typedef struct result_init_state_t_s
{
  result_session_t_tags tag;
  union {
    Noise_XK_init_state_t case_Res;
    Noise_XK_error_code case_Fail;
  }
  val;
}
result_init_state_t;

typedef struct result_resp_state_t_s
{
  result_session_t_tags tag;
  union {
    Noise_XK_resp_state_t case_Res;
    Noise_XK_error_code case_Fail;
  }
  val;
}
result_resp_state_t;

static Noise_XK_error_code
state_handshake_write(
  uint32_t payload_len,
  uint8_t *payload,
  Noise_XK_session_t *dst_p,
  uint32_t outlen,
  uint8_t *out
)
{
  Noise_XK_session_t *dst_p1 = dst_p;
  Noise_XK_session_t *stp = dst_p1;
  Noise_XK_session_t dst = stp[0U];
  result_session_t res0;
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_device_t *dst_dv = dst.val.case_DS_Initiator.dv;
    Noise_XK_noise_string *dst_pinfo = dst.val.case_DS_Initiator.pinfo;
    uint32_t dst_pid = dst.val.case_DS_Initiator.pid;
    uint8_t *dst_spub = dst.val.case_DS_Initiator.spub;
    uint8_t *dst_spriv = dst.val.case_DS_Initiator.spriv;
    Noise_XK_noise_string *dst_info = dst.val.case_DS_Initiator.info;
    uint32_t dst_id = dst.val.case_DS_Initiator.id;
    Noise_XK_init_state_t dst_st = dst.val.case_DS_Initiator.state;
    if (dst_st.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_re = dst_st.val.case_IMS_Handshake.re;
      uint8_t *st_rs = dst_st.val.case_IMS_Handshake.rs;
      uint8_t *st_epub = dst_st.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = dst_st.val.case_IMS_Handshake.epriv;
      uint8_t *st_spub = dst_st.val.case_IMS_Handshake.spub;
      uint8_t *st_spriv = dst_st.val.case_IMS_Handshake.spriv;
      uint8_t *st_h = dst_st.val.case_IMS_Handshake.h;
      uint8_t *st_ck = dst_st.val.case_IMS_Handshake.chaining_key;
      uint8_t *st_cipher = dst_st.val.case_IMS_Handshake.cipher_key;
      uint32_t st_step = dst_st.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)3U)
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else if (!(true == (st_step % (uint32_t)2U == (uint32_t)0U)))
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else
      {
        result_init_state_t res1;
        if (st_step == (uint32_t)0U)
        {
          result_init_state_t res;
          if (!(payload_len <= (uint32_t)4294967215U && outlen == (uint32_t)48U + payload_len))
            res =
              ((result_init_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
          else
          {
            uint32_t pat_outlen = (uint32_t)32U;
            uint8_t *pat_out = out;
            uint8_t *payload_out = out + pat_outlen;
            uint8_t *tk_out = pat_out;
            Noise_XK_mix_hash(st_h, (uint32_t)32U, st_epub);
            memcpy(tk_out, st_epub, (uint32_t)32U * sizeof (uint8_t));
            Noise_XK_error_code r0 = Noise_XK_mix_dh(st_epriv, st_rs, st_cipher, st_ck, st_h);
            Noise_XK_error_code r2 = r0;
            Noise_XK_error_code r1 = r2;
            Noise_XK_error_code r;
            if (!(r1 == Noise_XK_CSuccess))
              r = r1;
            else
            {
              Noise_XK_encrypt_and_hash(payload_len,
                payload,
                payload_out,
                st_cipher,
                st_h,
                (uint64_t)0U);
              r = Noise_XK_CSuccess;
            }
            Noise_XK_error_code res0 = r;
            if (res0 == Noise_XK_CSuccess)
              res =
                (
                  (result_init_state_t){
                    .tag = Res,
                    .val = {
                      .case_Res = {
                        .tag = Noise_XK_IMS_Handshake,
                        .val = {
                          .case_IMS_Handshake = {
                            .step = st_step + (uint32_t)1U, .cipher_key = st_cipher,
                            .chaining_key = st_ck, .h = st_h, .spriv = st_spriv, .spub = st_spub,
                            .epriv = st_epriv, .epub = st_epub, .rs = st_rs, .re = st_re
                          }
                        }
                      }
                    }
                  }
                );
            else
              switch (res0)
              {
                case Noise_XK_CDH_error:
                  {
                    res =
                      (
                        (result_init_state_t){
                          .tag = Fail,
                          .val = { .case_Fail = Noise_XK_CDH_error }
                        }
                      );
                    break;
                  }
                default:
                  {
                    KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
                    KRML_HOST_EXIT(253U);
                  }
              }
          }
          result_init_state_t res0 = res;
          res1 = res0;
        }
        else
        {
          result_init_state_t res;
          if (!(payload_len <= (uint32_t)4294967215U && outlen == (uint32_t)64U + payload_len))
            res =
              ((result_init_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
          else
          {
            uint32_t pat_outlen = (uint32_t)48U;
            uint8_t *pat_out = out;
            uint8_t *payload_out = out + pat_outlen;
            uint8_t *tk_out = pat_out;
            Noise_XK_encrypt_and_hash((uint32_t)32U,
              st_spub,
              tk_out,
              st_cipher,
              st_h,
              (uint64_t)1U);
            Noise_XK_error_code r0 = Noise_XK_mix_dh(st_spriv, st_re, st_cipher, st_ck, st_h);
            Noise_XK_error_code r2 = r0;
            Noise_XK_error_code r1 = r2;
            Noise_XK_error_code r;
            if (!(r1 == Noise_XK_CSuccess))
              r = r1;
            else
            {
              Noise_XK_encrypt_and_hash(payload_len,
                payload,
                payload_out,
                st_cipher,
                st_h,
                (uint64_t)0U);
              r = Noise_XK_CSuccess;
            }
            Noise_XK_error_code res0 = r;
            if (res0 == Noise_XK_CSuccess)
              res =
                (
                  (result_init_state_t){
                    .tag = Res,
                    .val = {
                      .case_Res = {
                        .tag = Noise_XK_IMS_Handshake,
                        .val = {
                          .case_IMS_Handshake = {
                            .step = st_step + (uint32_t)1U, .cipher_key = st_cipher,
                            .chaining_key = st_ck, .h = st_h, .spriv = st_spriv, .spub = st_spub,
                            .epriv = st_epriv, .epub = st_epub, .rs = st_rs, .re = st_re
                          }
                        }
                      }
                    }
                  }
                );
            else
              switch (res0)
              {
                case Noise_XK_CDH_error:
                  {
                    res =
                      (
                        (result_init_state_t){
                          .tag = Fail,
                          .val = { .case_Fail = Noise_XK_CDH_error }
                        }
                      );
                    break;
                  }
                default:
                  {
                    KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
                    KRML_HOST_EXIT(253U);
                  }
              }
          }
          result_init_state_t res0 = res;
          res1 = res0;
        }
        if (res1.tag == Fail)
        {
          Noise_XK_error_code e = res1.val.case_Fail;
          res0 = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
        }
        else if (res1.tag == Res)
        {
          Noise_XK_init_state_t st1 = res1.val.case_Res;
          Noise_XK_session_t ite;
          if (st_step == (uint32_t)2U)
          {
            Noise_XK_init_state_t st11;
            if (st1.tag == Noise_XK_IMS_Handshake)
            {
              uint8_t *st_re1 = st1.val.case_IMS_Handshake.re;
              uint8_t *st_rs1 = st1.val.case_IMS_Handshake.rs;
              uint8_t *st_epub1 = st1.val.case_IMS_Handshake.epub;
              uint8_t *st_epriv1 = st1.val.case_IMS_Handshake.epriv;
              uint8_t *st_h1 = st1.val.case_IMS_Handshake.h;
              uint8_t *st_ck1 = st1.val.case_IMS_Handshake.chaining_key;
              uint8_t *st_k = st1.val.case_IMS_Handshake.cipher_key;
              uint8_t *k1 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
              uint8_t *k2 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
              uint8_t temp_k1[64U] = { 0U };
              uint8_t temp_k2[64U] = { 0U };
              Noise_XK_kdf(st_ck1, (uint32_t)0U, NULL, temp_k1, temp_k2, NULL);
              memcpy(k1, temp_k1, (uint32_t)32U * sizeof (uint8_t));
              memcpy(k2, temp_k2, (uint32_t)32U * sizeof (uint8_t));
#ifdef WITH_SODIUM
              sodium_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
              sodium_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#else // WITH_SODIUM
              Lib_Memzero0_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
              Lib_Memzero0_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#endif // WITH_SODIUM
              KRML_HOST_FREE(st_k);
              KRML_HOST_FREE(st_ck1);
              KRML_HOST_FREE(st_epriv1);
              KRML_HOST_FREE(st_epub1);
              KRML_HOST_FREE(st_rs1);
              KRML_HOST_FREE(st_re1);
              st11 =
                (
                  (Noise_XK_init_state_t){
                    .tag = Noise_XK_IMS_Transport,
                    .val = {
                      .case_IMS_Transport = {
                        .h = st_h1, .recv_transport_message = false, .send_key = k1,
                        .send_nonce = (uint64_t)0U, .receive_key = k2, .receive_nonce = (uint64_t)0U
                      }
                    }
                  }
                );
            }
            else
              st11 =
                KRML_EABORT(Noise_XK_init_state_t,
                  "unreachable (pattern matches are exhaustive in F*)");
            ite =
              (
                (Noise_XK_session_t){
                  .tag = Noise_XK_DS_Initiator,
                  .val = {
                    .case_DS_Initiator = {
                      .state = st11, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                      .spub = dst_spub, .pid = dst_pid, .pinfo = dst_pinfo, .dv = dst_dv
                    }
                  }
                }
              );
          }
          else
            ite =
              (
                (Noise_XK_session_t){
                  .tag = Noise_XK_DS_Initiator,
                  .val = {
                    .case_DS_Initiator = {
                      .state = st1, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                      .spub = dst_spub, .pid = dst_pid, .pinfo = dst_pinfo, .dv = dst_dv
                    }
                  }
                }
              );
          res0 = ((result_session_t){ .tag = Res, .val = { .case_Res = ite } });
        }
        else
          res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
      }
    }
    else if (dst_st.tag == Noise_XK_IMS_Transport)
      res0 =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
    else
      res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_device_t *dst_dv = dst.val.case_DS_Responder.dv;
    Noise_XK_noise_string *dst_pinfo = dst.val.case_DS_Responder.pinfo;
    uint32_t dst_pid = dst.val.case_DS_Responder.pid;
    uint8_t *dst_spub = dst.val.case_DS_Responder.spub;
    uint8_t *dst_spriv = dst.val.case_DS_Responder.spriv;
    Noise_XK_noise_string *dst_info = dst.val.case_DS_Responder.info;
    uint32_t dst_id = dst.val.case_DS_Responder.id;
    Noise_XK_resp_state_t dst_st = dst.val.case_DS_Responder.state;
    if (dst_st.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_re = dst_st.val.case_IMS_Handshake.re;
      uint8_t *st_rs = dst_st.val.case_IMS_Handshake.rs;
      uint8_t *st_epub = dst_st.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = dst_st.val.case_IMS_Handshake.epriv;
      uint8_t *st_spub = dst_st.val.case_IMS_Handshake.spub;
      uint8_t *st_spriv = dst_st.val.case_IMS_Handshake.spriv;
      uint8_t *st_h = dst_st.val.case_IMS_Handshake.h;
      uint8_t *st_ck = dst_st.val.case_IMS_Handshake.chaining_key;
      uint8_t *st_cipher = dst_st.val.case_IMS_Handshake.cipher_key;
      uint32_t st_step = dst_st.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)3U)
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else if (!(false == (st_step % (uint32_t)2U == (uint32_t)0U)))
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else
      {
        result_resp_state_t res;
        if (!(payload_len <= (uint32_t)4294967215U && outlen == (uint32_t)48U + payload_len))
          res = ((result_resp_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
        else
        {
          uint32_t pat_outlen = (uint32_t)32U;
          uint8_t *pat_out = out;
          uint8_t *payload_out = out + pat_outlen;
          uint8_t *tk_out = pat_out;
          Noise_XK_mix_hash(st_h, (uint32_t)32U, st_epub);
          memcpy(tk_out, st_epub, (uint32_t)32U * sizeof (uint8_t));
          Noise_XK_error_code r0 = Noise_XK_mix_dh(st_epriv, st_re, st_cipher, st_ck, st_h);
          Noise_XK_error_code r2 = r0;
          Noise_XK_error_code r1 = r2;
          Noise_XK_error_code r;
          if (!(r1 == Noise_XK_CSuccess))
            r = r1;
          else
          {
            Noise_XK_encrypt_and_hash(payload_len,
              payload,
              payload_out,
              st_cipher,
              st_h,
              (uint64_t)0U);
            r = Noise_XK_CSuccess;
          }
          Noise_XK_error_code res0 = r;
          if (res0 == Noise_XK_CSuccess)
            res =
              (
                (result_resp_state_t){
                  .tag = Res,
                  .val = {
                    .case_Res = {
                      .tag = Noise_XK_IMS_Handshake,
                      .val = {
                        .case_IMS_Handshake = {
                          .step = st_step + (uint32_t)1U, .cipher_key = st_cipher,
                          .chaining_key = st_ck, .h = st_h, .spriv = st_spriv, .spub = st_spub,
                          .epriv = st_epriv, .epub = st_epub, .rs = st_rs, .re = st_re
                        }
                      }
                    }
                  }
                }
              );
          else
            switch (res0)
            {
              case Noise_XK_CDH_error:
                {
                  res =
                    (
                      (result_resp_state_t){
                        .tag = Fail,
                        .val = { .case_Fail = Noise_XK_CDH_error }
                      }
                    );
                  break;
                }
              default:
                {
                  KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
                  KRML_HOST_EXIT(253U);
                }
            }
        }
        result_resp_state_t res1 = res;
        result_resp_state_t res2 = res1;
        if (res2.tag == Fail)
        {
          Noise_XK_error_code e = res2.val.case_Fail;
          res0 = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
        }
        else if (res2.tag == Res)
        {
          Noise_XK_resp_state_t st1 = res2.val.case_Res;
          Noise_XK_session_t ite;
          if (st_step == (uint32_t)2U)
          {
            Noise_XK_resp_state_t st11;
            if (st1.tag == Noise_XK_IMS_Handshake)
            {
              uint8_t *st_re1 = st1.val.case_IMS_Handshake.re;
              uint8_t *st_rs1 = st1.val.case_IMS_Handshake.rs;
              uint8_t *st_epub1 = st1.val.case_IMS_Handshake.epub;
              uint8_t *st_epriv1 = st1.val.case_IMS_Handshake.epriv;
              uint8_t *st_h1 = st1.val.case_IMS_Handshake.h;
              uint8_t *st_ck1 = st1.val.case_IMS_Handshake.chaining_key;
              uint8_t *st_k = st1.val.case_IMS_Handshake.cipher_key;
              uint8_t *k1 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
              uint8_t *k2 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
              uint8_t temp_k1[64U] = { 0U };
              uint8_t temp_k2[64U] = { 0U };
              Noise_XK_kdf(st_ck1, (uint32_t)0U, NULL, temp_k1, temp_k2, NULL);
              memcpy(k1, temp_k1, (uint32_t)32U * sizeof (uint8_t));
              memcpy(k2, temp_k2, (uint32_t)32U * sizeof (uint8_t));
#ifdef WITH_SODIUM
              sodium_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
              sodium_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#else // WITH_SODIUM
              Lib_Memzero0_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
              Lib_Memzero0_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#endif // WITH_SODIUM
              KRML_HOST_FREE(st_k);
              KRML_HOST_FREE(st_ck1);
              KRML_HOST_FREE(st_epriv1);
              KRML_HOST_FREE(st_epub1);
              KRML_HOST_FREE(st_rs1);
              KRML_HOST_FREE(st_re1);
              st11 =
                (
                  (Noise_XK_resp_state_t){
                    .tag = Noise_XK_IMS_Transport,
                    .val = {
                      .case_IMS_Transport = {
                        .h = st_h1, .send_key = k2, .send_nonce = (uint64_t)0U, .receive_key = k1,
                        .receive_nonce = (uint64_t)0U
                      }
                    }
                  }
                );
            }
            else
              st11 =
                KRML_EABORT(Noise_XK_resp_state_t,
                  "unreachable (pattern matches are exhaustive in F*)");
            ite =
              (
                (Noise_XK_session_t){
                  .tag = Noise_XK_DS_Responder,
                  .val = {
                    .case_DS_Responder = {
                      .state = st11, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                      .spub = dst_spub, .pid = dst_pid, .pinfo = dst_pinfo, .dv = dst_dv
                    }
                  }
                }
              );
          }
          else
            ite =
              (
                (Noise_XK_session_t){
                  .tag = Noise_XK_DS_Responder,
                  .val = {
                    .case_DS_Responder = {
                      .state = st1, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                      .spub = dst_spub, .pid = dst_pid, .pinfo = dst_pinfo, .dv = dst_dv
                    }
                  }
                }
              );
          res0 = ((result_session_t){ .tag = Res, .val = { .case_Res = ite } });
        }
        else
          res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
      }
    }
    else if (dst_st.tag == Noise_XK_IMS_Transport)
      res0 =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
    else
      res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  }
  else
    res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  if (res0.tag == Fail)
  {
    Noise_XK_error_code e = res0.val.case_Fail;
    Noise_XK_session_t dst1 = dst_p1[0U];
    if (dst1.tag == Noise_XK_DS_Initiator)
    {
      Noise_XK_device_t *dv = dst1.val.case_DS_Initiator.dv;
      Noise_XK_noise_string *pinfo = dst1.val.case_DS_Initiator.pinfo;
      uint32_t pid = dst1.val.case_DS_Initiator.pid;
      uint8_t *spub = dst1.val.case_DS_Initiator.spub;
      uint8_t *spriv = dst1.val.case_DS_Initiator.spriv;
      Noise_XK_noise_string *info = dst1.val.case_DS_Initiator.info;
      uint32_t id = dst1.val.case_DS_Initiator.id;
      Noise_XK_init_state_t st = dst1.val.case_DS_Initiator.state;
      Noise_XK_init_state_t ite;
      if (st.tag == Noise_XK_IMS_Handshake)
      {
        uint8_t *re = st.val.case_IMS_Handshake.re;
        uint8_t *rs = st.val.case_IMS_Handshake.rs;
        uint8_t *epub = st.val.case_IMS_Handshake.epub;
        uint8_t *epriv = st.val.case_IMS_Handshake.epriv;
        uint8_t *spub1 = st.val.case_IMS_Handshake.spub;
        uint8_t *spriv1 = st.val.case_IMS_Handshake.spriv;
        uint8_t *h3 = st.val.case_IMS_Handshake.h;
        uint8_t *ck = st.val.case_IMS_Handshake.chaining_key;
        uint8_t *k = st.val.case_IMS_Handshake.cipher_key;
        ite =
          (
            (Noise_XK_init_state_t){
              .tag = Noise_XK_IMS_Handshake,
              .val = {
                .case_IMS_Handshake = {
                  .step = (uint32_t)4U, .cipher_key = k, .chaining_key = ck, .h = h3,
                  .spriv = spriv1, .spub = spub1, .epriv = epriv, .epub = epub, .rs = rs, .re = re
                }
              }
            }
          );
      }
      else if (st.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = st.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = st.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = st.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = st.val.case_IMS_Transport.send_key;
        bool recv_tpt_msg = st.val.case_IMS_Transport.recv_transport_message;
        uint8_t *h3 = st.val.case_IMS_Transport.h;
        ite =
          (
            (Noise_XK_init_state_t){
              .tag = Noise_XK_IMS_Transport,
              .val = {
                .case_IMS_Transport = {
                  .h = h3, .recv_transport_message = recv_tpt_msg, .send_key = send_key,
                  .send_nonce = send_nonce, .receive_key = receive_key,
                  .receive_nonce = receive_nonce
                }
              }
            }
          );
      }
      else
        ite =
          KRML_EABORT(Noise_XK_init_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      dst_p1[0U] =
        (
          (Noise_XK_session_t){
            .tag = Noise_XK_DS_Initiator,
            .val = {
              .case_DS_Initiator = {
                .state = ite, .id = id, .info = info, .spriv = spriv, .spub = spub, .pid = pid,
                .pinfo = pinfo, .dv = dv
              }
            }
          }
        );
    }
    else if (dst1.tag == Noise_XK_DS_Responder)
    {
      Noise_XK_device_t *dv = dst1.val.case_DS_Responder.dv;
      Noise_XK_noise_string *pinfo = dst1.val.case_DS_Responder.pinfo;
      uint32_t pid = dst1.val.case_DS_Responder.pid;
      uint8_t *spub = dst1.val.case_DS_Responder.spub;
      uint8_t *spriv = dst1.val.case_DS_Responder.spriv;
      Noise_XK_noise_string *info = dst1.val.case_DS_Responder.info;
      uint32_t id = dst1.val.case_DS_Responder.id;
      Noise_XK_resp_state_t st = dst1.val.case_DS_Responder.state;
      Noise_XK_resp_state_t ite;
      if (st.tag == Noise_XK_IMS_Handshake)
      {
        uint8_t *re = st.val.case_IMS_Handshake.re;
        uint8_t *rs = st.val.case_IMS_Handshake.rs;
        uint8_t *epub = st.val.case_IMS_Handshake.epub;
        uint8_t *epriv = st.val.case_IMS_Handshake.epriv;
        uint8_t *spub1 = st.val.case_IMS_Handshake.spub;
        uint8_t *spriv1 = st.val.case_IMS_Handshake.spriv;
        uint8_t *h3 = st.val.case_IMS_Handshake.h;
        uint8_t *ck = st.val.case_IMS_Handshake.chaining_key;
        uint8_t *k = st.val.case_IMS_Handshake.cipher_key;
        ite =
          (
            (Noise_XK_resp_state_t){
              .tag = Noise_XK_IMS_Handshake,
              .val = {
                .case_IMS_Handshake = {
                  .step = (uint32_t)4U, .cipher_key = k, .chaining_key = ck, .h = h3,
                  .spriv = spriv1, .spub = spub1, .epriv = epriv, .epub = epub, .rs = rs, .re = re
                }
              }
            }
          );
      }
      else if (st.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = st.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = st.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = st.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = st.val.case_IMS_Transport.send_key;
        uint8_t *h3 = st.val.case_IMS_Transport.h;
        ite =
          (
            (Noise_XK_resp_state_t){
              .tag = Noise_XK_IMS_Transport,
              .val = {
                .case_IMS_Transport = {
                  .h = h3, .send_key = send_key, .send_nonce = send_nonce,
                  .receive_key = receive_key, .receive_nonce = receive_nonce
                }
              }
            }
          );
      }
      else
        ite =
          KRML_EABORT(Noise_XK_resp_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      dst_p1[0U] =
        (
          (Noise_XK_session_t){
            .tag = Noise_XK_DS_Responder,
            .val = {
              .case_DS_Responder = {
                .state = ite, .id = id, .info = info, .spriv = spriv, .spub = spub, .pid = pid,
                .pinfo = pinfo, .dv = dv
              }
            }
          }
        );
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
    return e;
  }
  else if (res0.tag == Res)
  {
    Noise_XK_session_t dst1 = res0.val.case_Res;
    dst_p1[0U] = dst1;
    return Noise_XK_CSuccess;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

#define Res0 0
#define Fail0 1

typedef uint8_t result_unit_error_tags;

typedef struct result_unit_error_s
{
  result_unit_error_tags tag;
  Noise_XK_error_code v;
}
result_unit_error;

static Noise_XK_error_code
state_handshake_read(
  uint32_t payload_outlen,
  uint8_t *payload_out,
  Noise_XK_session_t *dst_p,
  uint32_t inlen,
  uint8_t *input
)
{
  Noise_XK_session_t dst = dst_p[0U];
  uint32_t pid;
  if (dst.tag == Noise_XK_DS_Initiator)
    pid = dst.val.case_DS_Initiator.pid;
  else if (dst.tag == Noise_XK_DS_Responder)
    pid = dst.val.case_DS_Responder.pid;
  else
    pid = KRML_EABORT(uint32_t, "unreachable (pattern matches are exhaustive in F*)");
  uint32_t *pid_ptr = KRML_HOST_MALLOC(sizeof (uint32_t));
  pid_ptr[0U] = pid;
  result_session_t res0;
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_device_t *dst_dv = dst.val.case_DS_Initiator.dv;
    Noise_XK_noise_string *dst_pinfo = dst.val.case_DS_Initiator.pinfo;
    uint32_t dst_pid = dst.val.case_DS_Initiator.pid;
    uint8_t *dst_spub = dst.val.case_DS_Initiator.spub;
    uint8_t *dst_spriv = dst.val.case_DS_Initiator.spriv;
    Noise_XK_noise_string *dst_info = dst.val.case_DS_Initiator.info;
    uint32_t dst_id = dst.val.case_DS_Initiator.id;
    Noise_XK_init_state_t dst_st = dst.val.case_DS_Initiator.state;
    if (dst_st.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_re = dst_st.val.case_IMS_Handshake.re;
      uint8_t *st_rs = dst_st.val.case_IMS_Handshake.rs;
      uint8_t *st_epub = dst_st.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = dst_st.val.case_IMS_Handshake.epriv;
      uint8_t *st_spub = dst_st.val.case_IMS_Handshake.spub;
      uint8_t *st_spriv = dst_st.val.case_IMS_Handshake.spriv;
      uint8_t *st_h = dst_st.val.case_IMS_Handshake.h;
      uint8_t *st_ck = dst_st.val.case_IMS_Handshake.chaining_key;
      uint8_t *st_cipher = dst_st.val.case_IMS_Handshake.cipher_key;
      uint32_t st_step = dst_st.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)3U)
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else if (!(true == (st_step % (uint32_t)2U == (uint32_t)1U)))
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else
      {
        Noise_XK_error_code r0;
        if (!(payload_outlen <= (uint32_t)4294967215U && inlen == (uint32_t)48U + payload_outlen))
          r0 = Noise_XK_CInput_size;
        else
        {
          uint8_t *msg_input = input;
          uint8_t *payload_input = input + (uint32_t)32U;
          uint8_t *tk_input = msg_input;
          Noise_XK_mix_hash(st_h, (uint32_t)32U, tk_input);
          memcpy(st_re, tk_input, (uint32_t)32U * sizeof (uint8_t));
          Noise_XK_error_code r20 = Noise_XK_mix_dh(st_epriv, st_re, st_cipher, st_ck, st_h);
          Noise_XK_error_code r1 = r20;
          Noise_XK_error_code r;
          if (!(r1 == Noise_XK_CSuccess))
            r = r1;
          else
          {
            Noise_XK_error_code
            r2 =
              Noise_XK_decrypt_and_hash(payload_outlen,
                payload_out,
                payload_input,
                st_cipher,
                st_h,
                (uint64_t)0U);
            r = r2;
          }
          Noise_XK_error_code r2 = r;
          Noise_XK_error_code res = r2;
          if (res == Noise_XK_CSuccess)
            r0 = Noise_XK_CSuccess;
          else
            r0 = res;
        }
        Noise_XK_error_code r1 = r0;
        result_init_state_t r;
        switch (r1)
        {
          case Noise_XK_CSuccess:
            {
              r =
                (
                  (result_init_state_t){
                    .tag = Res,
                    .val = {
                      .case_Res = {
                        .tag = Noise_XK_IMS_Handshake,
                        .val = {
                          .case_IMS_Handshake = {
                            .step = st_step + (uint32_t)1U, .cipher_key = st_cipher,
                            .chaining_key = st_ck, .h = st_h, .spriv = st_spriv, .spub = st_spub,
                            .epriv = st_epriv, .epub = st_epub, .rs = st_rs, .re = st_re
                          }
                        }
                      }
                    }
                  }
                );
              break;
            }
          default:
            {
              r = ((result_init_state_t){ .tag = Fail, .val = { .case_Fail = r1 } });
            }
        }
        result_init_state_t res1 = r;
        result_init_state_t res2 = res1;
        result_session_t res;
        if (res2.tag == Fail)
        {
          Noise_XK_error_code e = res2.val.case_Fail;
          res = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
        }
        else if (res2.tag == Res)
        {
          Noise_XK_init_state_t st1 = res2.val.case_Res;
          if (!(st_step == (uint32_t)2U))
            res =
              (
                (result_session_t){
                  .tag = Res,
                  .val = {
                    .case_Res = {
                      .tag = Noise_XK_DS_Initiator,
                      .val = {
                        .case_DS_Initiator = {
                          .state = st1, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                          .spub = dst_spub, .pid = dst_pid, .pinfo = dst_pinfo, .dv = dst_dv
                        }
                      }
                    }
                  }
                }
              );
          else
          {
            uint32_t pid1 = pid_ptr[0U];
            res =
              (
                (result_session_t){
                  .tag = Res,
                  .val = {
                    .case_Res = {
                      .tag = Noise_XK_DS_Initiator,
                      .val = {
                        .case_DS_Initiator = {
                          .state = st1, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                          .spub = dst_spub, .pid = pid1, .pinfo = dst_pinfo, .dv = dst_dv
                        }
                      }
                    }
                  }
                }
              );
          }
        }
        else
          res = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
        if (res.tag == Fail)
        {
          Noise_XK_error_code e = res.val.case_Fail;
          res0 = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
        }
        else if (res.tag == Res)
        {
          Noise_XK_session_t dst1 = res.val.case_Res;
          Noise_XK_session_t dst2;
          if (dst1.tag == Noise_XK_DS_Initiator)
          {
            Noise_XK_device_t *dv = dst1.val.case_DS_Initiator.dv;
            Noise_XK_noise_string *pinfo = dst1.val.case_DS_Initiator.pinfo;
            uint32_t pid1 = dst1.val.case_DS_Initiator.pid;
            uint8_t *spub = dst1.val.case_DS_Initiator.spub;
            uint8_t *spriv = dst1.val.case_DS_Initiator.spriv;
            Noise_XK_noise_string *info = dst1.val.case_DS_Initiator.info;
            uint32_t id = dst1.val.case_DS_Initiator.id;
            Noise_XK_init_state_t st = dst1.val.case_DS_Initiator.state;
            if (st_step == (uint32_t)2U)
            {
              Noise_XK_init_state_t st1;
              if (st.tag == Noise_XK_IMS_Handshake)
              {
                uint8_t *st_re1 = st.val.case_IMS_Handshake.re;
                uint8_t *st_rs1 = st.val.case_IMS_Handshake.rs;
                uint8_t *st_epub1 = st.val.case_IMS_Handshake.epub;
                uint8_t *st_epriv1 = st.val.case_IMS_Handshake.epriv;
                uint8_t *st_h1 = st.val.case_IMS_Handshake.h;
                uint8_t *st_ck1 = st.val.case_IMS_Handshake.chaining_key;
                uint8_t *st_k = st.val.case_IMS_Handshake.cipher_key;
                uint8_t *k1 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
                uint8_t *k2 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
                uint8_t temp_k1[64U] = { 0U };
                uint8_t temp_k2[64U] = { 0U };
                Noise_XK_kdf(st_ck1, (uint32_t)0U, NULL, temp_k1, temp_k2, NULL);
                memcpy(k1, temp_k1, (uint32_t)32U * sizeof (uint8_t));
                memcpy(k2, temp_k2, (uint32_t)32U * sizeof (uint8_t));
#ifdef WITH_SODIUM
                sodium_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
                sodium_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#else // WITH_SODIUM
                Lib_Memzero0_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
                Lib_Memzero0_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#endif // WITH_SODIUM
                KRML_HOST_FREE(st_k);
                KRML_HOST_FREE(st_ck1);
                KRML_HOST_FREE(st_epriv1);
                KRML_HOST_FREE(st_epub1);
                KRML_HOST_FREE(st_rs1);
                KRML_HOST_FREE(st_re1);
                st1 =
                  (
                    (Noise_XK_init_state_t){
                      .tag = Noise_XK_IMS_Transport,
                      .val = {
                        .case_IMS_Transport = {
                          .h = st_h1, .recv_transport_message = false, .send_key = k1,
                          .send_nonce = (uint64_t)0U, .receive_key = k2,
                          .receive_nonce = (uint64_t)0U
                        }
                      }
                    }
                  );
              }
              else
                st1 =
                  KRML_EABORT(Noise_XK_init_state_t,
                    "unreachable (pattern matches are exhaustive in F*)");
              dst2 =
                (
                  (Noise_XK_session_t){
                    .tag = Noise_XK_DS_Initiator,
                    .val = {
                      .case_DS_Initiator = {
                        .state = st1, .id = id, .info = info, .spriv = spriv, .spub = spub,
                        .pid = pid1, .pinfo = pinfo, .dv = dv
                      }
                    }
                  }
                );
            }
            else
              dst2 =
                (
                  (Noise_XK_session_t){
                    .tag = Noise_XK_DS_Initiator,
                    .val = {
                      .case_DS_Initiator = {
                        .state = st, .id = id, .info = info, .spriv = spriv, .spub = spub,
                        .pid = pid1, .pinfo = pinfo, .dv = dv
                      }
                    }
                  }
                );
          }
          else
            dst2 =
              KRML_EABORT(Noise_XK_session_t,
                "unreachable (pattern matches are exhaustive in F*)");
          res0 = ((result_session_t){ .tag = Res, .val = { .case_Res = dst2 } });
        }
        else
          res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
      }
    }
    else if (dst_st.tag == Noise_XK_IMS_Transport)
      res0 =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
    else
      res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_device_t *dst_dv = dst.val.case_DS_Responder.dv;
    Noise_XK_noise_string *dst_pinfo = dst.val.case_DS_Responder.pinfo;
    uint32_t dst_pid = dst.val.case_DS_Responder.pid;
    uint8_t *dst_spub = dst.val.case_DS_Responder.spub;
    uint8_t *dst_spriv = dst.val.case_DS_Responder.spriv;
    Noise_XK_noise_string *dst_info = dst.val.case_DS_Responder.info;
    uint32_t dst_id = dst.val.case_DS_Responder.id;
    Noise_XK_resp_state_t dst_st = dst.val.case_DS_Responder.state;
    if (dst_st.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_re = dst_st.val.case_IMS_Handshake.re;
      uint8_t *st_rs = dst_st.val.case_IMS_Handshake.rs;
      uint8_t *st_epub = dst_st.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = dst_st.val.case_IMS_Handshake.epriv;
      uint8_t *st_spub = dst_st.val.case_IMS_Handshake.spub;
      uint8_t *st_spriv = dst_st.val.case_IMS_Handshake.spriv;
      uint8_t *st_h = dst_st.val.case_IMS_Handshake.h;
      uint8_t *st_ck = dst_st.val.case_IMS_Handshake.chaining_key;
      uint8_t *st_cipher = dst_st.val.case_IMS_Handshake.cipher_key;
      uint32_t st_step = dst_st.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)3U)
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else if (!(false == (st_step % (uint32_t)2U == (uint32_t)1U)))
        res0 =
          (
            (result_session_t){
              .tag = Fail,
              .val = { .case_Fail = Noise_XK_CIncorrect_transition }
            }
          );
      else
      {
        Noise_XK_device_t dv0 = dst_dv[0U];
        result_resp_state_t res1;
        if (st_step == (uint32_t)0U)
        {
          Noise_XK_error_code r0;
          if (!(payload_outlen <= (uint32_t)4294967215U && inlen == (uint32_t)48U + payload_outlen))
            r0 = Noise_XK_CInput_size;
          else
          {
            uint8_t *msg_input = input;
            uint8_t *payload_input = input + (uint32_t)32U;
            uint8_t *tk_input = msg_input;
            Noise_XK_mix_hash(st_h, (uint32_t)32U, tk_input);
            memcpy(st_re, tk_input, (uint32_t)32U * sizeof (uint8_t));
            Noise_XK_error_code r20 = Noise_XK_mix_dh(st_spriv, st_re, st_cipher, st_ck, st_h);
            Noise_XK_error_code r1 = r20;
            Noise_XK_error_code r;
            if (!(r1 == Noise_XK_CSuccess))
              r = r1;
            else
            {
              Noise_XK_error_code
              r2 =
                Noise_XK_decrypt_and_hash(payload_outlen,
                  payload_out,
                  payload_input,
                  st_cipher,
                  st_h,
                  (uint64_t)0U);
              r = r2;
            }
            Noise_XK_error_code r2 = r;
            Noise_XK_error_code res = r2;
            if (res == Noise_XK_CSuccess)
              r0 = Noise_XK_CSuccess;
            else
              r0 = res;
          }
          Noise_XK_error_code r1 = r0;
          result_resp_state_t r;
          switch (r1)
          {
            case Noise_XK_CSuccess:
              {
                r =
                  (
                    (result_resp_state_t){
                      .tag = Res,
                      .val = {
                        .case_Res = {
                          .tag = Noise_XK_IMS_Handshake,
                          .val = {
                            .case_IMS_Handshake = {
                              .step = st_step + (uint32_t)1U, .cipher_key = st_cipher,
                              .chaining_key = st_ck, .h = st_h, .spriv = st_spriv, .spub = st_spub,
                              .epriv = st_epriv, .epub = st_epub, .rs = st_rs, .re = st_re
                            }
                          }
                        }
                      }
                    }
                  );
                break;
              }
            default:
              {
                r = ((result_resp_state_t){ .tag = Fail, .val = { .case_Fail = r1 } });
              }
          }
          result_resp_state_t res = r;
          res1 = res;
        }
        else
        {
          result_unit_error r0;
          if (!(payload_outlen <= (uint32_t)4294967215U && inlen == (uint32_t)64U + payload_outlen))
            r0 = ((result_unit_error){ .tag = Fail0, .v = Noise_XK_CInput_size });
          else
          {
            uint8_t *msg1 = input;
            uint8_t *msg2 = input + (uint32_t)48U;
            Noise_XK_error_code
            r1 =
              Noise_XK_decrypt_and_hash((uint32_t)32U,
                st_rs,
                msg1,
                st_cipher,
                st_h,
                (uint64_t)1U);
            Noise_XK_error_code r3 = r1;
            Noise_XK_error_code r10 = r3;
            if (r10 == Noise_XK_CSuccess)
            {
              Noise_XK_cell **peers1 = dv0.dv_peers;
              Noise_XK_cell *llt = *peers1;
              Noise_XK_cell *lltp = llt;
              Noise_XK_cell *llt10 = lltp;
              bool b0;
              if (llt10 == NULL)
                b0 = false;
              else
              {
                Noise_XK_cell c = llt10[0U];
                Noise_XK_peer_t x = c.data[0U];
                bool b = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, st_rs);
                b0 = !b;
              }
              bool cond = b0;
              while (cond)
              {
                Noise_XK_cell *llt1 = lltp;
                Noise_XK_cell c0 = llt1[0U];
                lltp = c0.next;
                Noise_XK_cell *llt10 = lltp;
                bool b;
                if (llt10 == NULL)
                  b = false;
                else
                {
                  Noise_XK_cell c = llt10[0U];
                  Noise_XK_peer_t x = c.data[0U];
                  bool b0 = Noise_XK_lbytes_eq((uint32_t)32U, x.p_s, st_rs);
                  b = !b0;
                }
                cond = b;
              }
              Noise_XK_cell *llt1 = *&lltp;
              Noise_XK_peer_t *res;
              if (llt1 == NULL)
                res = NULL;
              else
              {
                Noise_XK_cell c = *llt1;
                res = c.data;
              }
              Noise_XK_peer_t *peer_ptr = res;
              bool b1;
              if (!(peer_ptr == NULL))
              {
                Noise_XK_peer_t peer = peer_ptr[0U];
                uint8_t *input_str = peer.p_info[0U];
                bool b = input_str == NULL;
                uint8_t *out_str;
                if (b)
                  out_str = NULL;
                else
                {
                  uint32_t ip = (uint32_t)0U;
                  uint32_t i0 = ip;
                  uint8_t c0 = input_str[i0];
                  bool cond = c0 != (uint8_t)0U;
                  while (cond)
                  {
                    uint32_t i = ip;
                    ip = i + (uint32_t)1U;
                    uint32_t i0 = ip;
                    uint8_t c = input_str[i0];
                    cond = c != (uint8_t)0U;
                  }
                  uint32_t len = ip;
                  if (len == (uint32_t)0U)
                    out_str = NULL;
                  else
                  {
                    KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
                    uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
                    uint32_t np = (uint32_t)0U;
                    uint32_t n0 = np;
                    uint8_t c0 = input_str[n0];
                    bool cond = c0 != (uint8_t)0U;
                    while (cond)
                    {
                      uint32_t n = np;
                      uint8_t c = input_str[n];
                      out_str0[n] = c;
                      np = n + (uint32_t)1U;
                      uint32_t n0 = np;
                      uint8_t c0 = input_str[n0];
                      cond = c0 != (uint8_t)0U;
                    }
                    uint32_t n = np;
                    out_str0[n] = (uint8_t)0U;
                    uint8_t *out_str1 = out_str0;
                    out_str = out_str1;
                  }
                }
                dst_pinfo[0U] = out_str;
                pid_ptr[0U] = peer.p_id;
                b1 = true;
              }
              else
              {
                pid_ptr[0U] = (uint32_t)0U;
                b1 = false;
              }
              bool r1 = b1;
              if (r1)
              {
                uint8_t *payload_input = msg2;
                Noise_XK_error_code r11 = Noise_XK_mix_dh(st_epriv, st_rs, st_cipher, st_ck, st_h);
                Noise_XK_error_code r;
                if (!(r11 == Noise_XK_CSuccess))
                  r = r11;
                else
                {
                  Noise_XK_error_code
                  r2 =
                    Noise_XK_decrypt_and_hash(payload_outlen,
                      payload_out,
                      payload_input,
                      st_cipher,
                      st_h,
                      (uint64_t)0U);
                  r = r2;
                }
                Noise_XK_error_code r1 = r;
                Noise_XK_error_code r2 = r1;
                if (r2 == Noise_XK_CSuccess)
                  r0 = ((result_unit_error){ .tag = Res0 });
                else
                  r0 = ((result_unit_error){ .tag = Fail0, .v = r2 });
              }
              else
                r0 = ((result_unit_error){ .tag = Fail0, .v = Noise_XK_CRs_rejected_by_policy });
            }
            else
              r0 = ((result_unit_error){ .tag = Fail0, .v = r10 });
          }
          result_resp_state_t res;
          if (r0.tag == Res0)
            res =
              (
                (result_resp_state_t){
                  .tag = Res,
                  .val = {
                    .case_Res = {
                      .tag = Noise_XK_IMS_Handshake,
                      .val = {
                        .case_IMS_Handshake = {
                          .step = st_step + (uint32_t)1U, .cipher_key = st_cipher,
                          .chaining_key = st_ck, .h = st_h, .spriv = st_spriv, .spub = st_spub,
                          .epriv = st_epriv, .epub = st_epub, .rs = st_rs, .re = st_re
                        }
                      }
                    }
                  }
                }
              );
          else if (r0.tag == Fail0)
          {
            Noise_XK_error_code e = r0.v;
            res = ((result_resp_state_t){ .tag = Fail, .val = { .case_Fail = e } });
          }
          else
            res =
              KRML_EABORT(result_resp_state_t,
                "unreachable (pattern matches are exhaustive in F*)");
          res1 = res;
        }
        result_session_t res;
        if (res1.tag == Fail)
        {
          Noise_XK_error_code e = res1.val.case_Fail;
          res = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
        }
        else if (res1.tag == Res)
        {
          Noise_XK_resp_state_t st1 = res1.val.case_Res;
          if (!(st_step == (uint32_t)2U))
            res =
              (
                (result_session_t){
                  .tag = Res,
                  .val = {
                    .case_Res = {
                      .tag = Noise_XK_DS_Responder,
                      .val = {
                        .case_DS_Responder = {
                          .state = st1, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                          .spub = dst_spub, .pid = dst_pid, .pinfo = dst_pinfo, .dv = dst_dv
                        }
                      }
                    }
                  }
                }
              );
          else
          {
            uint32_t pid1 = pid_ptr[0U];
            res =
              (
                (result_session_t){
                  .tag = Res,
                  .val = {
                    .case_Res = {
                      .tag = Noise_XK_DS_Responder,
                      .val = {
                        .case_DS_Responder = {
                          .state = st1, .id = dst_id, .info = dst_info, .spriv = dst_spriv,
                          .spub = dst_spub, .pid = pid1, .pinfo = dst_pinfo, .dv = dst_dv
                        }
                      }
                    }
                  }
                }
              );
          }
        }
        else
          res = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
        if (res.tag == Fail)
        {
          Noise_XK_error_code e = res.val.case_Fail;
          res0 = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
        }
        else if (res.tag == Res)
        {
          Noise_XK_session_t dst1 = res.val.case_Res;
          Noise_XK_session_t dst2;
          if (dst1.tag == Noise_XK_DS_Responder)
          {
            Noise_XK_device_t *dv = dst1.val.case_DS_Responder.dv;
            Noise_XK_noise_string *pinfo = dst1.val.case_DS_Responder.pinfo;
            uint32_t pid1 = dst1.val.case_DS_Responder.pid;
            uint8_t *spub = dst1.val.case_DS_Responder.spub;
            uint8_t *spriv = dst1.val.case_DS_Responder.spriv;
            Noise_XK_noise_string *info = dst1.val.case_DS_Responder.info;
            uint32_t id = dst1.val.case_DS_Responder.id;
            Noise_XK_resp_state_t st = dst1.val.case_DS_Responder.state;
            if (st_step == (uint32_t)2U)
            {
              Noise_XK_resp_state_t st1;
              if (st.tag == Noise_XK_IMS_Handshake)
              {
                uint8_t *st_re1 = st.val.case_IMS_Handshake.re;
                uint8_t *st_rs1 = st.val.case_IMS_Handshake.rs;
                uint8_t *st_epub1 = st.val.case_IMS_Handshake.epub;
                uint8_t *st_epriv1 = st.val.case_IMS_Handshake.epriv;
                uint8_t *st_h1 = st.val.case_IMS_Handshake.h;
                uint8_t *st_ck1 = st.val.case_IMS_Handshake.chaining_key;
                uint8_t *st_k = st.val.case_IMS_Handshake.cipher_key;
                uint8_t *k1 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
                uint8_t *k2 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
                uint8_t temp_k1[64U] = { 0U };
                uint8_t temp_k2[64U] = { 0U };
                Noise_XK_kdf(st_ck1, (uint32_t)0U, NULL, temp_k1, temp_k2, NULL);
                memcpy(k1, temp_k1, (uint32_t)32U * sizeof (uint8_t));
                memcpy(k2, temp_k2, (uint32_t)32U * sizeof (uint8_t));
#ifdef WITH_SODIUM
                sodium_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
                sodium_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#else // WITH_SODIUM
                Lib_Memzero0_memzero(temp_k1, (uint32_t)64U * sizeof (temp_k1[0U]));
                Lib_Memzero0_memzero(temp_k2, (uint32_t)64U * sizeof (temp_k2[0U]));
#endif // WITH_SODIUM
                KRML_HOST_FREE(st_k);
                KRML_HOST_FREE(st_ck1);
                KRML_HOST_FREE(st_epriv1);
                KRML_HOST_FREE(st_epub1);
                KRML_HOST_FREE(st_rs1);
                KRML_HOST_FREE(st_re1);
                st1 =
                  (
                    (Noise_XK_resp_state_t){
                      .tag = Noise_XK_IMS_Transport,
                      .val = {
                        .case_IMS_Transport = {
                          .h = st_h1, .send_key = k2, .send_nonce = (uint64_t)0U, .receive_key = k1,
                          .receive_nonce = (uint64_t)0U
                        }
                      }
                    }
                  );
              }
              else
                st1 =
                  KRML_EABORT(Noise_XK_resp_state_t,
                    "unreachable (pattern matches are exhaustive in F*)");
              dst2 =
                (
                  (Noise_XK_session_t){
                    .tag = Noise_XK_DS_Responder,
                    .val = {
                      .case_DS_Responder = {
                        .state = st1, .id = id, .info = info, .spriv = spriv, .spub = spub,
                        .pid = pid1, .pinfo = pinfo, .dv = dv
                      }
                    }
                  }
                );
            }
            else
              dst2 =
                (
                  (Noise_XK_session_t){
                    .tag = Noise_XK_DS_Responder,
                    .val = {
                      .case_DS_Responder = {
                        .state = st, .id = id, .info = info, .spriv = spriv, .spub = spub,
                        .pid = pid1, .pinfo = pinfo, .dv = dv
                      }
                    }
                  }
                );
          }
          else
            dst2 =
              KRML_EABORT(Noise_XK_session_t,
                "unreachable (pattern matches are exhaustive in F*)");
          res0 = ((result_session_t){ .tag = Res, .val = { .case_Res = dst2 } });
        }
        else
          res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
      }
    }
    else if (dst_st.tag == Noise_XK_IMS_Transport)
      res0 =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
    else
      res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  }
  else
    res0 = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  KRML_HOST_FREE(pid_ptr);
  if (res0.tag == Fail)
  {
    Noise_XK_error_code e = res0.val.case_Fail;
    Noise_XK_session_t dst1 = dst_p[0U];
    if (dst1.tag == Noise_XK_DS_Initiator)
    {
      Noise_XK_device_t *dv = dst1.val.case_DS_Initiator.dv;
      Noise_XK_noise_string *pinfo = dst1.val.case_DS_Initiator.pinfo;
      uint32_t pid1 = dst1.val.case_DS_Initiator.pid;
      uint8_t *spub = dst1.val.case_DS_Initiator.spub;
      uint8_t *spriv = dst1.val.case_DS_Initiator.spriv;
      Noise_XK_noise_string *info = dst1.val.case_DS_Initiator.info;
      uint32_t id = dst1.val.case_DS_Initiator.id;
      Noise_XK_init_state_t st = dst1.val.case_DS_Initiator.state;
      Noise_XK_init_state_t ite;
      if (st.tag == Noise_XK_IMS_Handshake)
      {
        uint8_t *re = st.val.case_IMS_Handshake.re;
        uint8_t *rs = st.val.case_IMS_Handshake.rs;
        uint8_t *epub = st.val.case_IMS_Handshake.epub;
        uint8_t *epriv = st.val.case_IMS_Handshake.epriv;
        uint8_t *spub1 = st.val.case_IMS_Handshake.spub;
        uint8_t *spriv1 = st.val.case_IMS_Handshake.spriv;
        uint8_t *h4 = st.val.case_IMS_Handshake.h;
        uint8_t *ck = st.val.case_IMS_Handshake.chaining_key;
        uint8_t *k = st.val.case_IMS_Handshake.cipher_key;
        ite =
          (
            (Noise_XK_init_state_t){
              .tag = Noise_XK_IMS_Handshake,
              .val = {
                .case_IMS_Handshake = {
                  .step = (uint32_t)4U, .cipher_key = k, .chaining_key = ck, .h = h4,
                  .spriv = spriv1, .spub = spub1, .epriv = epriv, .epub = epub, .rs = rs, .re = re
                }
              }
            }
          );
      }
      else if (st.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = st.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = st.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = st.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = st.val.case_IMS_Transport.send_key;
        bool recv_tpt_msg = st.val.case_IMS_Transport.recv_transport_message;
        uint8_t *h4 = st.val.case_IMS_Transport.h;
        ite =
          (
            (Noise_XK_init_state_t){
              .tag = Noise_XK_IMS_Transport,
              .val = {
                .case_IMS_Transport = {
                  .h = h4, .recv_transport_message = recv_tpt_msg, .send_key = send_key,
                  .send_nonce = send_nonce, .receive_key = receive_key,
                  .receive_nonce = receive_nonce
                }
              }
            }
          );
      }
      else
        ite =
          KRML_EABORT(Noise_XK_init_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      dst_p[0U] =
        (
          (Noise_XK_session_t){
            .tag = Noise_XK_DS_Initiator,
            .val = {
              .case_DS_Initiator = {
                .state = ite, .id = id, .info = info, .spriv = spriv, .spub = spub, .pid = pid1,
                .pinfo = pinfo, .dv = dv
              }
            }
          }
        );
    }
    else if (dst1.tag == Noise_XK_DS_Responder)
    {
      Noise_XK_device_t *dv = dst1.val.case_DS_Responder.dv;
      Noise_XK_noise_string *pinfo = dst1.val.case_DS_Responder.pinfo;
      uint32_t pid1 = dst1.val.case_DS_Responder.pid;
      uint8_t *spub = dst1.val.case_DS_Responder.spub;
      uint8_t *spriv = dst1.val.case_DS_Responder.spriv;
      Noise_XK_noise_string *info = dst1.val.case_DS_Responder.info;
      uint32_t id = dst1.val.case_DS_Responder.id;
      Noise_XK_resp_state_t st = dst1.val.case_DS_Responder.state;
      Noise_XK_resp_state_t ite;
      if (st.tag == Noise_XK_IMS_Handshake)
      {
        uint8_t *re = st.val.case_IMS_Handshake.re;
        uint8_t *rs = st.val.case_IMS_Handshake.rs;
        uint8_t *epub = st.val.case_IMS_Handshake.epub;
        uint8_t *epriv = st.val.case_IMS_Handshake.epriv;
        uint8_t *spub1 = st.val.case_IMS_Handshake.spub;
        uint8_t *spriv1 = st.val.case_IMS_Handshake.spriv;
        uint8_t *h4 = st.val.case_IMS_Handshake.h;
        uint8_t *ck = st.val.case_IMS_Handshake.chaining_key;
        uint8_t *k = st.val.case_IMS_Handshake.cipher_key;
        ite =
          (
            (Noise_XK_resp_state_t){
              .tag = Noise_XK_IMS_Handshake,
              .val = {
                .case_IMS_Handshake = {
                  .step = (uint32_t)4U, .cipher_key = k, .chaining_key = ck, .h = h4,
                  .spriv = spriv1, .spub = spub1, .epriv = epriv, .epub = epub, .rs = rs, .re = re
                }
              }
            }
          );
      }
      else if (st.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = st.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = st.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = st.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = st.val.case_IMS_Transport.send_key;
        uint8_t *h4 = st.val.case_IMS_Transport.h;
        ite =
          (
            (Noise_XK_resp_state_t){
              .tag = Noise_XK_IMS_Transport,
              .val = {
                .case_IMS_Transport = {
                  .h = h4, .send_key = send_key, .send_nonce = send_nonce,
                  .receive_key = receive_key, .receive_nonce = receive_nonce
                }
              }
            }
          );
      }
      else
        ite =
          KRML_EABORT(Noise_XK_resp_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      dst_p[0U] =
        (
          (Noise_XK_session_t){
            .tag = Noise_XK_DS_Responder,
            .val = {
              .case_DS_Responder = {
                .state = ite, .id = id, .info = info, .spriv = spriv, .spub = spub, .pid = pid1,
                .pinfo = pinfo, .dv = dv
              }
            }
          }
        );
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
    return e;
  }
  else if (res0.tag == Res)
  {
    Noise_XK_session_t dst1 = res0.val.case_Res;
    dst_p[0U] = dst1;
    return Noise_XK_CSuccess;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static Noise_XK_error_code
state_transport_write(
  uint32_t plen,
  uint8_t *p,
  uint32_t clen,
  uint8_t *c,
  Noise_XK_session_t *dst_p
)
{
  Noise_XK_session_t dst = dst_p[0U];
  result_session_t r;
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_device_t *dv = dst.val.case_DS_Initiator.dv;
    Noise_XK_noise_string *pinfo = dst.val.case_DS_Initiator.pinfo;
    uint32_t pid = dst.val.case_DS_Initiator.pid;
    uint8_t *spub = dst.val.case_DS_Initiator.spub;
    uint8_t *spriv = dst.val.case_DS_Initiator.spriv;
    Noise_XK_noise_string *info = dst.val.case_DS_Initiator.info;
    uint32_t id = dst.val.case_DS_Initiator.id;
    Noise_XK_init_state_t state = dst.val.case_DS_Initiator.state;
    bool ite;
    if (state.tag == Noise_XK_IMS_Handshake)
      ite = true;
    else
      ite = false;
    if (!ite)
    {
      result_init_state_t scrut;
      if (state.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = state.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = state.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = state.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = state.val.case_IMS_Transport.send_key;
        bool recv_tpt_msg = state.val.case_IMS_Transport.recv_transport_message;
        uint8_t *h = state.val.case_IMS_Transport.h;
        if (!(plen <= (uint32_t)4294967279U && clen == plen + (uint32_t)16U))
          scrut =
            ((result_init_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
        else if (send_nonce >= (uint64_t)18446744073709551615U)
          scrut =
            (
              (result_init_state_t){
                .tag = Fail,
                .val = { .case_Fail = Noise_XK_CSaturated_nonce }
              }
            );
        else
        {
          Noise_XK_aead_encrypt(send_key, send_nonce, (uint32_t)0U, NULL, plen, p, c);
          scrut =
            (
              (result_init_state_t){
                .tag = Res,
                .val = {
                  .case_Res = {
                    .tag = Noise_XK_IMS_Transport,
                    .val = {
                      .case_IMS_Transport = {
                        .h = h, .recv_transport_message = recv_tpt_msg, .send_key = send_key,
                        .send_nonce = send_nonce + (uint64_t)1U, .receive_key = receive_key,
                        .receive_nonce = receive_nonce
                      }
                    }
                  }
                }
              }
            );
        }
      }
      else
        scrut =
          KRML_EABORT(result_init_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      if (scrut.tag == Fail)
      {
        Noise_XK_error_code e = scrut.val.case_Fail;
        r = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
      }
      else if (scrut.tag == Res)
      {
        Noise_XK_init_state_t state_ = scrut.val.case_Res;
        r =
          (
            (result_session_t){
              .tag = Res,
              .val = {
                .case_Res = {
                  .tag = Noise_XK_DS_Initiator,
                  .val = {
                    .case_DS_Initiator = {
                      .state = state_, .id = id, .info = info, .spriv = spriv, .spub = spub,
                      .pid = pid, .pinfo = pinfo, .dv = dv
                    }
                  }
                }
              }
            }
          );
      }
      else
        r = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
    }
    else
      r =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_device_t *dv = dst.val.case_DS_Responder.dv;
    Noise_XK_noise_string *pinfo = dst.val.case_DS_Responder.pinfo;
    uint32_t pid = dst.val.case_DS_Responder.pid;
    uint8_t *spub = dst.val.case_DS_Responder.spub;
    uint8_t *spriv = dst.val.case_DS_Responder.spriv;
    Noise_XK_noise_string *info = dst.val.case_DS_Responder.info;
    uint32_t id = dst.val.case_DS_Responder.id;
    Noise_XK_resp_state_t state = dst.val.case_DS_Responder.state;
    bool ite;
    if (state.tag == Noise_XK_IMS_Handshake)
      ite = true;
    else
      ite = false;
    if (!ite)
    {
      result_resp_state_t scrut;
      if (state.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = state.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = state.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = state.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = state.val.case_IMS_Transport.send_key;
        uint8_t *h = state.val.case_IMS_Transport.h;
        if (!(plen <= (uint32_t)4294967279U && clen == plen + (uint32_t)16U))
          scrut =
            ((result_resp_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
        else if (send_nonce >= (uint64_t)18446744073709551615U)
          scrut =
            (
              (result_resp_state_t){
                .tag = Fail,
                .val = { .case_Fail = Noise_XK_CSaturated_nonce }
              }
            );
        else
        {
          Noise_XK_aead_encrypt(send_key, send_nonce, (uint32_t)0U, NULL, plen, p, c);
          scrut =
            (
              (result_resp_state_t){
                .tag = Res,
                .val = {
                  .case_Res = {
                    .tag = Noise_XK_IMS_Transport,
                    .val = {
                      .case_IMS_Transport = {
                        .h = h, .send_key = send_key, .send_nonce = send_nonce + (uint64_t)1U,
                        .receive_key = receive_key, .receive_nonce = receive_nonce
                      }
                    }
                  }
                }
              }
            );
        }
      }
      else
        scrut =
          KRML_EABORT(result_resp_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      if (scrut.tag == Fail)
      {
        Noise_XK_error_code e = scrut.val.case_Fail;
        r = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
      }
      else if (scrut.tag == Res)
      {
        Noise_XK_resp_state_t state_ = scrut.val.case_Res;
        r =
          (
            (result_session_t){
              .tag = Res,
              .val = {
                .case_Res = {
                  .tag = Noise_XK_DS_Responder,
                  .val = {
                    .case_DS_Responder = {
                      .state = state_, .id = id, .info = info, .spriv = spriv, .spub = spub,
                      .pid = pid, .pinfo = pinfo, .dv = dv
                    }
                  }
                }
              }
            }
          );
      }
      else
        r = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
    }
    else
      r =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
  }
  else
    r = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  if (r.tag == Fail)
    return r.val.case_Fail;
  else if (r.tag == Res)
  {
    Noise_XK_session_t dst_ = r.val.case_Res;
    dst_p[0U] = dst_;
    return Noise_XK_CSuccess;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

static Noise_XK_error_code
state_transport_read(
  uint32_t plen,
  uint8_t *p,
  uint32_t clen,
  uint8_t *c,
  Noise_XK_session_t *dst_p
)
{
  Noise_XK_session_t dst = dst_p[0U];
  result_session_t r;
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_device_t *dv = dst.val.case_DS_Initiator.dv;
    Noise_XK_noise_string *pinfo = dst.val.case_DS_Initiator.pinfo;
    uint32_t pid = dst.val.case_DS_Initiator.pid;
    uint8_t *spub = dst.val.case_DS_Initiator.spub;
    uint8_t *spriv = dst.val.case_DS_Initiator.spriv;
    Noise_XK_noise_string *info = dst.val.case_DS_Initiator.info;
    uint32_t id = dst.val.case_DS_Initiator.id;
    Noise_XK_init_state_t state = dst.val.case_DS_Initiator.state;
    bool ite;
    if (state.tag == Noise_XK_IMS_Handshake)
      ite = true;
    else
      ite = false;
    if (!ite)
    {
      result_init_state_t scrut;
      if (state.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = state.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = state.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = state.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = state.val.case_IMS_Transport.send_key;
        uint8_t *h = state.val.case_IMS_Transport.h;
        if (!(plen <= (uint32_t)4294967279U && clen == plen + (uint32_t)16U))
          scrut =
            ((result_init_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
        else if (receive_nonce >= (uint64_t)18446744073709551615U)
          scrut =
            (
              (result_init_state_t){
                .tag = Fail,
                .val = { .case_Fail = Noise_XK_CSaturated_nonce }
              }
            );
        else
          switch (Noise_XK_aead_decrypt(receive_key, receive_nonce, (uint32_t)0U, NULL, plen, p, c))
          {
            case Noise_XK_CDecrypt_error:
              {
                scrut =
                  (
                    (result_init_state_t){
                      .tag = Fail,
                      .val = { .case_Fail = Noise_XK_CDecrypt_error }
                    }
                  );
                break;
              }
            case Noise_XK_CSuccess:
              {
                scrut =
                  (
                    (result_init_state_t){
                      .tag = Res,
                      .val = {
                        .case_Res = {
                          .tag = Noise_XK_IMS_Transport,
                          .val = {
                            .case_IMS_Transport = {
                              .h = h, .recv_transport_message = true, .send_key = send_key,
                              .send_nonce = send_nonce, .receive_key = receive_key,
                              .receive_nonce = receive_nonce + (uint64_t)1U
                            }
                          }
                        }
                      }
                    }
                  );
                break;
              }
            default:
              {
                KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
                KRML_HOST_EXIT(253U);
              }
          }
      }
      else
        scrut =
          KRML_EABORT(result_init_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      if (scrut.tag == Fail)
      {
        Noise_XK_error_code e = scrut.val.case_Fail;
        r = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
      }
      else if (scrut.tag == Res)
      {
        Noise_XK_init_state_t state_ = scrut.val.case_Res;
        r =
          (
            (result_session_t){
              .tag = Res,
              .val = {
                .case_Res = {
                  .tag = Noise_XK_DS_Initiator,
                  .val = {
                    .case_DS_Initiator = {
                      .state = state_, .id = id, .info = info, .spriv = spriv, .spub = spub,
                      .pid = pid, .pinfo = pinfo, .dv = dv
                    }
                  }
                }
              }
            }
          );
      }
      else
        r = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
    }
    else
      r =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_device_t *dv = dst.val.case_DS_Responder.dv;
    Noise_XK_noise_string *pinfo = dst.val.case_DS_Responder.pinfo;
    uint32_t pid = dst.val.case_DS_Responder.pid;
    uint8_t *spub = dst.val.case_DS_Responder.spub;
    uint8_t *spriv = dst.val.case_DS_Responder.spriv;
    Noise_XK_noise_string *info = dst.val.case_DS_Responder.info;
    uint32_t id = dst.val.case_DS_Responder.id;
    Noise_XK_resp_state_t state = dst.val.case_DS_Responder.state;
    bool ite;
    if (state.tag == Noise_XK_IMS_Handshake)
      ite = true;
    else
      ite = false;
    if (!ite)
    {
      result_resp_state_t scrut;
      if (state.tag == Noise_XK_IMS_Transport)
      {
        uint64_t receive_nonce = state.val.case_IMS_Transport.receive_nonce;
        uint8_t *receive_key = state.val.case_IMS_Transport.receive_key;
        uint64_t send_nonce = state.val.case_IMS_Transport.send_nonce;
        uint8_t *send_key = state.val.case_IMS_Transport.send_key;
        uint8_t *h = state.val.case_IMS_Transport.h;
        if (!(plen <= (uint32_t)4294967279U && clen == plen + (uint32_t)16U))
          scrut =
            ((result_resp_state_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CInput_size } });
        else if (receive_nonce >= (uint64_t)18446744073709551615U)
          scrut =
            (
              (result_resp_state_t){
                .tag = Fail,
                .val = { .case_Fail = Noise_XK_CSaturated_nonce }
              }
            );
        else
          switch (Noise_XK_aead_decrypt(receive_key, receive_nonce, (uint32_t)0U, NULL, plen, p, c))
          {
            case Noise_XK_CDecrypt_error:
              {
                scrut =
                  (
                    (result_resp_state_t){
                      .tag = Fail,
                      .val = { .case_Fail = Noise_XK_CDecrypt_error }
                    }
                  );
                break;
              }
            case Noise_XK_CSuccess:
              {
                scrut =
                  (
                    (result_resp_state_t){
                      .tag = Res,
                      .val = {
                        .case_Res = {
                          .tag = Noise_XK_IMS_Transport,
                          .val = {
                            .case_IMS_Transport = {
                              .h = h, .send_key = send_key, .send_nonce = send_nonce,
                              .receive_key = receive_key,
                              .receive_nonce = receive_nonce + (uint64_t)1U
                            }
                          }
                        }
                      }
                    }
                  );
                break;
              }
            default:
              {
                KRML_HOST_EPRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
                KRML_HOST_EXIT(253U);
              }
          }
      }
      else
        scrut =
          KRML_EABORT(result_resp_state_t,
            "unreachable (pattern matches are exhaustive in F*)");
      if (scrut.tag == Fail)
      {
        Noise_XK_error_code e = scrut.val.case_Fail;
        r = ((result_session_t){ .tag = Fail, .val = { .case_Fail = e } });
      }
      else if (scrut.tag == Res)
      {
        Noise_XK_resp_state_t state_ = scrut.val.case_Res;
        r =
          (
            (result_session_t){
              .tag = Res,
              .val = {
                .case_Res = {
                  .tag = Noise_XK_DS_Responder,
                  .val = {
                    .case_DS_Responder = {
                      .state = state_, .id = id, .info = info, .spriv = spriv, .spub = spub,
                      .pid = pid, .pinfo = pinfo, .dv = dv
                    }
                  }
                }
              }
            }
          );
      }
      else
        r = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
    }
    else
      r =
        ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
  }
  else
    r = KRML_EABORT(result_session_t, "unreachable (pattern matches are exhaustive in F*)");
  if (r.tag == Fail)
    return r.val.case_Fail;
  else if (r.tag == Res)
  {
    Noise_XK_session_t dst_ = r.val.case_Res;
    dst_p[0U] = dst_;
    return Noise_XK_CSuccess;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

#define None 0
#define Some 1

typedef uint8_t option__uint32_t_tags;

typedef struct option__uint32_t_s
{
  option__uint32_t_tags tag;
  uint32_t v;
}
option__uint32_t;

/*
  Write a message with the current session.

  If successful, this function will allocate a buffer of the proper length
  in `*out` and will write the length of this buffer in `*out_len`. Note that
  using `out` and `out_len` is always safe: if the function fails, it will set
  `*outlen` to 0 and `*out` to NULL.
*/
Noise_XK_rcode
Noise_XK_session_write(
  Noise_XK_encap_message_t *payload,
  Noise_XK_session_t *sn_p,
  uint32_t *out_len,
  uint8_t **out
)
{
  Noise_XK_session_t *sn_p1 = sn_p;
  Noise_XK_session_t *snp = sn_p1;
  Noise_XK_session_t sn = snp[0U];
  if (sn.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_init_state_t sn_state = sn.val.case_DS_Initiator.state;
    if (sn_state.tag == Noise_XK_IMS_Transport)
    {
      bool recv_tpt_msg = sn_state.val.case_IMS_Transport.recv_transport_message;
      Noise_XK_encap_message_t encap_payload = payload[0U];
      bool next_length_ok;
      if (encap_payload.em_message_len <= (uint32_t)4294967279U)
      {
        out_len[0U] = encap_payload.em_message_len + (uint32_t)16U;
        next_length_ok = true;
      }
      else
        next_length_ok = false;
      if (next_length_ok)
      {
        bool sec_ok;
        if (encap_payload.em_message_len == (uint32_t)0U)
          sec_ok = true;
        else
        {
          uint8_t clevel;
          if (recv_tpt_msg)
            clevel = (uint8_t)5U;
          else
            clevel = (uint8_t)5U;
          if (encap_payload.em_ac_level.tag == Noise_XK_Conf_level)
          {
            uint8_t req_level = encap_payload.em_ac_level.val.case_Conf_level;
            sec_ok =
              (req_level >= (uint8_t)2U && clevel >= req_level)
              || (req_level == (uint8_t)1U && (clevel == req_level || clevel >= (uint8_t)3U))
              || req_level == (uint8_t)0U;
          }
          else
            sec_ok = false;
        }
        if (sec_ok)
        {
          uint32_t outlen = out_len[0U];
          KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
          uint8_t *out1 = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
          Noise_XK_error_code
          res =
            state_transport_write(encap_payload.em_message_len,
              encap_payload.em_message,
              outlen,
              out1,
              sn_p1);
          if (res == Noise_XK_CSuccess)
          {
            out[0U] = out1;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
          }
          else
          {
            Noise_XK_error_code e = res;
            KRML_HOST_FREE(out1);
            out_len[0U] = (uint32_t)0U;
            out[0U] = NULL;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = e } });
          }
        }
        else
        {
          out_len[0U] = (uint32_t)0U;
          out[0U] = NULL;
          return
            (
              (Noise_XK_rcode){
                .tag = Noise_XK_Error,
                .val = { .case_Error = Noise_XK_CSecurity_level }
              }
            );
        }
      }
      else
      {
        out_len[0U] = (uint32_t)0U;
        out[0U] = NULL;
        return
          ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = Noise_XK_CInput_size } });
      }
    }
    else if (sn_state.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t st_step = sn_state.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)4U)
      {
        out_len[0U] = (uint32_t)0U;
        out[0U] = NULL;
        return
          (
            (Noise_XK_rcode){
              .tag = Noise_XK_Stuck,
              .val = { .case_Stuck = Noise_XK_CIncorrect_transition }
            }
          );
      }
      else
      {
        Noise_XK_encap_message_t encap_payload = payload[0U];
        option__uint32_t scrut;
        if ((uint32_t)0U == st_step)
          if (encap_payload.em_message_len <= (uint32_t)4294967215U)
            scrut =
              ((option__uint32_t){ .tag = Some, .v = encap_payload.em_message_len + (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)1U == st_step)
          if (encap_payload.em_message_len <= (uint32_t)4294967215U)
            scrut =
              ((option__uint32_t){ .tag = Some, .v = encap_payload.em_message_len + (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)2U == st_step)
          if (encap_payload.em_message_len <= (uint32_t)4294967215U)
            scrut =
              ((option__uint32_t){ .tag = Some, .v = encap_payload.em_message_len + (uint32_t)64U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else
          scrut = ((option__uint32_t){ .tag = None });
        bool next_length_ok;
        if (scrut.tag == Some)
        {
          uint32_t l = scrut.v;
          out_len[0U] = l;
          next_length_ok = true;
        }
        else
          next_length_ok = false;
        if (next_length_ok)
        {
          bool sec_ok;
          if (encap_payload.em_message_len == (uint32_t)0U)
            sec_ok = true;
          else
          {
            uint8_t clevel;
            if (st_step == (uint32_t)0U)
              clevel = (uint8_t)2U;
            else if (st_step == (uint32_t)1U)
              clevel = (uint8_t)1U;
            else
              clevel = (uint8_t)5U;
            if (encap_payload.em_ac_level.tag == Noise_XK_Conf_level)
            {
              uint8_t req_level = encap_payload.em_ac_level.val.case_Conf_level;
              sec_ok =
                (req_level >= (uint8_t)2U && clevel >= req_level)
                || (req_level == (uint8_t)1U && (clevel == req_level || clevel >= (uint8_t)3U))
                || req_level == (uint8_t)0U;
            }
            else
              sec_ok = false;
          }
          if (sec_ok)
          {
            uint32_t outlen = out_len[0U];
            KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
            uint8_t *out1 = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
            Noise_XK_error_code
            res =
              state_handshake_write(encap_payload.em_message_len,
                encap_payload.em_message,
                sn_p1,
                outlen,
                out1);
            if (res == Noise_XK_CSuccess)
            {
              out[0U] = out1;
              return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
            }
            else
            {
              Noise_XK_error_code e = res;
              KRML_HOST_FREE(out1);
              out_len[0U] = (uint32_t)0U;
              out[0U] = NULL;
              return ((Noise_XK_rcode){ .tag = Noise_XK_Stuck, .val = { .case_Stuck = e } });
            }
          }
          else
          {
            out_len[0U] = (uint32_t)0U;
            out[0U] = NULL;
            return
              (
                (Noise_XK_rcode){
                  .tag = Noise_XK_Error,
                  .val = { .case_Error = Noise_XK_CSecurity_level }
                }
              );
          }
        }
        else
        {
          out_len[0U] = (uint32_t)0U;
          out[0U] = NULL;
          return
            (
              (Noise_XK_rcode){
                .tag = Noise_XK_Error,
                .val = { .case_Error = Noise_XK_CInput_size }
              }
            );
        }
      }
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else if (sn.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_resp_state_t sn_state = sn.val.case_DS_Responder.state;
    if (sn_state.tag == Noise_XK_IMS_Transport)
    {
      Noise_XK_encap_message_t encap_payload = payload[0U];
      bool next_length_ok;
      if (encap_payload.em_message_len <= (uint32_t)4294967279U)
      {
        out_len[0U] = encap_payload.em_message_len + (uint32_t)16U;
        next_length_ok = true;
      }
      else
        next_length_ok = false;
      if (next_length_ok)
      {
        bool sec_ok;
        if (encap_payload.em_message_len == (uint32_t)0U)
          sec_ok = true;
        else
        {
          uint8_t clevel = (uint8_t)5U;
          if (encap_payload.em_ac_level.tag == Noise_XK_Conf_level)
          {
            uint8_t req_level = encap_payload.em_ac_level.val.case_Conf_level;
            sec_ok =
              (req_level >= (uint8_t)2U && clevel >= req_level)
              || (req_level == (uint8_t)1U && (clevel == req_level || clevel >= (uint8_t)3U))
              || req_level == (uint8_t)0U;
          }
          else
            sec_ok = false;
        }
        if (sec_ok)
        {
          uint32_t outlen = out_len[0U];
          KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
          uint8_t *out1 = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
          Noise_XK_error_code
          res =
            state_transport_write(encap_payload.em_message_len,
              encap_payload.em_message,
              outlen,
              out1,
              sn_p1);
          if (res == Noise_XK_CSuccess)
          {
            out[0U] = out1;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
          }
          else
          {
            Noise_XK_error_code e = res;
            KRML_HOST_FREE(out1);
            out_len[0U] = (uint32_t)0U;
            out[0U] = NULL;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = e } });
          }
        }
        else
        {
          out_len[0U] = (uint32_t)0U;
          out[0U] = NULL;
          return
            (
              (Noise_XK_rcode){
                .tag = Noise_XK_Error,
                .val = { .case_Error = Noise_XK_CSecurity_level }
              }
            );
        }
      }
      else
      {
        out_len[0U] = (uint32_t)0U;
        out[0U] = NULL;
        return
          ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = Noise_XK_CInput_size } });
      }
    }
    else if (sn_state.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t st_step = sn_state.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)4U)
      {
        out_len[0U] = (uint32_t)0U;
        out[0U] = NULL;
        return
          (
            (Noise_XK_rcode){
              .tag = Noise_XK_Stuck,
              .val = { .case_Stuck = Noise_XK_CIncorrect_transition }
            }
          );
      }
      else
      {
        Noise_XK_encap_message_t encap_payload = payload[0U];
        option__uint32_t scrut;
        if ((uint32_t)0U == st_step)
          if (encap_payload.em_message_len <= (uint32_t)4294967215U)
            scrut =
              ((option__uint32_t){ .tag = Some, .v = encap_payload.em_message_len + (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)1U == st_step)
          if (encap_payload.em_message_len <= (uint32_t)4294967215U)
            scrut =
              ((option__uint32_t){ .tag = Some, .v = encap_payload.em_message_len + (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)2U == st_step)
          if (encap_payload.em_message_len <= (uint32_t)4294967215U)
            scrut =
              ((option__uint32_t){ .tag = Some, .v = encap_payload.em_message_len + (uint32_t)64U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else
          scrut = ((option__uint32_t){ .tag = None });
        bool next_length_ok;
        if (scrut.tag == Some)
        {
          uint32_t l = scrut.v;
          out_len[0U] = l;
          next_length_ok = true;
        }
        else
          next_length_ok = false;
        if (next_length_ok)
        {
          bool sec_ok;
          if (encap_payload.em_message_len == (uint32_t)0U)
            sec_ok = true;
          else
          {
            uint8_t clevel;
            if (st_step == (uint32_t)0U)
              clevel = (uint8_t)2U;
            else if (st_step == (uint32_t)1U)
              clevel = (uint8_t)1U;
            else
              clevel = (uint8_t)5U;
            if (encap_payload.em_ac_level.tag == Noise_XK_Conf_level)
            {
              uint8_t req_level = encap_payload.em_ac_level.val.case_Conf_level;
              sec_ok =
                (req_level >= (uint8_t)2U && clevel >= req_level)
                || (req_level == (uint8_t)1U && (clevel == req_level || clevel >= (uint8_t)3U))
                || req_level == (uint8_t)0U;
            }
            else
              sec_ok = false;
          }
          if (sec_ok)
          {
            uint32_t outlen = out_len[0U];
            KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
            uint8_t *out1 = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
            Noise_XK_error_code
            res =
              state_handshake_write(encap_payload.em_message_len,
                encap_payload.em_message,
                sn_p1,
                outlen,
                out1);
            if (res == Noise_XK_CSuccess)
            {
              out[0U] = out1;
              return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
            }
            else
            {
              Noise_XK_error_code e = res;
              KRML_HOST_FREE(out1);
              out_len[0U] = (uint32_t)0U;
              out[0U] = NULL;
              return ((Noise_XK_rcode){ .tag = Noise_XK_Stuck, .val = { .case_Stuck = e } });
            }
          }
          else
          {
            out_len[0U] = (uint32_t)0U;
            out[0U] = NULL;
            return
              (
                (Noise_XK_rcode){
                  .tag = Noise_XK_Error,
                  .val = { .case_Error = Noise_XK_CSecurity_level }
                }
              );
          }
        }
        else
        {
          out_len[0U] = (uint32_t)0U;
          out[0U] = NULL;
          return
            (
              (Noise_XK_rcode){
                .tag = Noise_XK_Error,
                .val = { .case_Error = Noise_XK_CInput_size }
              }
            );
        }
      }
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Read a message with the current session.

  If successful, this function will allocate a an encapsulated message
  in `*payload_out`. Note that using `payload_out` is always safe: if the
  function fails, it will set `*payload_out` to NULL.
*/
Noise_XK_rcode
Noise_XK_session_read(
  Noise_XK_encap_message_t **payload_out,
  Noise_XK_session_t *sn_p,
  uint32_t inlen,
  uint8_t *input
)
{
  Noise_XK_session_t *sn_p1 = sn_p;
  Noise_XK_session_t *snp = sn_p1;
  Noise_XK_session_t sn = snp[0U];
  if (sn.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_init_state_t sn_state = sn.val.case_DS_Initiator.state;
    if (sn_state.tag == Noise_XK_IMS_Transport)
    {
      option__uint32_t scrut;
      if (inlen >= (uint32_t)16U)
        scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)16U });
      else
        scrut = ((option__uint32_t){ .tag = None });
      if (scrut.tag == Some)
      {
        uint32_t outlen = scrut.v;
        uint8_t *out;
        if (outlen > (uint32_t)0U)
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
          uint8_t *buf = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
          out = buf;
        }
        else
          out = NULL;
        Noise_XK_error_code res = state_transport_read(outlen, out, inlen, input, sn_p1);
        if (res == Noise_XK_CSuccess)
        {
          KRML_CHECK_SIZE(sizeof (Noise_XK_encap_message_t), (uint32_t)1U);
          Noise_XK_encap_message_t *em_ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_encap_message_t));
          em_ptr[0U]
          =
            (
              (Noise_XK_encap_message_t){
                .em_ac_level = {
                  .tag = Noise_XK_Auth_level,
                  .val = { .case_Auth_level = (uint8_t)2U }
                },
                .em_message_len = outlen,
                .em_message = out
              }
            );
          Noise_XK_encap_message_t *emp = em_ptr;
          payload_out[0U] = emp;
          return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
        }
        else
        {
          Noise_XK_error_code e = res;
          if (!(out == NULL))
            KRML_HOST_FREE(out);
          payload_out[0U] = NULL;
          return ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = e } });
        }
      }
      else
      {
        payload_out[0U] = NULL;
        return
          ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = Noise_XK_CInput_size } });
      }
    }
    else if (sn_state.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t st_step = sn_state.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)4U)
      {
        payload_out[0U] = NULL;
        return
          (
            (Noise_XK_rcode){
              .tag = Noise_XK_Stuck,
              .val = { .case_Stuck = Noise_XK_CIncorrect_transition }
            }
          );
      }
      else if (st_step % (uint32_t)2U == (uint32_t)1U && st_step < (uint32_t)3U)
      {
        option__uint32_t scrut;
        if ((uint32_t)0U == st_step)
          if (inlen >= (uint32_t)48U)
            scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)1U == st_step)
          if (inlen >= (uint32_t)48U)
            scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)2U == st_step)
          if (inlen >= (uint32_t)64U)
            scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)64U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else
          scrut = ((option__uint32_t){ .tag = None });
        if (scrut.tag == Some)
        {
          uint32_t outlen = scrut.v;
          uint8_t alevel;
          if (st_step == (uint32_t)0U)
            alevel = (uint8_t)0U;
          else if (st_step == (uint32_t)1U)
            alevel = (uint8_t)2U;
          else
            alevel = (uint8_t)2U;
          uint8_t *out;
          if (outlen > (uint32_t)0U)
          {
            KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
            uint8_t *buf = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
            out = buf;
          }
          else
            out = NULL;
          Noise_XK_error_code res = state_handshake_read(outlen, out, sn_p1, inlen, input);
          if (res == Noise_XK_CSuccess)
          {
            KRML_CHECK_SIZE(sizeof (Noise_XK_encap_message_t), (uint32_t)1U);
            Noise_XK_encap_message_t *em_ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_encap_message_t));
            em_ptr[0U]
            =
              (
                (Noise_XK_encap_message_t){
                  .em_ac_level = {
                    .tag = Noise_XK_Auth_level,
                    .val = { .case_Auth_level = alevel }
                  },
                  .em_message_len = outlen,
                  .em_message = out
                }
              );
            Noise_XK_encap_message_t *emp = em_ptr;
            payload_out[0U] = emp;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
          }
          else
          {
            Noise_XK_error_code e = res;
            if (!(out == NULL))
              KRML_HOST_FREE(out);
            payload_out[0U] = NULL;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Stuck, .val = { .case_Stuck = e } });
          }
        }
        else
        {
          payload_out[0U] = NULL;
          return
            (
              (Noise_XK_rcode){
                .tag = Noise_XK_Error,
                .val = { .case_Error = Noise_XK_CInput_size }
              }
            );
        }
      }
      else
      {
        payload_out[0U] = NULL;
        return
          (
            (Noise_XK_rcode){
              .tag = Noise_XK_Error,
              .val = { .case_Error = Noise_XK_CIncorrect_transition }
            }
          );
      }
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else if (sn.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_resp_state_t sn_state = sn.val.case_DS_Responder.state;
    if (sn_state.tag == Noise_XK_IMS_Transport)
    {
      option__uint32_t scrut;
      if (inlen >= (uint32_t)16U)
        scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)16U });
      else
        scrut = ((option__uint32_t){ .tag = None });
      if (scrut.tag == Some)
      {
        uint32_t outlen = scrut.v;
        uint8_t *out;
        if (outlen > (uint32_t)0U)
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
          uint8_t *buf = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
          out = buf;
        }
        else
          out = NULL;
        Noise_XK_error_code res = state_transport_read(outlen, out, inlen, input, sn_p1);
        if (res == Noise_XK_CSuccess)
        {
          KRML_CHECK_SIZE(sizeof (Noise_XK_encap_message_t), (uint32_t)1U);
          Noise_XK_encap_message_t *em_ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_encap_message_t));
          em_ptr[0U]
          =
            (
              (Noise_XK_encap_message_t){
                .em_ac_level = {
                  .tag = Noise_XK_Auth_level,
                  .val = { .case_Auth_level = (uint8_t)2U }
                },
                .em_message_len = outlen,
                .em_message = out
              }
            );
          Noise_XK_encap_message_t *emp = em_ptr;
          payload_out[0U] = emp;
          return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
        }
        else
        {
          Noise_XK_error_code e = res;
          if (!(out == NULL))
            KRML_HOST_FREE(out);
          payload_out[0U] = NULL;
          return ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = e } });
        }
      }
      else
      {
        payload_out[0U] = NULL;
        return
          ((Noise_XK_rcode){ .tag = Noise_XK_Error, .val = { .case_Error = Noise_XK_CInput_size } });
      }
    }
    else if (sn_state.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t st_step = sn_state.val.case_IMS_Handshake.step;
      if (st_step >= (uint32_t)4U)
      {
        payload_out[0U] = NULL;
        return
          (
            (Noise_XK_rcode){
              .tag = Noise_XK_Stuck,
              .val = { .case_Stuck = Noise_XK_CIncorrect_transition }
            }
          );
      }
      else if (st_step % (uint32_t)2U == (uint32_t)0U && st_step < (uint32_t)3U)
      {
        option__uint32_t scrut;
        if ((uint32_t)0U == st_step)
          if (inlen >= (uint32_t)48U)
            scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)1U == st_step)
          if (inlen >= (uint32_t)48U)
            scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)48U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else if ((uint32_t)2U == st_step)
          if (inlen >= (uint32_t)64U)
            scrut = ((option__uint32_t){ .tag = Some, .v = inlen - (uint32_t)64U });
          else
            scrut = ((option__uint32_t){ .tag = None });
        else
          scrut = ((option__uint32_t){ .tag = None });
        if (scrut.tag == Some)
        {
          uint32_t outlen = scrut.v;
          uint8_t alevel;
          if (st_step == (uint32_t)0U)
            alevel = (uint8_t)0U;
          else if (st_step == (uint32_t)1U)
            alevel = (uint8_t)2U;
          else
            alevel = (uint8_t)2U;
          uint8_t *out;
          if (outlen > (uint32_t)0U)
          {
            KRML_CHECK_SIZE(sizeof (uint8_t), outlen);
            uint8_t *buf = KRML_HOST_CALLOC(outlen, sizeof (uint8_t));
            out = buf;
          }
          else
            out = NULL;
          Noise_XK_error_code res = state_handshake_read(outlen, out, sn_p1, inlen, input);
          if (res == Noise_XK_CSuccess)
          {
            KRML_CHECK_SIZE(sizeof (Noise_XK_encap_message_t), (uint32_t)1U);
            Noise_XK_encap_message_t *em_ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_encap_message_t));
            em_ptr[0U]
            =
              (
                (Noise_XK_encap_message_t){
                  .em_ac_level = {
                    .tag = Noise_XK_Auth_level,
                    .val = { .case_Auth_level = alevel }
                  },
                  .em_message_len = outlen,
                  .em_message = out
                }
              );
            Noise_XK_encap_message_t *emp = em_ptr;
            payload_out[0U] = emp;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Success });
          }
          else
          {
            Noise_XK_error_code e = res;
            if (!(out == NULL))
              KRML_HOST_FREE(out);
            payload_out[0U] = NULL;
            return ((Noise_XK_rcode){ .tag = Noise_XK_Stuck, .val = { .case_Stuck = e } });
          }
        }
        else
        {
          payload_out[0U] = NULL;
          return
            (
              (Noise_XK_rcode){
                .tag = Noise_XK_Error,
                .val = { .case_Error = Noise_XK_CInput_size }
              }
            );
        }
      }
      else
      {
        payload_out[0U] = NULL;
        return
          (
            (Noise_XK_rcode){
              .tag = Noise_XK_Error,
              .val = { .case_Error = Noise_XK_CIncorrect_transition }
            }
          );
      }
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Compute the length of the next message, given a payload length.

  Note that the function may fail, if the length of the message is too long
  for example (though very unlikely). You thus need to check the returned value.

  Also note that the length of the next message is always equal to:
  payload length + a value depending only on the current step.
*/
bool
Noise_XK_session_compute_next_message_len(
  uint32_t *out,
  Noise_XK_session_t *sn,
  uint32_t payload_len
)
{
  Noise_XK_session_t dst = sn[0U];
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_init_state_t st = dst.val.case_DS_Initiator.state;
    if (st.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t step = st.val.case_IMS_Handshake.step;
      option__uint32_t scrut;
      if ((uint32_t)0U == step)
        if (payload_len <= (uint32_t)4294967215U)
          scrut = ((option__uint32_t){ .tag = Some, .v = payload_len + (uint32_t)48U });
        else
          scrut = ((option__uint32_t){ .tag = None });
      else if ((uint32_t)1U == step)
        if (payload_len <= (uint32_t)4294967215U)
          scrut = ((option__uint32_t){ .tag = Some, .v = payload_len + (uint32_t)48U });
        else
          scrut = ((option__uint32_t){ .tag = None });
      else if ((uint32_t)2U == step)
        if (payload_len <= (uint32_t)4294967215U)
          scrut = ((option__uint32_t){ .tag = Some, .v = payload_len + (uint32_t)64U });
        else
          scrut = ((option__uint32_t){ .tag = None });
      else
        scrut = ((option__uint32_t){ .tag = None });
      if (scrut.tag == Some)
      {
        uint32_t l = scrut.v;
        out[0U] = l;
        return true;
      }
      else
        return false;
    }
    else if (st.tag == Noise_XK_IMS_Transport)
      if (payload_len <= (uint32_t)4294967279U)
      {
        out[0U] = payload_len + (uint32_t)16U;
        return true;
      }
      else
        return false;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_resp_state_t st = dst.val.case_DS_Responder.state;
    if (st.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t step = st.val.case_IMS_Handshake.step;
      option__uint32_t scrut;
      if ((uint32_t)0U == step)
        if (payload_len <= (uint32_t)4294967215U)
          scrut = ((option__uint32_t){ .tag = Some, .v = payload_len + (uint32_t)48U });
        else
          scrut = ((option__uint32_t){ .tag = None });
      else if ((uint32_t)1U == step)
        if (payload_len <= (uint32_t)4294967215U)
          scrut = ((option__uint32_t){ .tag = Some, .v = payload_len + (uint32_t)48U });
        else
          scrut = ((option__uint32_t){ .tag = None });
      else if ((uint32_t)2U == step)
        if (payload_len <= (uint32_t)4294967215U)
          scrut = ((option__uint32_t){ .tag = Some, .v = payload_len + (uint32_t)64U });
        else
          scrut = ((option__uint32_t){ .tag = None });
      else
        scrut = ((option__uint32_t){ .tag = None });
      if (scrut.tag == Some)
      {
        uint32_t l = scrut.v;
        out[0U] = l;
        return true;
      }
      else
        return false;
    }
    else if (st.tag == Noise_XK_IMS_Transport)
      if (payload_len <= (uint32_t)4294967279U)
      {
        out[0U] = payload_len + (uint32_t)16U;
        return true;
      }
      else
        return false;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Return the current status.
*/
Noise_XK_status Noise_XK_session_get_status(Noise_XK_session_t *sn)
{
  Noise_XK_session_t dst = sn[0U];
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_init_state_t st = dst.val.case_DS_Initiator.state;
    if (st.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t step = st.val.case_IMS_Handshake.step;
      if (step % (uint32_t)2U == (uint32_t)0U)
        return Noise_XK_Handshake_write;
      else
        return Noise_XK_Handshake_read;
    }
    else if (st.tag == Noise_XK_IMS_Transport)
      return Noise_XK_Transport;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_resp_state_t st = dst.val.case_DS_Responder.state;
    if (st.tag == Noise_XK_IMS_Handshake)
    {
      uint32_t step = st.val.case_IMS_Handshake.step;
      if (step % (uint32_t)2U == (uint32_t)0U)
        return Noise_XK_Handshake_read;
      else
        return Noise_XK_Handshake_write;
    }
    else if (st.tag == Noise_XK_IMS_Transport)
      return Noise_XK_Transport;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Copy the session hash to the user provided buffer.

  Note that the session hash is always public.

  Using the session hash might be pertinent once the session has reached the
  transport phase.
*/
void Noise_XK_session_get_hash(uint8_t *out, Noise_XK_session_t *sn)
{
  Noise_XK_session_t dst = sn[0U];
  uint8_t *h;
  if (dst.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_init_state_t st = dst.val.case_DS_Initiator.state;
    if (st.tag == Noise_XK_IMS_Handshake)
      h = st.val.case_IMS_Handshake.h;
    else if (st.tag == Noise_XK_IMS_Transport)
      h = st.val.case_IMS_Transport.h;
    else
      h = KRML_EABORT(uint8_t *, "unreachable (pattern matches are exhaustive in F*)");
  }
  else if (dst.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_resp_state_t st = dst.val.case_DS_Responder.state;
    if (st.tag == Noise_XK_IMS_Handshake)
      h = st.val.case_IMS_Handshake.h;
    else if (st.tag == Noise_XK_IMS_Transport)
      h = st.val.case_IMS_Transport.h;
    else
      h = KRML_EABORT(uint8_t *, "unreachable (pattern matches are exhaustive in F*)");
  }
  else
    h = KRML_EABORT(uint8_t *, "unreachable (pattern matches are exhaustive in F*)");
  memcpy(out, h, (uint32_t)64U * sizeof (uint8_t));
}

/*
  Return the session unique identifier.
*/
uint32_t Noise_XK_session_get_id(Noise_XK_session_t *sn)
{
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator)
    return st.val.case_DS_Initiator.id;
  else if (st.tag == Noise_XK_DS_Responder)
    return st.val.case_DS_Responder.id;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Copy the session information to the user provided pointer.
*/
void Noise_XK_session_get_info(Noise_XK_noise_string *out, Noise_XK_session_t *sn)
{
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_noise_string *info = st.val.case_DS_Initiator.info;
    uint8_t *input_str = info[0U];
    bool b = input_str == NULL;
    uint8_t *out_str;
    if (b)
      out_str = NULL;
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c0 = input_str[i0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = input_str[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t len = ip;
      if (len == (uint32_t)0U)
        out_str = NULL;
      else
      {
        KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
        uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
        uint32_t np = (uint32_t)0U;
        uint32_t n0 = np;
        uint8_t c0 = input_str[n0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t n = np;
          uint8_t c = input_str[n];
          out_str0[n] = c;
          np = n + (uint32_t)1U;
          uint32_t n0 = np;
          uint8_t c0 = input_str[n0];
          cond = c0 != (uint8_t)0U;
        }
        uint32_t n = np;
        out_str0[n] = (uint8_t)0U;
        uint8_t *out_str1 = out_str0;
        out_str = out_str1;
      }
    }
    out[0U] = out_str;
  }
  else if (st.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_noise_string *info = st.val.case_DS_Responder.info;
    uint8_t *input_str = info[0U];
    bool b = input_str == NULL;
    uint8_t *out_str;
    if (b)
      out_str = NULL;
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c0 = input_str[i0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = input_str[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t len = ip;
      if (len == (uint32_t)0U)
        out_str = NULL;
      else
      {
        KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
        uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
        uint32_t np = (uint32_t)0U;
        uint32_t n0 = np;
        uint8_t c0 = input_str[n0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t n = np;
          uint8_t c = input_str[n];
          out_str0[n] = c;
          np = n + (uint32_t)1U;
          uint32_t n0 = np;
          uint8_t c0 = input_str[n0];
          cond = c0 != (uint8_t)0U;
        }
        uint32_t n = np;
        out_str0[n] = (uint8_t)0U;
        uint8_t *out_str1 = out_str0;
        out_str = out_str1;
      }
    }
    out[0U] = out_str;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Return the session's peer unique identifier.

  The remote may be unknown, in which case the returned id will be 0.
  Note that you can safely use the returned peer id without testing
  it, because all the functions taking peer ids as parameters were
  written to correctly manipulate 0. In particular, looking up id 0 will return
  NULL, and trying to create a session with peer id 0 will cleanly fail
  by also returning NULL.
*/
uint32_t Noise_XK_session_get_peer_id(Noise_XK_session_t *sn)
{
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator)
    return st.val.case_DS_Initiator.pid;
  else if (st.tag == Noise_XK_DS_Responder)
    return st.val.case_DS_Responder.pid;
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Copy the session peer information, if known, to the user provided pointer.

  The remote may be unknown yet, in which case there is no peer information
  in the device and the function will return false.
*/
bool Noise_XK_session_get_peer_info(Noise_XK_noise_string *out, Noise_XK_session_t *sn)
{
  Noise_XK_session_t st = sn[0U];
  if (st.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_noise_string *pinfo = st.val.case_DS_Initiator.pinfo;
    uint32_t pid = st.val.case_DS_Initiator.pid;
    if (pid != (uint32_t)0U)
    {
      uint8_t *input_str = pinfo[0U];
      bool b = input_str == NULL;
      uint8_t *out_str;
      if (b)
        out_str = NULL;
      else
      {
        uint32_t ip = (uint32_t)0U;
        uint32_t i0 = ip;
        uint8_t c0 = input_str[i0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t i = ip;
          ip = i + (uint32_t)1U;
          uint32_t i0 = ip;
          uint8_t c = input_str[i0];
          cond = c != (uint8_t)0U;
        }
        uint32_t len = ip;
        if (len == (uint32_t)0U)
          out_str = NULL;
        else
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
          uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
          uint32_t np = (uint32_t)0U;
          uint32_t n0 = np;
          uint8_t c0 = input_str[n0];
          bool cond = c0 != (uint8_t)0U;
          while (cond)
          {
            uint32_t n = np;
            uint8_t c = input_str[n];
            out_str0[n] = c;
            np = n + (uint32_t)1U;
            uint32_t n0 = np;
            uint8_t c0 = input_str[n0];
            cond = c0 != (uint8_t)0U;
          }
          uint32_t n = np;
          out_str0[n] = (uint8_t)0U;
          uint8_t *out_str1 = out_str0;
          out_str = out_str1;
        }
      }
      out[0U] = out_str;
      return true;
    }
    else
      return false;
  }
  else if (st.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_noise_string *pinfo = st.val.case_DS_Responder.pinfo;
    uint32_t pid = st.val.case_DS_Responder.pid;
    if (pid != (uint32_t)0U)
    {
      uint8_t *input_str = pinfo[0U];
      bool b = input_str == NULL;
      uint8_t *out_str;
      if (b)
        out_str = NULL;
      else
      {
        uint32_t ip = (uint32_t)0U;
        uint32_t i0 = ip;
        uint8_t c0 = input_str[i0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t i = ip;
          ip = i + (uint32_t)1U;
          uint32_t i0 = ip;
          uint8_t c = input_str[i0];
          cond = c != (uint8_t)0U;
        }
        uint32_t len = ip;
        if (len == (uint32_t)0U)
          out_str = NULL;
        else
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
          uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
          uint32_t np = (uint32_t)0U;
          uint32_t n0 = np;
          uint8_t c0 = input_str[n0];
          bool cond = c0 != (uint8_t)0U;
          while (cond)
          {
            uint32_t n = np;
            uint8_t c = input_str[n];
            out_str0[n] = c;
            np = n + (uint32_t)1U;
            uint32_t n0 = np;
            uint8_t c0 = input_str[n0];
            cond = c0 != (uint8_t)0U;
          }
          uint32_t n = np;
          out_str0[n] = (uint8_t)0U;
          uint8_t *out_str1 = out_str0;
          out_str = out_str1;
        }
      }
      out[0U] = out_str;
      return true;
    }
    else
      return false;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  Return true if this session has reached the maximum security level for this
  pattern.

  Once the maximum security level is reached, it is not possible to have better
  confidentiality/authentication guarantees for the payloads sent/received
  with this session. Note that the guarantees provided by the maximum reachable
  level vary with the pattern, which must thus be carefully chosen.

  In order to reach the maximum level, the session must have finished the
  handshake. Moreover, in case the session sends the last handshake message,
  it must wait for the first transport message from the remote: otherwise,
  we have no way to know whether the remote was itself able to finish the
  handshake.
*/
bool Noise_XK_session_reached_max_security(Noise_XK_session_t *snp)
{
  Noise_XK_session_t sn = snp[0U];
  if (sn.tag == Noise_XK_DS_Initiator)
  {
    Noise_XK_init_state_t sn_state = sn.val.case_DS_Initiator.state;
    if (sn_state.tag == Noise_XK_IMS_Transport)
      return sn_state.val.case_IMS_Transport.recv_transport_message;
    else if (sn_state.tag == Noise_XK_IMS_Handshake)
      return false;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else if (sn.tag == Noise_XK_DS_Responder)
  {
    Noise_XK_resp_state_t sn_state = sn.val.case_DS_Responder.state;
    if (sn_state.tag == Noise_XK_IMS_Transport)
      return true;
    else if (sn_state.tag == Noise_XK_IMS_Handshake)
      return false;
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  DO NOT use this: for tests and benchmarks only
*/
Noise_XK_session_t
*Noise_XK__session_create_initiator_with_ephemeral(
  Noise_XK_device_t *dvp,
  uint8_t *epriv,
  uint8_t *epub,
  uint32_t pid
)
{
  Noise_XK_device_t dv = dvp[0U];
  result_session_t res0;
  if (dv.dv_states_counter == (uint32_t)4294967295U)
    res0 =
      ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
  else
  {
    Noise_XK_device_t dv1 = dvp[0U];
    Noise_XK_peer_t *peer_ptr;
    if (pid == (uint32_t)0U)
      peer_ptr = NULL;
    else
    {
      Noise_XK_cell *llt = *dv1.dv_peers;
      Noise_XK_cell *lltp = llt;
      Noise_XK_cell *llt10 = lltp;
      bool b0;
      if (llt10 == NULL)
        b0 = false;
      else
      {
        Noise_XK_cell c = llt10[0U];
        Noise_XK_peer_t x = c.data[0U];
        bool b = x.p_id == pid;
        b0 = !b;
      }
      bool cond = b0;
      while (cond)
      {
        Noise_XK_cell *llt1 = lltp;
        Noise_XK_cell c0 = llt1[0U];
        lltp = c0.next;
        Noise_XK_cell *llt10 = lltp;
        bool b;
        if (llt10 == NULL)
          b = false;
        else
        {
          Noise_XK_cell c = llt10[0U];
          Noise_XK_peer_t x = c.data[0U];
          bool b0 = x.p_id == pid;
          b = !b0;
        }
        cond = b;
      }
      Noise_XK_cell *llt1 = *&lltp;
      Noise_XK_peer_t *res;
      if (llt1 == NULL)
        res = NULL;
      else
      {
        Noise_XK_cell c = *llt1;
        res = c.data;
      }
      peer_ptr = res;
    }
    bool p_is_null = peer_ptr == NULL;
    if (p_is_null)
      res0 = ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CUnknown_peer_id } });
    else
    {
      uint8_t *o0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      memcpy(o0, dv.dv_spriv, (uint32_t)32U * sizeof (uint8_t));
      uint8_t *st_spriv = o0;
      uint8_t *o = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      memcpy(o, dv.dv_spub, (uint32_t)32U * sizeof (uint8_t));
      uint8_t *st_spub = o;
      uint8_t *str0 = dv.dv_info[0U];
      bool b0 = str0 == NULL;
      uint8_t *out_str0;
      if (b0)
        out_str0 = NULL;
      else
      {
        uint32_t ip = (uint32_t)0U;
        uint32_t i0 = ip;
        uint8_t c0 = str0[i0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t i = ip;
          ip = i + (uint32_t)1U;
          uint32_t i0 = ip;
          uint8_t c = str0[i0];
          cond = c != (uint8_t)0U;
        }
        uint32_t len = ip;
        if (len == (uint32_t)0U)
          out_str0 = NULL;
        else
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
          uint8_t *out_str = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
          uint32_t np = (uint32_t)0U;
          uint32_t n0 = np;
          uint8_t c0 = str0[n0];
          bool cond = c0 != (uint8_t)0U;
          while (cond)
          {
            uint32_t n = np;
            uint8_t c = str0[n];
            out_str[n] = c;
            np = n + (uint32_t)1U;
            uint32_t n0 = np;
            uint8_t c0 = str0[n0];
            cond = c0 != (uint8_t)0U;
          }
          uint32_t n = np;
          out_str[n] = (uint8_t)0U;
          uint8_t *out_str1 = out_str;
          out_str0 = out_str1;
        }
      }
      KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
      uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
      out_ptr[0U] = out_str0;
      Noise_XK_noise_string *st_info = out_ptr;
      Noise_XK_peer_t peer = peer_ptr[0U];
      uint8_t *str = peer.p_info[0U];
      bool b = str == NULL;
      uint8_t *out_str;
      if (b)
        out_str = NULL;
      else
      {
        uint32_t ip = (uint32_t)0U;
        uint32_t i0 = ip;
        uint8_t c0 = str[i0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t i = ip;
          ip = i + (uint32_t)1U;
          uint32_t i0 = ip;
          uint8_t c = str[i0];
          cond = c != (uint8_t)0U;
        }
        uint32_t len = ip;
        if (len == (uint32_t)0U)
          out_str = NULL;
        else
        {
          KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
          uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
          uint32_t np = (uint32_t)0U;
          uint32_t n0 = np;
          uint8_t c0 = str[n0];
          bool cond = c0 != (uint8_t)0U;
          while (cond)
          {
            uint32_t n = np;
            uint8_t c = str[n];
            out_str0[n] = c;
            np = n + (uint32_t)1U;
            uint32_t n0 = np;
            uint8_t c0 = str[n0];
            cond = c0 != (uint8_t)0U;
          }
          uint32_t n = np;
          out_str0[n] = (uint8_t)0U;
          uint8_t *out_str1 = out_str0;
          out_str = out_str1;
        }
      }
      KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
      uint8_t **out_ptr0 = KRML_HOST_MALLOC(sizeof (uint8_t *));
      out_ptr0[0U] = out_str;
      Noise_XK_noise_string *st_pinfo = out_ptr0;
      uint8_t *rs = peer.p_s;
      dvp[0U] =
        (
          (Noise_XK_device_t){
            .dv_info = dv.dv_info,
            .dv_sk = dv.dv_sk,
            .dv_spriv = dv.dv_spriv,
            .dv_spub = dv.dv_spub,
            .dv_prologue = dv.dv_prologue,
            .dv_states_counter = dv.dv_states_counter + (uint32_t)1U,
            .dv_peers = dv.dv_peers,
            .dv_peers_counter = dv.dv_peers_counter
          }
        );
      uint8_t *st_k = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      uint8_t *st_ck0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
      uint8_t *st_h0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
      uint8_t *st_spriv1 = st_spriv;
      uint8_t *st_spub1 = st_spub;
      uint8_t *st_epriv0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      uint8_t *st_epub0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      uint8_t *st_rs0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      uint8_t *st_re = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
      Noise_XK_init_state_t
      st =
        {
          .tag = Noise_XK_IMS_Handshake,
          .val = {
            .case_IMS_Handshake = {
              .step = (uint32_t)0U, .cipher_key = st_k, .chaining_key = st_ck0, .h = st_h0,
              .spriv = st_spriv1, .spub = st_spub1, .epriv = st_epriv0, .epub = st_epub0,
              .rs = st_rs0, .re = st_re
            }
          }
        };
      uint8_t
      pname[33U] =
        {
          (uint8_t)78U, (uint8_t)111U, (uint8_t)105U, (uint8_t)115U, (uint8_t)101U, (uint8_t)95U,
          (uint8_t)88U, (uint8_t)75U, (uint8_t)95U, (uint8_t)50U, (uint8_t)53U, (uint8_t)53U,
          (uint8_t)49U, (uint8_t)57U, (uint8_t)95U, (uint8_t)67U, (uint8_t)104U, (uint8_t)97U,
          (uint8_t)67U, (uint8_t)104U, (uint8_t)97U, (uint8_t)80U, (uint8_t)111U, (uint8_t)108U,
          (uint8_t)121U, (uint8_t)95U, (uint8_t)66U, (uint8_t)76U, (uint8_t)65U, (uint8_t)75U,
          (uint8_t)69U, (uint8_t)50U, (uint8_t)98U
        };
      if (st.tag == Noise_XK_IMS_Handshake)
      {
        uint8_t *st_rs = st.val.case_IMS_Handshake.rs;
        uint8_t *st_epub = st.val.case_IMS_Handshake.epub;
        uint8_t *st_epriv = st.val.case_IMS_Handshake.epriv;
        uint8_t *st_h = st.val.case_IMS_Handshake.h;
        uint8_t *st_ck = st.val.case_IMS_Handshake.chaining_key;
        if ((uint32_t)33U <= (uint32_t)64U)
          memcpy(st_h, pname, (uint32_t)33U * sizeof (uint8_t));
        else
          Noise_XK_hash(st_h, (uint32_t)33U, pname);
        memcpy(st_ck, st_h, (uint32_t)64U * sizeof (uint8_t));
        Noise_XK_mix_hash(st_h, dv.dv_prologue.size, dv.dv_prologue.buffer);
        memcpy(st_epriv, epriv, (uint32_t)32U * sizeof (uint8_t));
        memcpy(st_epub, epub, (uint32_t)32U * sizeof (uint8_t));
        memcpy(st_rs, rs, (uint32_t)32U * sizeof (uint8_t));
        Noise_XK_mix_hash(st_h, (uint32_t)32U, rs);
      }
      else
      {
        KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
          __FILE__,
          __LINE__,
          "unreachable (pattern matches are exhaustive in F*)");
        KRML_HOST_EXIT(255U);
      }
      Noise_XK_init_state_t st0 = st;
      result_session_t
      res =
        {
          .tag = Res,
          .val = {
            .case_Res = {
              .tag = Noise_XK_DS_Initiator,
              .val = {
                .case_DS_Initiator = {
                  .state = st0, .id = dv.dv_states_counter, .info = st_info, .spriv = st_spriv,
                  .spub = st_spub, .pid = pid, .pinfo = st_pinfo, .dv = dvp
                }
              }
            }
          }
        };
      res0 = res;
    }
  }
  if (res0.tag == Fail)
    return NULL;
  else if (res0.tag == Res)
  {
    Noise_XK_session_t st = res0.val.case_Res;
    KRML_CHECK_SIZE(sizeof (Noise_XK_session_t), (uint32_t)1U);
    Noise_XK_session_t *ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_session_t));
    ptr[0U] = st;
    return ptr;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

/*
  DO NOT use this: for tests and benchmarks only
*/
Noise_XK_session_t
*Noise_XK__session_create_responder_with_ephemeral(
  Noise_XK_device_t *dvp,
  uint8_t *epriv,
  uint8_t *epub
)
{
  Noise_XK_device_t dv = dvp[0U];
  result_session_t res;
  if (dv.dv_states_counter == (uint32_t)4294967295U)
    res =
      ((result_session_t){ .tag = Fail, .val = { .case_Fail = Noise_XK_CIncorrect_transition } });
  else
  {
    uint8_t *o0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    memcpy(o0, dv.dv_spriv, (uint32_t)32U * sizeof (uint8_t));
    uint8_t *st_spriv = o0;
    uint8_t *o = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    memcpy(o, dv.dv_spub, (uint32_t)32U * sizeof (uint8_t));
    uint8_t *st_spub = o;
    uint8_t *str = dv.dv_info[0U];
    bool b = str == NULL;
    uint8_t *out_str;
    if (b)
      out_str = NULL;
    else
    {
      uint32_t ip = (uint32_t)0U;
      uint32_t i0 = ip;
      uint8_t c0 = str[i0];
      bool cond = c0 != (uint8_t)0U;
      while (cond)
      {
        uint32_t i = ip;
        ip = i + (uint32_t)1U;
        uint32_t i0 = ip;
        uint8_t c = str[i0];
        cond = c != (uint8_t)0U;
      }
      uint32_t len = ip;
      if (len == (uint32_t)0U)
        out_str = NULL;
      else
      {
        KRML_CHECK_SIZE(sizeof (uint8_t), len + (uint32_t)1U);
        uint8_t *out_str0 = KRML_HOST_CALLOC(len + (uint32_t)1U, sizeof (uint8_t));
        uint32_t np = (uint32_t)0U;
        uint32_t n0 = np;
        uint8_t c0 = str[n0];
        bool cond = c0 != (uint8_t)0U;
        while (cond)
        {
          uint32_t n = np;
          uint8_t c = str[n];
          out_str0[n] = c;
          np = n + (uint32_t)1U;
          uint32_t n0 = np;
          uint8_t c0 = str[n0];
          cond = c0 != (uint8_t)0U;
        }
        uint32_t n = np;
        out_str0[n] = (uint8_t)0U;
        uint8_t *out_str1 = out_str0;
        out_str = out_str1;
      }
    }
    KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
    uint8_t **out_ptr0 = KRML_HOST_MALLOC(sizeof (uint8_t *));
    out_ptr0[0U] = out_str;
    Noise_XK_noise_string *st_info = out_ptr0;
    KRML_CHECK_SIZE(sizeof (uint8_t *), (uint32_t)1U);
    uint8_t **out_ptr = KRML_HOST_MALLOC(sizeof (uint8_t *));
    out_ptr[0U] = NULL;
    Noise_XK_noise_string *st_pinfo = out_ptr;
    dvp[0U] =
      (
        (Noise_XK_device_t){
          .dv_info = dv.dv_info,
          .dv_sk = dv.dv_sk,
          .dv_spriv = dv.dv_spriv,
          .dv_spub = dv.dv_spub,
          .dv_prologue = dv.dv_prologue,
          .dv_states_counter = dv.dv_states_counter + (uint32_t)1U,
          .dv_peers = dv.dv_peers,
          .dv_peers_counter = dv.dv_peers_counter
        }
      );
    uint8_t *st_k = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    uint8_t *st_ck0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
    uint8_t *st_h0 = KRML_HOST_CALLOC((uint32_t)64U, sizeof (uint8_t));
    uint8_t *st_spriv1 = st_spriv;
    uint8_t *st_spub10 = st_spub;
    uint8_t *st_epriv0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    uint8_t *st_epub0 = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    uint8_t *st_rs = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    uint8_t *st_re = KRML_HOST_CALLOC((uint32_t)32U, sizeof (uint8_t));
    Noise_XK_resp_state_t
    st =
      {
        .tag = Noise_XK_IMS_Handshake,
        .val = {
          .case_IMS_Handshake = {
            .step = (uint32_t)0U, .cipher_key = st_k, .chaining_key = st_ck0, .h = st_h0,
            .spriv = st_spriv1, .spub = st_spub10, .epriv = st_epriv0, .epub = st_epub0, .rs = st_rs,
            .re = st_re
          }
        }
      };
    uint8_t
    pname[33U] =
      {
        (uint8_t)78U, (uint8_t)111U, (uint8_t)105U, (uint8_t)115U, (uint8_t)101U, (uint8_t)95U,
        (uint8_t)88U, (uint8_t)75U, (uint8_t)95U, (uint8_t)50U, (uint8_t)53U, (uint8_t)53U,
        (uint8_t)49U, (uint8_t)57U, (uint8_t)95U, (uint8_t)67U, (uint8_t)104U, (uint8_t)97U,
        (uint8_t)67U, (uint8_t)104U, (uint8_t)97U, (uint8_t)80U, (uint8_t)111U, (uint8_t)108U,
        (uint8_t)121U, (uint8_t)95U, (uint8_t)66U, (uint8_t)76U, (uint8_t)65U, (uint8_t)75U,
        (uint8_t)69U, (uint8_t)50U, (uint8_t)98U
      };
    if (st.tag == Noise_XK_IMS_Handshake)
    {
      uint8_t *st_epub = st.val.case_IMS_Handshake.epub;
      uint8_t *st_epriv = st.val.case_IMS_Handshake.epriv;
      uint8_t *st_spub1 = st.val.case_IMS_Handshake.spub;
      uint8_t *st_h = st.val.case_IMS_Handshake.h;
      uint8_t *st_ck = st.val.case_IMS_Handshake.chaining_key;
      if ((uint32_t)33U <= (uint32_t)64U)
        memcpy(st_h, pname, (uint32_t)33U * sizeof (uint8_t));
      else
        Noise_XK_hash(st_h, (uint32_t)33U, pname);
      memcpy(st_ck, st_h, (uint32_t)64U * sizeof (uint8_t));
      Noise_XK_mix_hash(st_h, dv.dv_prologue.size, dv.dv_prologue.buffer);
      memcpy(st_epriv, epriv, (uint32_t)32U * sizeof (uint8_t));
      memcpy(st_epub, epub, (uint32_t)32U * sizeof (uint8_t));
      Noise_XK_mix_hash(st_h, (uint32_t)32U, st_spub1);
    }
    else
    {
      KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
        __FILE__,
        __LINE__,
        "unreachable (pattern matches are exhaustive in F*)");
      KRML_HOST_EXIT(255U);
    }
    Noise_XK_resp_state_t st0 = st;
    result_session_t
    res0 =
      {
        .tag = Res,
        .val = {
          .case_Res = {
            .tag = Noise_XK_DS_Responder,
            .val = {
              .case_DS_Responder = {
                .state = st0, .id = dv.dv_states_counter, .info = st_info, .spriv = st_spriv,
                .spub = st_spub, .pid = (uint32_t)0U, .pinfo = st_pinfo, .dv = dvp
              }
            }
          }
        }
      };
    res = res0;
  }
  if (res.tag == Fail)
    return NULL;
  else if (res.tag == Res)
  {
    Noise_XK_session_t st = res.val.case_Res;
    KRML_CHECK_SIZE(sizeof (Noise_XK_session_t), (uint32_t)1U);
    Noise_XK_session_t *ptr = KRML_HOST_MALLOC(sizeof (Noise_XK_session_t));
    ptr[0U] = st;
    return ptr;
  }
  else
  {
    KRML_HOST_EPRINTF("KaRaMeL abort at %s:%d\n%s\n",
      __FILE__,
      __LINE__,
      "unreachable (pattern matches are exhaustive in F*)");
    KRML_HOST_EXIT(255U);
  }
}

