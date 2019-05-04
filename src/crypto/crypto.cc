#include "crypto.h"
#include "common.h"
#ifdef CRYPTO_VERBOSE
#include <iostream>
#endif

/* Changing this will break a number of assumptions re: padding and
 * block size made elsewhere in the code, highly recommend not changing
 */
#define _CRYPTO_CIPHER EVP_aes_256_gcm()

/**
 * @brief
 *
 * @param data_buf The buffer storing the user's data
 * @param data_len length of data including the SECURE header
 * @param key The gcm key
 * @param iv_ptr Pointer to the AES-GCM IV (Initialisation Vector)
 * @param tag_buf 
 *
 * @return Error Code (0)
 */
namespace erpc {
int aes_gcm_encrypt_internal(unsigned char *data_buf, int data_len,
                             unsigned char *key,
                             const unsigned char *iv_ptr,
                             unsigned char *tag_ptr) {
  int ct_len = 0;
  int tmplen = 0;

  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();

#ifdef CRYPTO_VERBOSE
  std::cout << "Plaintext: " << std::endl;
  BIO_dump_fp(stdout, reinterpret_cast<const char *>(data_buf), data_len);
#endif

  // TODO: replace gcm_key with negotiated key
  EVP_EncryptInit_ex(ctx, _CRYPTO_CIPHER, NULL, key, iv_ptr);

  EVP_EncryptUpdate(ctx, data_buf, &tmplen,
                    reinterpret_cast<const unsigned char *>(data_buf),
                    data_len);
  ct_len += tmplen;

  EVP_EncryptFinal_ex(ctx, data_buf + ct_len, &tmplen);
  ct_len += tmplen;

#ifdef CRYPTO_VERBOSE
  std::cout << "Ciphertext: " << std::endl;
  BIO_dump_fp(stdout, reinterpret_cast<const char *>(data_buf), data_len);
#endif

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CRYPTO_TAG_LEN, tag_ptr);

#ifdef CRYPTO_VERBOSE
  std::cout << "Tag: " << std::endl;
  BIO_dump_fp(
      stdout,
      reinterpret_cast<const char *>(data_buf) + data_len + CRYPTO_IV_LEN,
      CRYPTO_TAG_LEN);
#endif

  EVP_CIPHER_CTX_free(ctx);

  // We don't return ciphertext_len, as in GCM it's ideally the same as
  // plaintext_len. Somethign is broken if that's not the case.
  assert(data_len == ct_len);

  return 0;
}

/**
 * @brief Function for performing encryption for messages
 *
 * @param void* data_buf
 * @param int data_len
 * @param key The gcm key
 * 
 * @return Error Code (0)
 */
int aes_gcm_encrypt(unsigned char *data_buf, int data_len, unsigned char *key) {
  // We assume 28-byte headroom at the end of databuf[data_len]
  unsigned char *iv_ptr = data_buf + data_len;
  unsigned char *tag_ptr = data_buf + data_len + CRYPTO_IV_LEN;

  int ret = aes_gcm_encrypt_internal(data_buf, data_len, key, iv_ptr, tag_ptr);

  return ret;
}

/**
 * @brief
 *
 * @param data_buf The buffer storing the user's data
 * @param data_len length of data including the SECURE header
 * @param key The gcm key
 * @param iv_ptr Pointer to the initialisation vector
 * @param tag_ptr
 * @return 0 if successful, < 0 otherwise
 */

int aes_gcm_decrypt_internal(unsigned char *data_buf, int data_len,
                             unsigned char *key,
                             const unsigned char *iv_ptr,
                             unsigned char *tag_ptr) {
  EVP_CIPHER_CTX *ctx;
  int pt_len = 0, tmplen = 0, rv;

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, _CRYPTO_CIPHER, NULL, key, iv_ptr);

  EVP_DecryptUpdate(ctx, data_buf, &tmplen, data_buf, data_len);
  pt_len += tmplen;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CRYPTO_TAG_LEN, tag_ptr);

  rv = EVP_DecryptFinal_ex(ctx, data_buf + pt_len, &tmplen);
  pt_len += tmplen;

  if (rv > 0) rv = 0; // normalize EVP error code to our scheme

  EVP_CIPHER_CTX_free(ctx);

  assert(data_len == pt_len);

  return rv;
}

/**
 * @brief
 *
 * @param data_buf The pointer to the buffer with the user usable buffer first 
 *  then the secure header
 * @param data_len length of data INCLUDING the SECURE header
 * @param key The gcm key
 * 
 * @return int Error Codes
 */
int aes_gcm_decrypt(unsigned char *data_buf, int data_len, unsigned char *key) {
  unsigned char *iv_ptr = data_buf + data_len;
  unsigned char *tag_ptr = data_buf + data_len + CRYPTO_IV_LEN;

  int ret = aes_gcm_decrypt_internal(data_buf, data_len, key, iv_ptr, tag_ptr);

  return ret;
}


template <class TTr>
void Rpc<TTr>::sm_pkt_udp_tx_st(const SmPkt &sm_pkt) {
  LOG_INFO("Rpc %u: Sending packet %s.\n", rpc_id, sm_pkt.to_string().c_str());
  const std::string rem_hostname =
      sm_pkt.is_req() ? sm_pkt.server.hostname : sm_pkt.client.hostname;
  const uint16_t rem_sm_udp_port =
      sm_pkt.is_req() ? sm_pkt.server.sm_udp_port : sm_pkt.client.sm_udp_port;

  udp_client.send(rem_hostname, rem_sm_udp_port, sm_pkt);
}

template <class TTr>
void Rpc<TTr>::send_sm_req_st(Session *session) {
  // https://wiki.openssl.org/index.php/Diffie_Hellman

{
  DH *dh;
  int codes, secret_size;

  dh = DH_new(); // FIXME
  // if (NULL == (dh = DH_new())) return EPROTO;
  DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL); // FIXME
  // if (1 != DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL)) return EPROTO;

  DH_check(dh, &codes); // FIXME
  // if (1 != DH_check(dh, &codes)) return ENOMEM;
  // if(codes != 0) {
  //     // FIXME
  //     abort();
  // }

  /* Generate the public and private key pair */
  DH_generate_key(dh); // FIXME
  // if (1 != DH_generate_key(dh)) return ENOMEM;

  /* Send the public key to the peer.
   * How this occurs will be specific to your situation (see main text below) */
  ke_pkt.pub_key = BN_bn2hex(dh->pub_key);
}


  char* key_buffer = ...?
  /* Receive the public key from the peer. In this example we're just hard coding a value */
  BIGNUM *peerkey = NULL;
  BN_hex2bn(&peerkey, key_buffer); // FIXME
  // if (0 == (BN_dec2bn(&peerkey, key_buffer))) return ENOMEM;

  /* Compute the shared secret */
  unsigned char *secret;
  secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey)); // FIXME
  // if(NULL == (secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey))))) return ENOMEM;
  secret_size = DH_compute_key(secret, pubkey, privkey);
  // FIXME
  // if(0 > (secret_size = DH_compute_key(secret, pubkey, privkey))) return ENOMEM;

  /* Clean up, no longer needed since we just want the shared secret */
  BN_free(peerkey);
  DH_free(dh);

  // unsigned char *key = secret;
  unsigned char *key = static_cast<unsigned char *> gcm_key;
  session->set_key(key);
}

}  // namespace erpc
