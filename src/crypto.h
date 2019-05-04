#pragma once

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#include <assert.h>

#define CRYPTO_IV_LEN 12u
#define CRYPTO_TAG_LEN 16u
#define CRYPTO_GCM_KEY_LEN 32u
#define CRYPTO_GCM_HEX_KEY_LEN 66u

namespace erpc {
// Shared key for each eRPC session. This should _eventually_ be negotiated
// using a secure handshake

static const size_t CRYPTO_HDR_LEN { CRYPTO_IV_LEN + CRYPTO_TAG_LEN };

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65,
    0x66, 0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8,
    0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f};

int aes_gcm_encrypt(unsigned char *data_buf, int data_len, unsigned char *key);

int aes_gcm_decrypt(unsigned char *data_buf, int buf_len, unsigned char *key);

// class KePkt {
//   public:
//     conn_req_uniq_token_t uniq_token;  ///< The token for this session
//     SessionEndpoint client, server;    ///< Endpoint metadata
//     const char pub_key[CRYPTO_GCM_KEY_LEN];
//     std::string to_string() const {
//       std::ostringstream ret;
//       ret << sm_pkt_type_str(pkt_type) << ", " << sm_err_type_str(err_type)
//           << ", client: " << client.name() << ", server: " << server.name();
//       return ret.str();
//     }
//     KePkt() {}
//     KePkt(conn_req_uniq_token_t uniq_token, SessionEndpoint client,
//           SessionEndpoint server)
//         : uniq_token(uniq_token),
//           client(client),
//           server(server) {}
// }

}  // namespace erpc
