#pragma once

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <assert.h>

#define CRYPTO_IV_LEN 12u
#define CRYPTO_TAG_LEN 16u

#define CRYPTO_VERBOSE 1

namespace erpc {
// Shared key for each eRPC session. This should _eventually_ be negotiated
// using a secure handshake

static const size_t CRYPTO_HDR_LEN { CRYPTO_IV_LEN + CRYPTO_TAG_LEN };

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65,
    0x66, 0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8,
    0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f};

int aes_gcm_encrypt(unsigned char *data_buf, int data_len);

int aes_gcm_decrypt(unsigned char *data_buf, int buf_len);

}  // namespace erpc
