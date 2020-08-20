#ifndef __SSL_CRYPTO_H__
#define __SSL_CRYPTO_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include "ssloff.h"
#include "ssl_api.h"

#define GCM_TAG_SIZE 16
#define MAX_HASH_SIZE 256

typedef enum tls_crypto_function
{
    TLS_RSA =       1,
    TLS_AES_CBC =   2,
    TLS_AES_GCM =   3,
    TLS_HMAC_SHA1 = 4
} tls_crypto_function_t;
typedef enum
{
    HASH =              1,
    ENCRYPT =           2,
    DECRYPT =           3,
    PUBLIC_ENCRYPT =    4,
    PUBLIC_DECRYPT =    5,
    PRIVATE_ENCRYPT =   6,
    PRIVATE_DECRYPT =   7
} tls_crypto_op_t;

#define TLS_OPCODE_AES_CBC_128_ENCRYPT 0x00800202u
#define TLS_OPCODE_AES_CBC_128_DECRYPT 0x00800302u
#define TLS_OPCODE_AES_CBC_256_ENCRYPT 0x01000202u
#define TLS_OPCODE_AES_CBC_256_DECRYPT 0x01000302u
#define TLS_OPCODE_AES_GCM_128_ENCRYPT 0x00800203u
#define TLS_OPCODE_AES_GCM_128_DECRYPT 0x00800303u
#define TLS_OPCODE_AES_GCM_256_ENCRYPT 0x01000203u
#define TLS_OPCODE_AES_GCM_256_DECRYPT 0x01000303u
#define TLS_OPCODE_HMAC_SHA1_HASH      0x00000104u
#define TLS_OPCODE_HMAC_SHA256_HASH    0x00000204u
#define TLS_OPCODE_HMAC_SHA384_HASH    0x00000304u
#define TLS_OPCODE_RSA_1024_PUBLIC_DECRYPT  0x04000501u
#define TLS_OPCODE_RSA_1024_PRIVATE_DECRYPT 0x04000701u
#define TLS_OPCODE_RSA_2048_PUBLIC_DECRYPT  0x08000501u
#define TLS_OPCODE_RSA_2048_PRIVATE_DECRYPT 0x08000701u
#define TLS_OPCODE_RSA_4096_PUBLIC_DECRYPT  0x10000501u
#define TLS_OPCODE_RSA_4096_PRIVATE_DECRYPT 0x10000701u

typedef
union ssl_crypto_opcode {
    struct
    {
        uint8_t function;
        uint8_t op;
        uint16_t bit;
    } s;
    uint32_t u32;
} ssl_crypto_opcode_t;

typedef struct ssl_crypto_op {
    struct ssl_thread_context *ctx;
    ssl_crypto_opcode_t opcode;

    uint8_t *in;
    uint8_t *out;

    uint8_t *key;
    uint8_t *iv;
    uint8_t *aad;	/* used for AEAD crypto operation */

    uint32_t in_len;
    uint16_t key_len;
    uint16_t iv_len;
    uint32_t out_len;
    uint16_t aad_len;	/* used for AEAD crypto operation */

    struct ssl_session* sess;
    void *data;

    TAILQ_ENTRY(ssl_crypto_op) op_pool_link;
    TAILQ_ENTRY(ssl_crypto_op) op_trace_link;
} ssl_crypto_op_t;

typedef struct ssl_crypto {
} ssl_crypto_t;

int
execute_rsa_crypto(ssl_crypto_op_t *op);

int
execute_aes_crypto(EVP_CIPHER_CTX *ctx, ssl_crypto_op_t *op);

int
execute_mac_crypto(ssl_crypto_op_t *op);

void
HMAC_SHA1(uint8_t *key, int key_len, uint8_t *in, int in_len, uint8_t *out);

int
PRF (const EVP_MD* (*hash_func)(void), const int secret_len, const uint8_t *secret,
     const int label_len,  const uint8_t *label,
     const int seed_len,   const uint8_t *seed,
     const int out_len,    uint8_t *out);

#endif /* __SSL_CRYPTO_H__ */
