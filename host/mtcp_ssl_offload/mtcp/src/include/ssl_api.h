#ifndef __SSL_API__
#define __SSL_API__

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
/* #include <openssl/ec.h> */

#include <mtcp_api.h>

#define MAX_CERTIFICATE_LENGTH 4096
#define RSA_PADDING RSA_PKCS1_PADDING
#define MAX_MTCP_SSL_RET 10

typedef struct ssl_session mtcp_SSL;
typedef struct ssl_thread_context mtcp_SSL_CTX;

typedef struct ssl_pubkey_context {
    uint8_t key_exchange_algorithm;
    uint8_t certificate[MAX_CERTIFICATE_LENGTH];
    int certificate_length;
	union {
		/* EC_KEY *ecc; */
		RSA *rsa;
	};
} mtcp_PUBLIC_CRYPTO_CTX;


typedef enum
{
	mtcp_TLSv1_2_server,
} mtcp_SSL_METHOD;

typedef enum
{
	mtcp_SSL_ERROR_UNKNOWN,
	mtcp_SSL_ERROR_INVALID_RECORD,
	mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE,
	mtcp_SSL_ERROR_CRYPTO_FAIL,
	mtcp_SSL_ERROR_SEQUENCE_ERR,
	mtcp_SSL_ERROR_INVALID_MAC,
	mtcp_SSL_ERROR_INVALID_CIPHER,
	mtcp_SSL_ERROR_INVALID_HANDSHAKE_HASH,
	mtcp_SSL_ERROR_TCP_RETURN_ZERO,
	mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE,
	mtcp_SSL_ERROR_INVALID_ARGUMENT,
	mtcp_SSL_ERROR_WANT_READ,
	mtcp_SSL_ERROR_WANT_WRITE,

} mtcp_SSL_ERROR;

typedef enum
{
	FAIL,
	mtcp_SSL_SUCCESS_NORMAL,
	mtcp_SSL_SUCCESS_OFFLOAD,
} mtcp_SSL_RET;

int mtcp_SSL_library_init(void);

mtcp_SSL_METHOD *
mtcp_TLSv1_2_server_method(void);

mtcp_SSL_CTX *
mtcp_SSL_CTX_new(mctx_t mctx, const mtcp_SSL_METHOD *method);

int
mtcp_get_free_op(mtcp_SSL_CTX *ssl_ctx);

int
mtcp_get_using_op(mtcp_SSL_CTX *ssl_ctx);

void
mtcp_SSL_CTX_free(mtcp_SSL_CTX *ssl_ctx);

int
mtcp_SSL_CTX_use_CRYPTO_CTX(mtcp_SSL_CTX *ssl_ctx, mtcp_PUBLIC_CRYPTO_CTX *crypto_ctx);

mtcp_SSL *
mtcp_SSL_new(mtcp_SSL_CTX *ssl_ctx);

void
mtcp_SSL_free(mtcp_SSL *ssl);

int
mtcp_SSL_set_fd(mtcp_SSL *ssl, int fd);

int
mtcp_SSL_get_fd(mtcp_SSL *ssl);

/* Clear all parameter except SSL_CTX related parameters. e.g.) mctx, coreid */
void
mtcp_SSL_clear(mtcp_SSL *ssl);

int
mtcp_SSL_accept(mtcp_SSL *ssl);

int
mtcp_SSL_get_error(mtcp_SSL *ssl, int ret_val);

int
mtcp_SSL_shutdown(mtcp_SSL *ssl);

int
mtcp_SSL_read(mtcp_SSL *ssl, void *buf, int num);

int
mtcp_SSL_write(mtcp_SSL *ssl, void *buf, int num);

#endif /* __SSL_API__ */
