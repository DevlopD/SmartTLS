#ifndef __SSL_CERT_H__
#define __SSL_CERT_H__

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>

#include <ssl_api.h>

typedef struct option
{
	char *key_file;
	char *key_passwd;
} option_t;
extern option_t option;

int
cert_load_key(mtcp_PUBLIC_CRYPTO_CTX* ctx);

#endif /* __SSL_CERT_H__ */
