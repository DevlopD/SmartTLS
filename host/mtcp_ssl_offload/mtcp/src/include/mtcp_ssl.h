#ifndef MTCP_SSL_H
#define MTCP_SSL_H

#include "mtcp_api.h"

#define MAX_KEY_SIZE 128

typedef struct protocol_version {
	uint8_t major;
	uint8_t minor;
} protocol_version_t;

typedef enum {
	NO_CIPHER = 0,
	RC4	= 1,
	RC2	= 2,
	DES	= 3,
	DES3	= 4,
	DES40	= 5,
	AES	= 6
} bulk_cipher_algorithm_t;

typedef enum {
	NO_TYPE = 0,
	STREAM	= 1,
	BLOCK	= 2,
	AEAD	= 3
} cipher_type_t;

typedef enum {
	NO_MAC  	= 0,
	MAC_MD5 	= 1,
	MAC_SHA1	= 2,
	MAC_SHA256	= 3,
	MAC_SHA384	= 4,
	MAC_SHA512	= 5
} mac_algorithm_t;

typedef struct ssl_info {
	uint16_t session_id;

	protocol_version_t version;

	bulk_cipher_algorithm_t bulk_cipher_algorithm;
	cipher_type_t cipher_type;
	mac_algorithm_t mac_algorithm;

	/* ToDo: support aes256gcm-sha384 for SmartNIC */
	/* Also, we need to reduce metadata size - MAX_KEY_SIZE is too big */
	/* union { */
	/* 	struct keyblock_aes256cbc_sha1 kb_aes256cbc_sha1; */
	/* 	struct keyblock_aes256gcm_sha384 kb_aes256gcm_sha384; */
	/* 	uint8_t buf[MAX_KEY_SIZE*6 + 3] */
	/* } key_block; */

	uint8_t mac_key_size;
	uint8_t client_write_MAC_secret[MAX_KEY_SIZE];
	uint8_t server_write_MAC_secret[MAX_KEY_SIZE];

	uint8_t enc_key_size;
	uint8_t client_write_key[MAX_KEY_SIZE];
	uint8_t server_write_key[MAX_KEY_SIZE];

	uint8_t fixed_iv_length;
	uint8_t client_write_IV[MAX_KEY_SIZE];
	uint8_t server_write_IV[MAX_KEY_SIZE];

	uint8_t active;
} ssl_info_t;

struct meta_hdr {
        uint32_t        key_size;
        uint32_t        iv_size;
        uint32_t        reserved;
        uint16_t        h_proto;
};

int
mtcp_accept_tls(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen,
		ssl_info_t *info);

#endif /* MTCP_SSL_H */
