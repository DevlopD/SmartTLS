#ifndef __SSL_H__
#define __SSL_H__

#include <sys/queue.h>
#include "mtcp_api.h"
#include "mtcp_ssl.h"
#include "tcp_in.h"

#define MAX_PLAIN_DATA_LEN ((size_t)15000)
#define MAX_RECORD_SIZE (16*1024)
#define MAX_HANDSHAKE_LENGTH 4096
#define MAX_KEY_SIZE 128
#define MAX_KEY_BLOCK_LEN (256 * 6)
#define MAX_IV_SIZE 16
#define MAC_SIZE 20

enum content_type {
    CHANGE_CIPHER_SPEC  = 20,
    ALERT               = 21,
    HANDSHAKE           = 22,
    APPLICATION_DATA    = 23,
};

typedef struct plain_text {
    uint8_t c_type;
    protocol_version_t version;
    uint16_t length;
    uint8_t* fragment;
} plain_text_t;

typedef struct compressed_text {
    uint8_t c_type;
    protocol_version_t version;
    uint16_t length;
    uint8_t* fragment;
} compressed_text_t;

typedef struct generic_block_cipher {
    uint8_t *IV;
    uint8_t *content;
    uint8_t *mac;
    uint8_t *padding;
    uint8_t padding_length;
} generic_block_cipher_t;

typedef struct generic_stream_cipher {
    uint8_t *content;
    uint8_t *mac;
} generic_stream_cipher_t;

typedef struct generic_aead_cipher {
    uint8_t *nonce_explicit;
    uint8_t *content;
} generic_aead_cipher_t;

typedef struct tls_ciphertext {
    uint8_t c_type;
    protocol_version_t version;
    unsigned short length;
    union {
        generic_block_cipher_t block_cipher;
        generic_stream_cipher_t stream_cipher;
        generic_aead_cipher_t aead_cipher;
    } fragment;
} cipher_text_t;

enum handshake_type {
    HELLO_REQUEST       = 0,
    CLIENT_HELLO        = 1,
    SERVER_HELLO        = 2,
    CERTIFICATE         = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE   = 14,
    CERTIFICATE_VERIFY  = 15,
    CLIENT_KEY_EXCHANGE = 16,
    CLIENT_CIPHER_SPEC  = 17,
    CLIENT_FINISHED     = 20,
    SERVER_CIPHER_SPEC  = 21,
    SERVER_FINISHED     = 22,
};

enum alert_level {
	WARNING         = 1,
	FATAL           = 2,
};

enum alert_description {
    CLOSE_NOTIFY                = 0,
    UNEXPECTED_MESSAGE          = 10,
	BAD_RECORD_MAC              = 20,
	DECRYPTION_FAILED_RESERVED  = 21,
	RECORD_OVERFLOW             = 22,
	DECOMPRESSION_FAILURE       = 30,
	HANDSHAKE_FAILURE           = 40,
	NO_CERTIFICATE_RESERVED     = 41,
	BAD_CERTIFICATE             = 42,
	UNSUPPORTED_CERTIFICATE     = 43,
	CERTIFICATE_REVOKED         = 44,
	CERTIFICATE_EXPIRED         = 45,
	CERTIFICATE_UNKNOWN         = 46,
	ILLEGAL_PARAMETER           = 47,
	UNKNOWN_CA                  = 48,
	ACCESS_DENIED               = 49,
	DECODE_ERROR                = 50,
	DECRYPT_ERROR               = 51,
	EXPORT_RESTRICTION_RESERVED = 60,
	PROTOCOL_VERSION            = 70,
	INSUFFICIENT_SECURITY       = 71,
	INTERNEL_ERROR              = 80,
	USER_CANCELED               = 90,
	NO_RENEGOTIATION            = 100,
	UNSUPPORTED_EXTENSION       = 110,
};

typedef enum {
    TO_PACK_HEADER,
    TO_PACK_CONTENT,
    TO_APPEND_MAC,
    TO_ENCRYPT,
    WRITE_READY,
    TO_UNPACK_HEADER,
    TO_DECRYPT,
    TO_VERIFY_MAC,
    TO_UNPACK_CONTENT,
    READ_READY,

    NULL_STATE
} ssl_record_state_t;

typedef struct uint24 {
    uint8_t u8[3];
} uint24_t;

typedef uint64_t sequence_num_t;

typedef struct random {
    uint32_t gmt_unix_time;
    uint8_t rand_bytes[28];
} __attribute__((packed)) random_t;

typedef struct session_id {
    uint8_t id[32];
} session_id_t;

typedef struct cipher_suite {
    uint8_t cs[2];
} cipher_suite_t;

static const cipher_suite_t TLS_RSA_WITH_AES_128_CBC_SHA = {{0x00, 0x2f}};
static const cipher_suite_t TLS_RSA_WITH_AES_256_CBC_SHA = {{0x00, 0x35}};
static const cipher_suite_t TLS_RSA_WITH_AES_256_GCM_SHA384 = {{0x00, 0x9d}};
static const cipher_suite_t TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = {{0xc0, 0x30}};
static const cipher_suite_t TLS_NULL_WITH_NULL_NULL = {{0x00, 0x00}};

#define COMPARE_CIPHER(x, y) ( \
    ((x.cs[0] == y.cs[0]) && (x.cs[1] == y.cs[1])) ? 1 : 0 \
)

#define ASSIGN_CIPHER(d, s) { \
    d.cs[0] = s.cs[0]; \
    d.cs[1] = s.cs[1]; \
}

typedef struct compression_method {
    uint8_t cm;
} compression_method_t;

typedef struct client_hello {
    protocol_version_t version;
    random_t random;
    uint8_t session_id_length;
    session_id_t session_id;
    uint16_t cipher_suite_length;
    cipher_suite_t *cipher_suites;
    uint8_t compression_method_length;
    compression_method_t *compression_methods;
    uint16_t extension_length;
    uint8_t *extension;
} client_hello_t;

typedef struct server_hello {
    protocol_version_t version;
    random_t random;
    uint8_t session_id_length;
    session_id_t session_id;
    cipher_suite_t cipher_suite;
    compression_method_t compression_method;
} server_hello_t;

typedef enum {
    SERVER = 0,
    CLIENT = 1
} connection_end_t;

/* Need to support more PRF algorithms later */
typedef enum {
    PRF_SHA256 = 0,
    PRF_SHA384 = 1
} prf_algorithm_t;

typedef enum {
    NO_COMP = 0
} compression_method_enum_t;


typedef struct security_params {
    connection_end_t            entity;
	cipher_suite_t              cipher;
    prf_algorithm_t             prf_algorithm;
    bulk_cipher_algorithm_t     bulk_cipher_algorithm;
    cipher_type_t               cipher_type;
    uint8_t                     enc_key_size;
    uint8_t                     block_length;
    uint8_t                     fixed_iv_length;
    uint8_t                     record_iv_length;
    mac_algorithm_t             mac_algorithm;
    uint8_t                     mac_length;
    uint8_t                     mac_key_size;
    compression_method_enum_t   compression_algorithm;
    uint8_t                     master_secret[48];
    uint8_t                     client_random[32];
    uint8_t                     server_random[32];
} security_params_t;

typedef struct certificate {
    uint24_t length;
    uint8_t *certificate;
} certificate_t;

typedef struct certificate_list {
    uint24_t certificate_length;
    certificate_t *certificates;
} certificate_list_t;

typedef struct premaster_secret {
    protocol_version_t version;
    uint8_t random[46];
} premaster_secret_t;

typedef struct encrypted_premaster_secret {
    uint8_t *encrypted_premaster_secret;
} encrypted_premaster_secret_t;

typedef struct client_diffie_hellman_public {
    uint8_t *data;
} client_diffie_hellman_public_t;

typedef struct client_key_exchange {
    union {
        encrypted_premaster_secret_t rsa;
        client_diffie_hellman_public_t diffie_hellman;
    } key;
    premaster_secret_t ps;
} client_key_exchange_t;

typedef struct finished {
    uint8_t verify_data[12];
} finished_t;


typedef struct change_cipher_spec {
    uint8_t type;
} change_cipher_spec_t;

typedef struct alert {
	uint8_t level;
    uint8_t description;
} alert_t;

#define HANDSHAKE_HEADER_SIZE 4
typedef struct handshake {
    uint8_t msg_type;
    uint24_t length;
    union {
        client_hello_t client_hello;
        server_hello_t server_hello;
        certificate_list_t certificate;
        client_key_exchange_t client_key_exchange;
        finished_t client_finished;
        finished_t server_finished;
    } body;
} handshake_t;

typedef struct application_data {
    uint8_t *data;
} application_data_t;


#define RECORD_HEADER_SIZE 5
/* ToDo: remame variables for better readability */
typedef struct record {
    int id;
    struct ssl_thread_context *ctx;
    struct ssl_session *sess;

    ssl_record_state_t state;
    size_t length;
    size_t current_len;
#if SEG_RECORD_BUF
    uint8_t buf[TCP_EXTENDED_MSS];
#else
    uint8_t buf[MAX_RECORD_SIZE];
#endif
    uint8_t *data;
    uint8_t buf_unencrypted[MAX_RECORD_SIZE];
    uint8_t *mac_in;
    uint8_t *decrypted;
    uint8_t *next_iv;
    uint8_t is_reset;
    uint8_t is_received;
    uint8_t is_encrypted;
    uint8_t mac_buf[MAC_SIZE];

#if SEG_RECORD_BUF
	int total_payload_to_send;
#endif
	int payload_to_send;
	int total_to_send;
	int already_sent;
	void *where_to_send;

    sequence_num_t seq_num;

    plain_text_t plain_text;
    cipher_text_t cipher_text;

    union {
        change_cipher_spec_t change_cipher_spec;
        alert_t alert;
        handshake_t handshake;
        application_data_t application_data;
    } fragment;

    TAILQ_ENTRY(record) recv_q_link;
    TAILQ_ENTRY(record) record_pool_link;
    TAILQ_ENTRY(record) record_trace_link;
} record_t;

#endif /* __SSL_H__ */
