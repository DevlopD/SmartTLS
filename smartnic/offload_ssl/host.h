#ifndef __HOST_H__
#define __HOST_H__

#include "ssloff.h"

/* ToDo: dynamically resize this; MAX_KEY_SIZE is too big now */
typedef struct conn_meta {
    uint16_t session_id;

    /* SSL related parameter */
    protocol_version_t  version;

    bulk_cipher_algorithm_t bulk_cipher_algorithm;
    cipher_type_t cipher_type;
    mac_algorithm_t mac_algorithm;

    uint8_t mac_key_size;
    uint8_t client_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t server_write_MAC_secret[MAX_KEY_SIZE];

    uint8_t enc_key_size;
    uint8_t client_write_key[MAX_KEY_SIZE];
    uint8_t server_write_key[MAX_KEY_SIZE];

    uint8_t fixed_iv_length;
    uint8_t client_write_IV[MAX_KEY_SIZE];
    uint8_t server_write_IV[MAX_KEY_SIZE];
} conn_meta_t;

int
send_connection_state(struct ssl_session* sess, int change_cipher_pkt_len, int server_finish_len);

int
change_connection_rule(struct ssl_session* sess);

#endif /* __HOST_H__ */
