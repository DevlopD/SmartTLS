#ifndef __SSLOFF_H__
#define __SSLOFF_H__

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <gmp.h>
#include <assert.h>
#include <byteswap.h>
#include <pthread.h>
#include <sched.h>
#include <netinet/in.h>

#include "option.h"
#include "ssl.h"
#include "ssl_crypto.h"
#include "ssl_api.h"

#include "tcp_in.h"

#define MAX_CPUS            16
#define MAX_DPDK_PORT       8
#define MAX_TCP_PORT            65536

#define RECORD_SIZE_LIMIT		16384

#if 0
/* TCP Flags */
#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08
#define TCP_FLAG_ACK        0x10
#endif

#define SSL_PORT            443

#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

enum ssl_session_state {
    STATE_INIT,
    STATE_HANDSHAKE,
    STATE_ACTIVE,
	STATE_CLOSE_SENT,
	STATE_CLOSE_RECEIVED,
	STATE_CLOSED,
};

struct ssl_session {
	mctx_t				mctx;

    int		            coreid;
	int					sockid;

    int                 state;
    int                 handshake_state;
    uint16_t            num_current_records;
    int                 next_record_id;

    struct ssl_thread_context* ctx;
    record_t *current_read_record;
	record_t *current_send_record;

    protocol_version_t  version;

    session_id_t        id_;

    sequence_num_t send_seq_num_;
    sequence_num_t recv_seq_num_;

    uint8_t handshake_msgs[MAX_HANDSHAKE_LENGTH];
    int handshake_msgs_len;

    uint8_t client_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t server_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t client_write_key[MAX_KEY_SIZE];
    uint8_t server_write_key[MAX_KEY_SIZE];
    uint8_t client_write_IV[MAX_KEY_SIZE];
    uint8_t server_write_IV[MAX_KEY_SIZE];
    sequence_num_t client_write_IV_seq_num;
    sequence_num_t server_write_IV_seq_num;

    uint64_t rand_seed;

    security_params_t   pending_sp;
    security_params_t   read_sp;
    security_params_t   write_sp;

    int waiting_crypto;
    TAILQ_HEAD(recv_q_head, record) recv_q;
    int recv_q_cnt;

	int msg_num[MAX_MTCP_SSL_RET];

	int read_buf_offset;
	char read_buf[RECORD_SIZE_LIMIT];
};


struct ssl_thread_context {
    uint16_t coreid;
	mctx_t mctx;

	const void *method;
    mtcp_PUBLIC_CRYPTO_CTX public_crypto_ctx;
	EVP_CIPHER_CTX *symmetric_crypto_ctx;

    uint8_t rsa_result[128];

    TAILQ_HEAD(record_pool_head, record) record_pool;
    int free_record_cnt;
    int using_record_cnt;

    TAILQ_HEAD(op_pool_head, ssl_crypto_op) op_pool;
    int free_op_cnt;
    int using_op_cnt;

    TAILQ_HEAD(record_trace_head, record) whole_record;
    TAILQ_HEAD(op_trace_head, ssl_crypto_op) whole_op;
};


#define OFF_PROTO 1234

extern uint32_t complete_conn[MAX_CPUS];
extern uint8_t port_type[MAX_DPDK_PORT];
extern int max_conn;
extern int local_max_conn;

/* Functions */
/*--------------------------------------------------------------------------*/
/* main.c */
void
global_destroy(void);

/*--------------------------------------------------------------------------*/
/* tcp.c */

int
abort_session(struct ssl_session* sess);

/*--------------------------------------------------------------------------*/
/* ssl.c */
 
int
process_crypto(struct ssl_thread_context* ctx);

int
process_ssl_packet(struct ssl_session* ssl_sess,
                 uint8_t *payload, uint16_t payloadlen,
                 char *buf, uint16_t buf_len);

int
send_record(struct ssl_session* ssl_sess,
			record_t *record,
			uint8_t c_type, int length);

int
send_data(struct ssl_session* ssl_sess,
			void *buf,
			int num);

int
close_session(struct ssl_session* sess);

void
clear_session(struct ssl_session* ssl);

void
init_random(struct ssl_session* sess, uint8_t *random, unsigned size);

#endif /* __SSLOFF_H__ */
