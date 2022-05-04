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

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include "option.h"
#include "ssl.h"
#include "cert.h"
#include "ssl_crypto.h"

#if ONLOAD
#include "host.h"
#endif /* ONLOAD */

#if USE_TC_RULE
#include "tc.h"
#endif

#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 128

#define NUM_MBUFS           8192

#define MBUF_CACHE_SIZE     250
#define BURST_SIZE          32

#define MAX_PKT_BURST       256
#define MAX_CPUS            16
#define MAX_DPDK_PORT       8
#define MAX_TCP_PORT            65536

#define INIT_KEY_SIZE       16
#define INIT_IV_SIZE        16

#define RX_PTHRESH          8
#define RX_HTHRESH          8
#define RX_WTHRESH          4

#define TX_PTHRESH          36
#define TX_HTHRESH          0
#define TX_WTHRESH          0

#define RX_IDLE_ENABLE      TRUE

#define ETHER_TYPE_META     0x080F

/* TCP Flags */
#define TCP_FLAG_FIN        0x01
#define TCP_FLAG_SYN        0x02
#define TCP_FLAG_RST        0x04
#define TCP_FLAG_PSH        0x08
#define TCP_FLAG_ACK        0x10

/* TCP Send Offload Flags */
#define TCP_OFFL_TSO        0x01
#define TCP_OFFL_TLS_AES    0x02

#define SSL_PORT            443

#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

#ifdef MIN
#else
#define MIN(x, y)   ((int32_t)((x)-(y)) < 0 ? (x) : (y))
#endif

#ifdef MAX
#else
#define MAX(x, y)   ((int32_t)((x)-(y)) > 0 ? (x) : (y))
#endif

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

#define true 1
#define false 0

#define MAX_PKT_SIZE 1500
#define TCP_RTO 1000 /* unit: ms */
#define HEALTH_CHECK 10000 /* unit: ms */

#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define TCP_HEADER_LEN 20
#define TOTAL_HEADER_LEN 54

struct meta_hdr {
    uint32_t key_size;
    uint32_t iv_size;
    uint32_t reserved;
    uint16_t h_proto;
};

struct ssl_stat {
    uint64_t completes;
    uint64_t throughput;

    uint64_t only_tcp;
    uint64_t only_tcp_throughput;

    uint64_t rx_bytes[MAX_DPDK_PORT];
    uint64_t rx_pkts[MAX_DPDK_PORT];

    uint64_t tx_bytes[MAX_DPDK_PORT];
    uint64_t tx_pkts[MAX_DPDK_PORT];

    uint64_t rtx_bytes[MAX_DPDK_PORT];
    uint64_t rtx_pkts[MAX_DPDK_PORT];
};

enum tcp_session_state {
    TCP_SESSION_IDLE,
    TCP_SESSION_RECEIVED,
    TCP_SESSION_SENT,
};

enum ssl_session_state {
    STATE_INIT,
    STATE_HANDSHAKE,
    STATE_ACTIVE,
};

enum packet_type {
    PKT_TYPE_NONE,
    PKT_TYPE_HELLO,
    PKT_TYPE_FINISH,
#if OFFLOAD_AES_GCM
    PKT_TYPE_OFFL_TLS_AES,
#endif
};

struct ssl_session {
    uint16_t            coreid;
    int                 state;
    int                 handshake_state;
    uint16_t            num_current_records;
    int                 next_record_id;

    struct thread_context* ctx;
    struct tcp_session* parent;
    record_t *current_read_record;

#if OFFLOAD_AES_GCM
	uint8_t is_offl_aead;
	struct rte_eth_tls_ctx tls_ctx;
#endif

    protocol_version_t  version;

    session_id_t        id_;

    sequence_num_t send_seq_num_;
    sequence_num_t recv_seq_num_;

    uint8_t handshake_msgs[MAX_HANDSHAKE_LENGTH];
    int handshake_msgs_len;

    uint8_t send_buffer[MAX_RECORD_SIZE];
    int send_buffer_offset;

    uint8_t client_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t server_write_MAC_secret[MAX_KEY_SIZE];
    uint8_t client_write_key[MAX_KEY_SIZE];
    uint8_t server_write_key[MAX_KEY_SIZE];
    uint8_t client_write_IV[MAX_KEY_SIZE];
    uint8_t server_write_IV[MAX_KEY_SIZE];
    sequence_num_t client_write_IV_seq_num;
    sequence_num_t server_write_IV_seq_num;

    uint8_t server_finish_digest[12];

    uint64_t rand_seed;

    pka_operand_t *rsa_operand;

    security_params_t   pending_sp;
    security_params_t   read_sp;
    security_params_t   write_sp;

    int waiting_crypto;
    TAILQ_HEAD(recv_q_head, record) recv_q;
    int recv_q_cnt;

    void *pending_rsa_op;	/* ssl_crypto_op_t* */
};

struct tcp_session {
    struct thread_context* ctx;

    int             state;
    int             onload;

    uint16_t        coreid;
    uint16_t        portid;
    uint16_t        session_id;
    uint16_t        ip_id;

    struct timeval  last_interaction;

    unsigned char   client_mac[6];
    unsigned char   server_mac[6];

    uint32_t        client_ip;
    uint32_t        server_ip;

    uint16_t        client_port;
    uint16_t        server_port;

    uint32_t        last_recv_seq;
    uint32_t        last_recv_ack;
    uint32_t        last_recv_len;

    uint32_t        last_sent_seq;
    uint32_t        last_sent_ack;
    uint32_t        last_sent_len;

#if OFFLOAD_AES_GCM
    uint32_t        next_sent_seq;
#endif

    uint32_t        total_sent;

    uint16_t        window;

#if USE_TC_RULE
	struct tc_flower tc_obj;
	struct tc_flower tc_rev_obj; /* reversed rule */
	uint16_t tc_prio;
#endif

    struct ssl_session *ssl_session;
    TAILQ_ENTRY(tcp_session) active_session_link;
    TAILQ_ENTRY(tcp_session) free_session_link;
};

struct mbuf_table {
    uint16_t len; /* length of queued packets */
    struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct dpdk_private_context {
    struct mbuf_table rmbufs[RTE_MAX_ETHPORTS];
    struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];
    struct rte_mempool *pktmbuf_pool;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
#ifdef RX_IDLE_ENABLE
    uint8_t rx_idle;
#endif
} __rte_cache_aligned;

struct thread_context {
    int ready;
    uint16_t coreid;

	EVP_CIPHER_CTX *symmetric_crypto_ctx;

    struct dpdk_private_context *dpc;
    struct tcp_session** tcp_array;

    pka_handle_t *handle;
    pka_results_t *rsa_result;
    unsigned cur_crypto_cnt;

	ssl_context_t* ssl_context;

    TAILQ_HEAD(record_pool_head, record) record_pool;
    int free_record_cnt;
    int using_record_cnt;

    TAILQ_HEAD(op_pool_head, ssl_crypto_op) op_pool;
    int free_op_cnt;
    int using_op_cnt;

    int decrease;

#if USE_TC_RULE
	uint16_t tc_rule_cnt;
#endif

    TAILQ_HEAD(record_trace_head, record) whole_record;
    TAILQ_HEAD(op_trace_head, ssl_crypto_op) whole_op;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    struct hashtable *active_session_table;
#else
    TAILQ_HEAD(active_head, tcp_session) active_session_q;
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    int active_cnt;

    TAILQ_HEAD(free_head, tcp_session) free_session_q;
    int free_cnt;

    struct ssl_stat stat;
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh    =   RX_PTHRESH,
        .hthresh    =   RX_HTHRESH,
        .wthresh    =   RX_WTHRESH,
    },
    .rx_free_thresh =   32,
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh    =   TX_PTHRESH,
        .hthresh    =   TX_HTHRESH,
        .wthresh    =   TX_WTHRESH,
    },
    .tx_free_thresh =   0,
    .tx_rs_thresh   =   0,
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
    .txq_flags      =   0x0,
#endif
};

#define OFF_PROTO 1234
extern uint8_t nic_key[MAX_KEY_SIZE];
extern uint8_t nic_key_size;
extern uint8_t nic_iv[MAX_KEY_SIZE];
extern uint8_t nic_iv_size;
extern uint8_t host_key[MAX_KEY_SIZE];
extern uint8_t host_key_size;
extern uint8_t host_iv[MAX_KEY_SIZE];
extern uint8_t host_iv_size;

extern struct ssl_stat global_stat;
extern struct rte_mempool *pktmbuf_pool[MAX_CPUS];
extern struct thread_context* ctx_array[MAX_CPUS];
extern uint32_t complete_conn[MAX_CPUS];
extern uint8_t port_type[MAX_DPDK_PORT];
extern ssl_context_t ctx_example;
extern int max_conn;
extern int local_max_conn;

extern pka_instance_t instance;
extern pka_barrier_t thread_start_barrier;
extern pka_handle_t handle[MAX_CPUS];

extern uint8_t t_major;
extern uint8_t t_minor;

/* Functions */
/*--------------------------------------------------------------------------*/
/* main.c */
void
global_destroy(void);

/*--------------------------------------------------------------------------*/
/* tcp.c */

int
ssloff_main_loop(__attribute__((unused)) void *arg);

int
abort_session(struct ssl_session* sess);

int
send_meta_packet(int coreid, int port, struct tcp_session *sess,
                uint32_t next_recv_seq, uint32_t next_recv_ack,
                uint8_t* payload, uint16_t payload_len);

int
send_tcp_packet(struct tcp_session *sess, uint8_t *payload,
                uint16_t len, uint8_t flags, uint8_t offl_flags);

/*--------------------------------------------------------------------------*/
/* dpdk_io.c */
void
free_pkts(struct rte_mbuf **mtable, unsigned len);

int32_t
recv_pkts(uint16_t core_id, uint16_t port);

uint8_t *
get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t *len);

int
send_pkts(uint16_t core_id, uint16_t port);

#if OFFLOAD_AES_GCM
struct rte_mbuf *
get_wmbuf(uint16_t core_id, uint16_t port, uint16_t pktsize);
#endif

uint8_t *
get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize);

/*--------------------------------------------------------------------------*/
/* ssl.c */

pka_results_t *
malloc_results(uint32_t result_cnt, uint32_t buf_len);

void
clear_results(pka_results_t *results);

void
free_results(pka_results_t *results);

int
process_crypto(struct thread_context* ctx);

int
process_ssl_packet(struct tcp_session* tcp_sess,
                 uint8_t *payload, uint16_t payloadlen);
void
init_random(struct ssl_session* sess, uint8_t *random, unsigned size);

void
remove_pending_rsa_op(struct ssl_session* sess);
 
int
process_session_read(struct ssl_session* sess);

int
send_server_hello(struct ssl_session* sess);

int
send_certificate(struct ssl_session* sess);

int
send_server_hello_done(struct ssl_session* sess);

int
send_change_cipher_spec(struct ssl_session* sess);

int
send_server_finish(struct ssl_session *sess, uint8_t *digest);

#endif /* __SSLOFF_H__ */
