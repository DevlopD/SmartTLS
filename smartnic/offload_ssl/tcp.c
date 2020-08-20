#include <sys/time.h>

#include "ssloff.h"
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
#include "fhash.h"
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */

#define B_TO_Mb(x) ((x) * 8 / 1000 / 1000)

#define TCP_SEQ_LT(a,b)         ((int32_t)((a)-(b)) < 0)
#define TCP_SEQ_LEQ(a,b)        ((int32_t)((a)-(b)) <= 0)
#define TCP_SEQ_GT(a,b)         ((int32_t)((a)-(b)) > 0)
#define TCP_SEQ_GEQ(a,b)        ((int32_t)((a)-(b)) >= 0)
#define TCP_SEQ_BETWEEN(a,b,c)  (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

#define ISN 1234
/* for RSA 2048 bit */
/* #define UPPER_BOUND 150 */
/* #define LOWER_BOUND 145 */
/* for RSA 2048 bit with static tc rule */
#define UPPER_BOUND 80
#define LOWER_BOUND 78
/* for RSA 4096 bit */
/* #define UPPER_BOUND 35 */
/* #define LOWER_BOUND 32 */

int test_flag = 1;

/*---------------------------------------------------------------------------*/
/* Function Prototype */

#if ONLOAD
static inline int
is_overloaded(struct thread_context *ctx, struct ether_hdr *ethh);
#endif /* ONLOAD */

static inline void
clear_tcp_session(struct tcp_session *tcp);

static inline void
clear_ssl_session(struct ssl_session *ssl);

static void
thread_local_init(int core_id);

static void
thread_local_destroy(int core_id);

static inline void
remove_session(struct ssl_session* sess);

static inline struct tcp_session *
search_tcp_session(struct thread_context *ctx,
                   uint32_t client_ip, uint16_t client_port,
                   uint32_t server_ip, uint16_t server_port);

static inline struct tcp_session *
pop_free_session(struct thread_context *ctx);

static inline struct tcp_session *
insert_tcp_session(struct thread_context *ctx, uint16_t portid,
                   const unsigned char* client_mac, 
                   uint32_t client_ip, uint16_t client_port,
                   const unsigned char* server_mac,
                   uint32_t server_ip, uint16_t server_port,
                   uint32_t seq_no, uint32_t ack_no, uint32_t cookie,
                   uint16_t window, int payload_len);

static inline int
validate_sequence(struct tcp_session *sess, uint32_t seq_no);

static void
process_packet(uint16_t core_id, uint16_t port, uint8_t *pktbuf, int len);

static inline unsigned
check_ready(void);

static inline int
process_session_health_check(struct tcp_session *sess);

/*---------------------------------------------------------------------------*/

static inline uint32_t
get_cookie(uint32_t client_ip, uint16_t client_port,
           uint32_t server_ip, uint16_t server_port)
{
    uint32_t cookie;
    uint32_t input[3];
    uint8_t hash[20];

    cookie = t_major;
    cookie = cookie << 3;

    cookie += 3; /* MSS 1500 */

    /* Make hash input */
    input[0] = client_ip;
    input[1] = server_ip;
    input[2] = (uint32_t)client_port | ((uint32_t)server_port << 16);

    SHA1((uint8_t *)input, 12, hash);

    cookie = cookie << 8;
    cookie += hash[0];

    cookie = cookie << 8;
    cookie += hash[1];

    cookie = cookie << 8;
    cookie += hash[2];

    return cookie;
}

#if ONLOAD
static inline int
is_overloaded(struct thread_context *ctx, struct ether_hdr *ethh)
{
#if !NO_TLS
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;
    int ret = 0;
    int waiting_op = 0;
    int i;

    iph = (struct ipv4_hdr *)(ethh + 1);
    tcph = (struct tcp_hdr *)(iph + 1);
    for (i = 0; i < MAX_CPUS; i++) {
        if (ctx_array[i])
            waiting_op += ctx_array[i]->using_op_cnt;
    }

    if (waiting_op < LOWER_BOUND)
        ctx->decrease = 0;

    if (waiting_op > UPPER_BOUND)
        ctx->decrease = 1;

    if (ctx->decrease)
        ret = 1;

    //fprintf(stderr, "waiting_op: %d\n", waiting_op);


    UNUSED(ctx);
    UNUSED(tcph);
    return ret;

#else  /* !NO_TLS */
    UNUSED(ctx);
    UNUSED(ethh);
    return 1;
#endif /* NO_TLS */
}
#endif /* ONLOAD */

static inline void
clear_tcp_session(struct tcp_session *tcp)
{
    /* Do not touch coreid, ssl_session */
    tcp->state = TCP_SESSION_IDLE;
    tcp->portid = 0;

    tcp->ip_id = 0;

    tcp->client_ip = 0;
    tcp->client_port = 0;

#if ONLOAD
    tcp->onload = FALSE;
#endif /* ONLOAD */

    tcp->server_ip = 0;
    tcp->server_port = 0;

    tcp->window = 0;

    tcp->total_sent = 0;

    tcp->last_recv_seq = 0;
    tcp->last_recv_ack = 0;
    tcp->last_recv_len = 0;

    tcp->last_sent_seq = 0;
    tcp->last_sent_ack = 0;
    tcp->last_sent_len = 0;
}

static inline void
clear_ssl_session(struct ssl_session *ssl)
{
    /* Do not touch parent, context_ */
    ssl->state = STATE_INIT;
    ssl->handshake_state = HELLO_REQUEST;

    ssl->current_read_record = NULL;

    ssl->version.major = 0;
    ssl->version.minor = 0;

    ssl->recv_seq_num_ = 0;
    ssl->send_seq_num_ = 0;

    ssl->handshake_msgs_len = 0;

    ssl->client_write_IV_seq_num = 0;
    ssl->server_write_IV_seq_num = 0;

    ssl->rand_seed = rand();

    memset(&ssl->send_buffer, 0, sizeof(ssl->send_buffer));
    ssl->send_buffer_offset = 0;

    memset(&ssl->read_sp, 0, sizeof(ssl->read_sp));
    memset(&ssl->write_sp, 0, sizeof(ssl->write_sp));
    memset(&ssl->pending_sp, 0, sizeof(ssl->pending_sp));

    ssl->read_sp.entity = SERVER;
    ssl->write_sp.entity = SERVER;

    /* Remove the pending rsa op and corresponding record */
    remove_pending_rsa_op(ssl);

    /* Remove records from the session */
    record_t *cur, *next;
    cur = TAILQ_FIRST(&ssl->recv_q);
    while(cur != NULL) {
        next = TAILQ_NEXT(cur, recv_q_link);

        /* Remove from receive queue */
        TAILQ_REMOVE(&ssl->recv_q, cur, recv_q_link);

        /* Clear the record */
        memset(cur, 0, sizeof(record_t));
        cur->ctx = ssl->ctx;

        /* Put the record back to the record pool */
        TAILQ_INSERT_TAIL(&ssl->ctx->record_pool, cur, record_pool_link);
        ssl->ctx->free_record_cnt++;
        ssl->ctx->using_record_cnt--;
        
        cur = next;
    }

    ssl->num_current_records = 0;
    ssl->recv_q_cnt = 0;

    ssl->waiting_crypto = FALSE;

    init_random(ssl, ssl->id_.id, sizeof(ssl->id_.id));
}

static void
thread_local_init(int core_id)
{
    struct thread_context* ctx;
    struct dpdk_private_context* dpc;
    struct ssl_session* ssl;
    int nb_ports;
    int i, j;

    nb_ports = rte_eth_dev_count_avail();

    /* Allocate memory for thread context */
    ctx_array[core_id] = calloc(1, sizeof(struct thread_context));
    ctx = ctx_array[core_id];
    if (ctx == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for thread_context, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    ctx->ready = 0;
    ctx->coreid = (uint16_t)core_id;

    /* Allocate memory for dpdk private context */
    ctx->dpc = calloc(1, sizeof(struct dpdk_private_context));
    dpc = ctx->dpc;
    if (dpc == NULL)
        rte_exit(EXIT_FAILURE,
                 "[CPU %d] Cannot allocate memory for dpdk_private_context, "
                 "errno: %d\n",
                 rte_lcore_id(), errno);

    /* Assign packet mbuf pool to dpdk private context */
    dpc->pktmbuf_pool = pktmbuf_pool[core_id];

    for (j = 0; j < nb_ports; j++) {
        /* Allocate wmbufs for each registered port */
        for (i = 0; i< MAX_PKT_BURST; i++) {
            dpc->wmbufs[j].m_table[i] =
				rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
            if (dpc->wmbufs[j].m_table[i] == NULL) {
                rte_exit(EXIT_FAILURE,
                         "[CPU %d] Cannot allocate memory for "
                         "port %d wmbuf[%d]\n",
                         rte_lcore_id(), j, i);
            }
        }
        dpc->wmbufs[j].len = 0;
    }

    /* Initialize Session Queues */
#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ctx->active_session_table = create_ht(NUM_BINS);
    if(!ctx->active_session_table) {
		fprintf(stderr, "Cannot allocate memory for "
         		"session hashtable of core[%d]",
	        	rte_lcore_id());
		exit(EXIT_FAILURE);
    }
#else
    TAILQ_INIT(&ctx->active_session_q);
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    ctx->active_cnt = 0;

    TAILQ_INIT(&ctx->free_session_q);
    ctx->free_cnt = 0;

    ctx->tcp_array = calloc(local_max_conn, sizeof(struct tcp_session *));

	/* Initialize ssl_ctx */
	ctx->ssl_context = calloc(1, sizeof(ctx_example));
	if (ctx->ssl_context == NULL) {
		fprintf(stderr, "Cannot allocate memory for"
				"core[%d]\n",
				rte_lcore_id());
		exit(EXIT_FAILURE);
	}
	memcpy(ctx->ssl_context, &ctx_example, sizeof(ctx_example));

	ctx->ssl_context->rsa = calloc(1, sizeof(RSA));
	if (ctx->ssl_context->rsa == NULL) {
		fprintf(stderr, "Cannot allocate memory for"
				"%dth rsa context of core[%d]\n",
				j, rte_lcore_id());
		exit(EXIT_FAILURE);
	}
	memcpy(ctx->ssl_context->rsa, ctx_example.rsa, sizeof(RSA));

	ctx->ssl_context->pka = calloc(1, sizeof(pka_t));
	if (ctx->ssl_context->pka == NULL) {
		fprintf(stderr, "Cannot allocate memory for"
				"%dth pka context of core[%d]\n",
				j, rte_lcore_id());
		exit(EXIT_FAILURE);
	}
	memcpy(ctx->ssl_context->pka, ctx_example.pka, sizeof(pka_t));

    /* Allocate memory for tcp sessions */
    for (j = 0; j < local_max_conn; j++) {
        ctx->tcp_array[j] = calloc(1, sizeof(struct tcp_session));
        if (ctx->tcp_array[j] == NULL) {
            fprintf(stderr, "Cannot allocate memory for"
					"%dth tcp array of core[%d]\n",
					j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        /* Insert Session into free_session_q */
        TAILQ_INSERT_TAIL(&ctx->free_session_q,
                          ctx->tcp_array[j], free_session_link);
        ctx->free_cnt++;

        clear_tcp_session(ctx->tcp_array[j]);
        ctx->tcp_array[j]->ctx = ctx;
        ctx->tcp_array[j]->coreid = core_id;
        ctx->tcp_array[j]->session_id = j;
        ctx->tcp_array[j]->ssl_session = calloc(1, sizeof(struct ssl_session));
        if (ctx->tcp_array[j]->ssl_session == NULL) {
            fprintf(stderr, "Cannot allocate memory for"
					"%dth ssl session of core[%d]\n",
					j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        /* Initialize SSL Session */
        ssl = ctx->tcp_array[j]->ssl_session;
        ssl->ctx = ctx;
        ssl->parent = ctx->tcp_array[j];
        ssl->coreid = ctx->tcp_array[j]->coreid;


        ssl->next_record_id = 0;

        TAILQ_INIT(&ssl->recv_q);
        ssl->recv_q_cnt = 0;

        ssl->waiting_crypto = FALSE;

        ssl->rsa_operand = calloc(1, sizeof(ctx_example));
        if (ssl->rsa_operand == NULL) {
            fprintf(stderr, "Cannot allocate memory for"
					"%dth rsa operand of core[%d]\n",
					j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        ssl->rsa_operand->buf_ptr = calloc(1, MAX_BYTE_LEN + 8);
        if (ssl->rsa_operand->buf_ptr == NULL) {
            fprintf(stderr, "Cannot allocate memory for"
					"buf of %dth rsa operand of core[%d]\n",
					j, rte_lcore_id());
            exit(EXIT_FAILURE);
        }

        ssl->rsa_operand->buf_len = MAX_BYTE_LEN + 8;

        clear_ssl_session(ssl);
    }

    pka_barrier_wait(&thread_start_barrier);
    handle[core_id] = pka_init_local(instance);
    if (handle[core_id] == PKA_HANDLE_INVALID) {
        fprintf(stderr, "Local PKA initialilzation failed\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "PKA Locally Initialized for Core %d\n", core_id);

    ctx->handle = &handle[core_id];
    ctx->cur_crypto_cnt = 0;
    ctx->rsa_result = malloc_results(2, MAX_BYTE_LEN + 8);
    if (ctx->rsa_result == NULL) {
        fprintf(stderr, "malloc_results failed\n");
        exit(EXIT_FAILURE);
    }

    /* Insert local_max_conn * 5 records into record_pool */
    TAILQ_INIT(&ctx->record_pool);
    TAILQ_INIT(&ctx->whole_record);
    ctx->free_record_cnt = 0;
    ctx->using_record_cnt = 0;
    for (i = 0; i < local_max_conn * 4; i++) {
        record_t* new_record = (record_t *)calloc(1, sizeof(record_t));
        new_record->ctx = ctx;
        TAILQ_INSERT_TAIL(&ctx->record_pool, new_record, record_pool_link);
        /* For memory management */
        TAILQ_INSERT_TAIL(&ctx->whole_record, new_record, record_trace_link);
        ctx->free_record_cnt++;
    }

    /* Insert local_max_conn ops into op_pool */
    TAILQ_INIT(&ctx->op_pool);
    TAILQ_INIT(&ctx->whole_op);
    ctx->free_op_cnt = 0;
    ctx->using_op_cnt = 0;
    for (i = 0; i < local_max_conn; i++) {
        ssl_crypto_op_t* new_op =
			(ssl_crypto_op_t *)calloc(1, sizeof(ssl_crypto_op_t));
        new_op->ctx = ctx;
        TAILQ_INSERT_TAIL(&ctx->op_pool, new_op, op_pool_link);
        TAILQ_INSERT_TAIL(&ctx->whole_op, new_op, op_trace_link);
        ctx->free_op_cnt++;
    }

    ctx->decrease = 0;

    ctx->stat.completes = 0;
    ctx->stat.only_tcp = 0;
    ctx->stat.throughput = 0;
    ctx->stat.only_tcp_throughput = 0;

    RTE_ETH_FOREACH_DEV(i) {
        ctx->stat.rx_bytes[i] = 0;
        ctx->stat.rx_pkts[i] = 0;

        ctx->stat.tx_bytes[i] = 0;
        ctx->stat.tx_pkts[i] = 0;

        ctx->stat.rtx_bytes[i] = 0;
        ctx->stat.rtx_pkts[i] = 0;
    }

	/* Create and initialise the OpenSSL AES context */
	if(!(ctx->symmetric_crypto_ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Wrong ssl_aes_ctx\n");
        exit(EXIT_FAILURE);
    }
}

static void
thread_local_destroy(int core_id)
{
    struct thread_context* ctx;
    struct dpdk_private_context* dpc;
    struct tcp_session* tcp;
    struct ssl_session* ssl;
    int port, i;

    ctx = ctx_array[core_id];
    dpc = ctx->dpc;
    void *cur, *next;

    /* Free RSA result metadata buffer */
    free_results(ctx->rsa_result);

	EVP_CIPHER_CTX_free(ctx->symmetric_crypto_ctx);


    /* Remove sessions from queues */
    cur = TAILQ_FIRST(&ctx->free_session_q);
    while(cur != NULL) {
        next = (struct tcp_session *)TAILQ_NEXT((struct tcp_session *)cur,
                                                free_session_link);
        TAILQ_REMOVE(&ctx->free_session_q,
                     (struct tcp_session *)cur,
                     free_session_link);
        cur = next;
    }

#if !USE_HASHTABLE_FOR_ACTIVE_SESSION
    cur = TAILQ_FIRST(&ctx->active_session_q);
    while(cur != NULL) {
        next = (struct tcp_session *)TAILQ_NEXT((struct tcp_session *)cur,
                                                active_session_link);
        TAILQ_REMOVE(&ctx->active_session_q,
                     (struct tcp_session *)cur,
                     active_session_link);
        cur = next;
    }
#endif	/* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

    /* Destroy each session */
    for (i = 0; i < local_max_conn; i++) {
        tcp = ctx->tcp_array[i];
        ssl = tcp->ssl_session;

        /* Destroy SSL session */

        /* Free RSA operand metadata buffer */
        if (ssl->rsa_operand) {
            if (ssl->rsa_operand->buf_ptr)
                free(ssl->rsa_operand->buf_ptr);
            free(ssl->rsa_operand);
        }

        /* Remove records from recv queue */
        cur = TAILQ_FIRST(&ssl->recv_q);
        while(cur != NULL) {
            next = (record_t *)TAILQ_NEXT((record_t *)cur,
										  recv_q_link);
            TAILQ_REMOVE(&ssl->recv_q,
                         (record_t *)cur,
                         recv_q_link);
            cur = next;
        }

        /* Destroy SSL session */
        free(ssl);
        /* Destroy sessions */
        free(tcp);
    }

    free(ctx->tcp_array);

    /* Remove records and ops from their pools. */
    cur = TAILQ_FIRST(&ctx->op_pool);
    while(cur != NULL) {
        next = (ssl_crypto_op_t *)TAILQ_NEXT((ssl_crypto_op_t *)cur,
											 op_pool_link);
        TAILQ_REMOVE(&ctx->op_pool,
                     (ssl_crypto_op_t *)cur,
                     op_pool_link);
        cur = next;
    }

    cur = TAILQ_FIRST(&ctx->record_pool);
    while(cur != NULL) {
        next = (record_t *)TAILQ_NEXT((record_t *)cur,
									  record_pool_link);
        TAILQ_REMOVE(&ctx->record_pool,
                     (record_t *)cur,
                     record_pool_link);
        cur = next;
    }

    /* Free ops and records */
    cur = TAILQ_FIRST(&ctx->whole_op);
    while(cur != NULL) {
        next = (ssl_crypto_op_t *)TAILQ_NEXT((ssl_crypto_op_t *)cur,
                                             op_trace_link);
        TAILQ_REMOVE(&ctx->whole_op,
                     (ssl_crypto_op_t *)cur,
                     op_trace_link);
        free(cur);
        cur = next;
    }

    cur = TAILQ_FIRST(&ctx->whole_record);
    while(cur != NULL) {
        next = (record_t *)TAILQ_NEXT((record_t *)cur, record_trace_link);
        TAILQ_REMOVE(&ctx->whole_record,
                     (record_t *)cur,
                     record_trace_link);
        free(cur);
        cur = next;
    }

    /* Free dpdk private context */
    RTE_ETH_FOREACH_DEV(port) {
        if (dpc->rmbufs[port].len != 0) {
            free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
            dpc->rmbufs[port].len = 0;
        }
    }
    rte_mempool_free(dpc->pktmbuf_pool);
    free(ctx->dpc);

    /* Free thread context */
    free(ctx);
}

static inline void
remove_session(struct ssl_session* sess)
{
    struct thread_context *ctx = ctx_array[sess->coreid];

    assert(ctx->active_cnt > 0);

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ht_remove(ctx->active_session_table, sess->parent);
#else
    TAILQ_REMOVE(&ctx->active_session_q, sess->parent, active_session_link);
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */
    ctx->active_cnt--;

    /* Destroy SSL session */
    clear_ssl_session(sess);
    clear_tcp_session(sess->parent);

    /* Insert back to free session queue */
    TAILQ_INSERT_TAIL(&ctx->free_session_q, sess->parent, free_session_link);
    ctx->free_cnt++;
}

inline int
abort_session(struct ssl_session* sess)
{
    /* Send RST packet */
    if (unlikely(0 > send_tcp_packet(sess->parent,
									 NULL,
									 0,
									 TCP_FLAG_RST | TCP_FLAG_ACK))) {
        fprintf(stderr, "sending reset packet error!\n");
        return -1;
    }

    remove_session(sess);

    return 0;
}

static inline int
send_synack_packet(uint16_t core_id, uint16_t port,
                   uint8_t *pktbuf, uint32_t cookie)
{
    struct ether_hdr *ethh = (struct ether_hdr *)pktbuf;
    struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
    struct tcp_hdr *tcph = (struct tcp_hdr *)(iph + 1);

    uint32_t seq_no = ntohl(tcph->sent_seq);

    uint8_t *option;
    uint16_t option_len;
    uint8_t *payload;
	int i;

    option = (uint8_t *)(tcph + 1);
    payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);

    option_len = payload - option;

    uint8_t *buf;

    buf = get_wptr(core_id, port, TOTAL_HEADER_LEN + option_len);
    if (unlikely(!buf)) {
        fprintf(stderr, "Allocating memory for syn-ack failed.\n");
        exit(EXIT_FAILURE);
    }
    
    struct ether_hdr *syn_ethh = (struct ether_hdr *)buf;
    struct ipv4_hdr *syn_iph = (struct ipv4_hdr *)(syn_ethh + 1);
    struct tcp_hdr *syn_tcph = (struct tcp_hdr *)(syn_iph + 1);

    uint8_t *syn_option;
#if VERBOSE_TCP
    char syn_dst_hw[20];
    char syn_src_hw[20];
#endif /* VERBOSE_TCP */

    /* update dst & src MAC address */
    for (i = 0; i < 6; i++) {
        syn_ethh->d_addr.addr_bytes[i] = ethh->s_addr.addr_bytes[i];
        syn_ethh->s_addr.addr_bytes[i] = ethh->d_addr.addr_bytes[i];
    }
	syn_ethh->ether_type = ethh->ether_type;

    /* update ip address */
    syn_iph->dst_addr = iph->src_addr;
    syn_iph->src_addr = iph->dst_addr;

    syn_iph->version_ihl = 69;
    syn_iph->type_of_service = 0;
    syn_iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + option_len);
    syn_iph->packet_id = htons(0);
    syn_iph->fragment_offset = htons(0x4000);
    syn_iph->time_to_live = 64;
    syn_iph->next_proto_id = IPPROTO_TCP;
    syn_iph->hdr_checksum = 0;
    syn_iph->hdr_checksum = rte_ipv4_cksum(syn_iph);

    /* update tcp port */
    syn_tcph->dst_port = tcph->src_port;
    syn_tcph->src_port = tcph->dst_port;

    /* update tcp flags */
    syn_tcph->tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

    syn_tcph->rx_win = tcph->rx_win;

    /* update seq and ack */
    syn_tcph->recv_ack = htonl(seq_no + 1);
    syn_tcph->sent_seq = htonl(cookie);

#if 1
    /* Attach option */
    syn_option = (uint8_t *)(syn_tcph + 1);

    memcpy(syn_option, option, option_len);
    syn_tcph->data_off = ((TCP_HEADER_LEN + option_len) >> 2) << 4;
#else
    syn_tcph->data_off = TCP_HEADER_LEN << 2;
#endif

    /* update checksum */
    syn_tcph->cksum = 0;
    syn_tcph->cksum = rte_ipv4_udptcp_cksum(syn_iph, syn_tcph);

#if VERBOSE_TCP
    memset(syn_dst_hw, 0, 10);
    memset(syn_src_hw, 0, 10);

    sprintf(syn_dst_hw, "%x:%x:%x:%x:%x:%x",
            syn_ethh->d_addr.addr_bytes[0],
            syn_ethh->d_addr.addr_bytes[1],
            syn_ethh->d_addr.addr_bytes[2],
            syn_ethh->d_addr.addr_bytes[3],
            syn_ethh->d_addr.addr_bytes[4],
            syn_ethh->d_addr.addr_bytes[5]);

    sprintf(syn_src_hw, "%x:%x:%x:%x:%x:%x",
            syn_ethh->s_addr.addr_bytes[0],
            syn_ethh->s_addr.addr_bytes[1],
            syn_ethh->s_addr.addr_bytes[2],
            syn_ethh->s_addr.addr_bytes[3],
            syn_ethh->s_addr.addr_bytes[4],
            syn_ethh->s_addr.addr_bytes[5]);

    fprintf(stderr, "\nSYN-ACK Sending Info---------------------------------\n"
			"core: %d\n"
			"dest hwaddr: %s\n"
			"source hwaddr: %s\n"
			"%x : %u -> %x : %u, id: %u\n"
			"len: %d, seq: %u, ack: %u, flag: %x\n\n",
			core_id, syn_dst_hw, syn_src_hw,
			ntohl(syn_iph->src_addr), ntohs(syn_tcph->src_port),
			ntohl(syn_iph->dst_addr), ntohs(syn_tcph->dst_port),
			ntohs(syn_iph->packet_id),
			TOTAL_HEADER_LEN + option_len,
			ntohl(syn_tcph->sent_seq),
			ntohl(syn_tcph->recv_ack),
			syn_tcph->tcp_flags);
#endif /* VERBOSE_TCP */

    return TOTAL_HEADER_LEN;
}

inline int
send_meta_packet(int coreid, int port, struct tcp_session *sess,
				 uint32_t next_recv_seq, uint32_t next_recv_ack,
				 uint8_t* payload, uint16_t payload_len) {

    uint8_t *buf;
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;
#if VERBOSE_TCP
    char dst_hw[20];
    char src_hw[20];
#endif /* VERBOSE_TCP */
    int send_cnt;


    buf = get_wptr(coreid, port, TOTAL_HEADER_LEN + payload_len);
    assert(buf != NULL);

    ethh = (struct ether_hdr *)buf;

    int i;
    for (i = 0; i < 6; i++) {
        ethh->d_addr.addr_bytes[i] = sess->server_mac[i];
        ethh->s_addr.addr_bytes[i] = sess->client_mac[i];
    }

    ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    iph = (struct ipv4_hdr *)(ethh + 1);
    iph->version_ihl = 69;
    iph->type_of_service = 0xff;
    iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + payload_len);
    iph->packet_id = 0;
    iph->fragment_offset = htons(0x4000);
    iph->time_to_live = 64;
    iph->next_proto_id = IPPROTO_TCP;
    iph->src_addr = sess->client_ip;
    iph->dst_addr = sess->server_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    tcph = (struct tcp_hdr *)(iph + 1);

    tcph->src_port = sess->client_port;
    tcph->dst_port = sess->server_port;
    tcph->tcp_flags = 0;

    tcph->recv_ack = next_recv_ack;
    tcph->sent_seq = next_recv_seq;

    tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;
    tcph->rx_win = sess->window;
    tcph->cksum = 0;

    if (payload_len > 0)
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN, payload, payload_len);

    /* Send Immediately */
    send_cnt = send_pkts(coreid, port);

    if (unlikely(!send_cnt)) {
        fprintf(stderr, "Why no packets are sent?");
        exit(EXIT_FAILURE);
    }
#if VERBOSE_TCP
    else {
        sprintf(dst_hw, "%x:%x:%x:%x:%x:%x",
                ethh->d_addr.addr_bytes[0],
                ethh->d_addr.addr_bytes[1],
                ethh->d_addr.addr_bytes[2],
                ethh->d_addr.addr_bytes[3],
                ethh->d_addr.addr_bytes[4],
                ethh->d_addr.addr_bytes[5]);

        sprintf(src_hw, "%x:%x:%x:%x:%x:%x",
                ethh->s_addr.addr_bytes[0],
                ethh->s_addr.addr_bytes[1],
                ethh->s_addr.addr_bytes[2],
                ethh->s_addr.addr_bytes[3],
                ethh->s_addr.addr_bytes[4],
                ethh->s_addr.addr_bytes[5]);

        fprintf(stderr, "\nMeta Sending Info---------------------------------\n"
				"core: %d\n"
				"dest hwaddr: %s\n"
				"source hwaddr: %s\n"
				"%x : %u -> %x : %u, "
				"id: %u\n"
				"next_recv_seq: %u, next_recv_ack: %u, flag: %x\n\n"
				"total_len: %d, payload_len: %d\n",
				coreid, dst_hw, src_hw,
				ntohl(iph->src_addr), ntohs(tcph->src_port),
				ntohl(iph->dst_addr), ntohs(tcph->dst_port),
				ntohs(iph->packet_id),
				ntohl(tcph->sent_seq),
				ntohl(tcph->recv_ack),
				tcph->tcp_flags,
				TOTAL_HEADER_LEN+payload_len, payload_len);
    }
#endif /* VERBOSE_TCP */

    return 0;
}

inline static int
send_raw_reset(int coreid, int portid,
               const uint8_t* hw_src, const uint8_t* hw_dst,
               uint32_t ip_src, uint32_t ip_dst,
               uint16_t tcp_src, uint16_t tcp_dst,
               uint32_t seq, uint32_t ack)
{
    int i;
    uint8_t *buf;
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;
#if VERBOSE_TCP
    char dst_hw[20];
    char src_hw[20];
#endif /* VERBOSE_TCP */

    buf = get_wptr(coreid, portid, TOTAL_HEADER_LEN);
    assert(buf != NULL);

    ethh = (struct ether_hdr *)buf;
    for (i = 0; i < 6; i++) {
        ethh->d_addr.addr_bytes[i] = hw_dst[i];
        ethh->s_addr.addr_bytes[i] = hw_src[i];
    }
    ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    iph = (struct ipv4_hdr *)(ethh + 1);
    iph->version_ihl = 69;
    iph->type_of_service = 0;
    iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
    iph->packet_id = htons(0);
    iph->fragment_offset = htons(0x4000);
    iph->time_to_live = 64;
    iph->next_proto_id = IPPROTO_TCP;
    iph->src_addr = ip_src;
    iph->dst_addr = ip_dst;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    tcph = (struct tcp_hdr *)(iph + 1);

    tcph->src_port = tcp_src;
    tcph->dst_port = tcp_dst;
    tcph->tcp_flags = TCP_FLAG_RST | TCP_FLAG_ACK;

    tcph->recv_ack = htonl(ack);
    tcph->sent_seq = htonl(seq);

    tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;
    tcph->rx_win = htons(8192);

    tcph->cksum = 0;
    tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);

#if VERBOSE_TCP
    sprintf(dst_hw, "%x:%x:%x:%x:%x:%x",
            ethh->d_addr.addr_bytes[0],
            ethh->d_addr.addr_bytes[1],
            ethh->d_addr.addr_bytes[2],
            ethh->d_addr.addr_bytes[3],
            ethh->d_addr.addr_bytes[4],
            ethh->d_addr.addr_bytes[5]);

    sprintf(src_hw, "%x:%x:%x:%x:%x:%x",
            ethh->s_addr.addr_bytes[0],
            ethh->s_addr.addr_bytes[1],
            ethh->s_addr.addr_bytes[2],
            ethh->s_addr.addr_bytes[3],
            ethh->s_addr.addr_bytes[4],
            ethh->s_addr.addr_bytes[5]);

    fprintf(stderr, "\nReset Sending Info---------------------------------\n"
			"core: %d\n"
			"dest hwaddr: %s\n"
			"source hwaddr: %s\n"
			"%x : %u -> %x : %u, "
			"id: %u\n"
			"seq: %u, ack: %u, flag: %x\n\n",
			coreid, dst_hw, src_hw,
			ntohl(iph->src_addr), ntohs(tcph->src_port),
			ntohl(iph->dst_addr), ntohs(tcph->dst_port),
			ntohs(iph->packet_id),
			ntohl(tcph->sent_seq),
			ntohl(tcph->recv_ack),
			tcph->tcp_flags);
#endif /* VERBOSE_TCP */

    return 0;
}


inline int
send_tcp_packet(struct tcp_session* sess,
                uint8_t* payload,
                uint16_t payload_len,
                uint8_t flags) {

    int i;
    uint8_t *buf;
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;
#if VERBOSE_TCP
    char send_dst_hw[20];
    char send_src_hw[20];
#endif /* VERBOSE_TCP */

	int left_to_send = payload_len;
	int already_to_send = 0;
	int byte_to_send;

	do {
		byte_to_send = MIN(left_to_send, MAX_PKT_SIZE - IP_HEADER_LEN - TCP_HEADER_LEN);

		buf = get_wptr(sess->coreid, sess->portid, TOTAL_HEADER_LEN + byte_to_send);
		assert(buf != NULL);

		ethh = (struct ether_hdr *)buf;
		for (i = 0; i < 6; i++) {
			ethh->d_addr.addr_bytes[i] = sess->client_mac[i];
			ethh->s_addr.addr_bytes[i] = sess->server_mac[i];
		}
		ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

		iph = (struct ipv4_hdr *)(ethh + 1);
		iph->version_ihl = 69;
		iph->type_of_service = 0;
		iph->total_length = htons(IP_HEADER_LEN + TCP_HEADER_LEN + byte_to_send);
		iph->packet_id = htons(sess->ip_id++);
		iph->fragment_offset = htons(0x4000);
		iph->time_to_live = 64;
		iph->next_proto_id = IPPROTO_TCP;
		iph->src_addr = sess->server_ip;
		iph->dst_addr = sess->client_ip;
		iph->hdr_checksum = 0;
		iph->hdr_checksum = rte_ipv4_cksum(iph);

		tcph = (struct tcp_hdr *)(iph + 1);

		tcph->src_port = sess->server_port;
		tcph->dst_port = sess->client_port;
		tcph->tcp_flags = flags;

		/* Now the tcp session should be always "TCP_SESSION_RECEIVED" */
		tcph->recv_ack = htonl(sess->last_recv_seq + sess->last_recv_len);
		tcph->sent_seq = htonl(sess->last_recv_ack + already_to_send);

		sess->last_sent_seq = ntohl(tcph->sent_seq);
		sess->last_sent_ack = ntohl(tcph->recv_ack);

		tcph->data_off = (TCP_HEADER_LEN >> 2) << 4;
		if (byte_to_send > 0)
			memcpy((uint8_t *)tcph + TCP_HEADER_LEN, payload + already_to_send, byte_to_send);

		sess->last_sent_len = byte_to_send;

		tcph->rx_win = htons(8192);

		tcph->cksum = 0;
		tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);

		sess->total_sent += byte_to_send;
		sess->state = TCP_SESSION_SENT;

		/* Intended Packet Drop */
#if 0
		if ((sess->ssl_session->handshake_state == SERVER_CIPHER_SPEC) && test_flag) {
			memset(buf, 0, TOTAL_HEADER_LEN + byte_to_send);
			test_flag = 0;
		}
#endif

#if VERBOSE_TCP
		memset(send_dst_hw, 0, 10);
		memset(send_src_hw, 0, 10);

		sprintf(send_dst_hw, "%x:%x:%x:%x:%x:%x",
				ethh->d_addr.addr_bytes[0],
				ethh->d_addr.addr_bytes[1],
				ethh->d_addr.addr_bytes[2],
				ethh->d_addr.addr_bytes[3],
				ethh->d_addr.addr_bytes[4],
				ethh->d_addr.addr_bytes[5]);

		sprintf(send_src_hw, "%x:%x:%x:%x:%x:%x",
				ethh->s_addr.addr_bytes[0],
				ethh->s_addr.addr_bytes[1],
				ethh->s_addr.addr_bytes[2],
				ethh->s_addr.addr_bytes[3],
				ethh->s_addr.addr_bytes[4],
				ethh->s_addr.addr_bytes[5]);

		fprintf(stderr, "\nPacket Sending Info---------------------------------\n"
				"core: %d, port: %u\n"
				"dest hwaddr: %s\n"
				"source hwaddr: %s\n"
				"%x : %u -> %x : %u, id: %u\n"
				"seq: %u, ack: %u, flag: %x\n"
				"total len: %u, payload_len: %u\n"
				"ssl handshake state: %u\n\n",
				sess->coreid, sess->portid, send_dst_hw, send_src_hw, 
				ntohl(iph->src_addr), ntohs(tcph->src_port),
				ntohl(iph->dst_addr), ntohs(tcph->dst_port),
				ntohs(iph->packet_id),
				ntohl(tcph->sent_seq),
				ntohl(tcph->recv_ack),
				tcph->tcp_flags,
				TOTAL_HEADER_LEN + byte_to_send, byte_to_send,
				sess->ssl_session->handshake_state);
#endif /* VERBOSE_TCP */

		left_to_send -= byte_to_send;
		already_to_send += byte_to_send;

	} while(left_to_send > 0);

    return 0;
}

static inline struct tcp_session *
search_tcp_session(struct thread_context *ctx,
                   uint32_t client_ip, uint16_t client_port,
                   uint32_t server_ip, uint16_t server_port)
{
    struct tcp_session *target, *ret;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ret = ht_search(ctx->active_session_table,
					client_ip, client_port, server_ip, server_port);
    UNUSED(target);
#else
    ret = NULL;
    TAILQ_FOREACH(target, &ctx->active_session_q, active_session_link) {
        assert(target->state != TCP_SESSION_IDLE);

        if ((target->client_ip == client_ip) &&
            (target->client_port == client_port) &&
            (target->server_ip == server_ip) &&
            (target->server_port == server_port))
            ret = target;
    }  
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */

    return ret;
}

static inline struct tcp_session *
pop_free_session(struct thread_context *ctx)
{
    struct tcp_session *target;

    target = TAILQ_FIRST(&ctx->free_session_q);
    if (unlikely(!target)) {
        fprintf(stderr, "Not enough session, and this must not happen!\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->free_session_q, target, free_session_link);
    ctx->free_cnt--;
    return target;
}

static inline struct tcp_session *
insert_tcp_session(struct thread_context *ctx, uint16_t portid,
                   const unsigned char* client_mac, 
                   uint32_t client_ip, uint16_t client_port,
                   const unsigned char* server_mac,
                   uint32_t server_ip, uint16_t server_port,
                   uint32_t seq_no, uint32_t ack_no, uint32_t cookie,
                   uint16_t window, int payload_len)
{
    struct tcp_session *target;
    int j;

    target = pop_free_session(ctx);
    assert(target);
    assert(target->state == TCP_SESSION_IDLE);

    for (j = 0; j < 6; j++) {
        target->client_mac[j] = client_mac[j];
        target->server_mac[j] = server_mac[j];
    }
    target->state = TCP_SESSION_RECEIVED;
    target->portid = portid;

    target->client_ip = client_ip;
    target->client_port = client_port;
    target->server_ip = server_ip;
    target->server_port = server_port;

    target->last_recv_ack = ack_no;
    target->last_recv_seq = seq_no;
    target->last_recv_len = payload_len;

    target->last_sent_ack = seq_no;
    target->last_sent_seq = cookie;
    target->last_sent_len = 0;

    target->window = window;
    target->ip_id = 1;

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
    ht_insert(ctx->active_session_table, target);
#else
    TAILQ_INSERT_TAIL(&ctx->active_session_q,
                      target, active_session_link);
#endif	/* USE_HASHTABLE_FOR_ACTIVE_SESSION */

    ctx->active_cnt++;

    return target;
}

static inline int
validate_sequence(struct tcp_session *sess, uint32_t seq_no)
{
    if (sess->last_sent_ack == seq_no)
        return 0;

    if (sess->last_recv_seq + sess->last_recv_len == seq_no)
        return 0;

#if VERBOSE_TCP
	fprintf(stderr, "Invalid Seqence! \n"
			"seq_no: %u\n"
			"should be: %u or %u\n"
			"last_sent_seq: %u, last_sent_ack: %u, last_sent_len: %u\n"
			"last_recv_seq: %u, last_recv_ack: %u, last_recv_len: %u\n",
			seq_no,
			sess->last_sent_ack, sess->last_recv_seq + sess->last_recv_len,
			sess->last_sent_seq, sess->last_sent_ack, sess->last_sent_len,
			sess->last_recv_seq, sess->last_recv_ack, sess->last_recv_len);
#endif /* VERBOSE_TCP */

    if (seq_no > sess->last_sent_ack &&
        seq_no > (sess->last_recv_seq + sess->last_recv_len))
        return -2;

    return -1;
}

static inline void
process_init_meta(uint8_t *meta_pkt)
{
    struct meta_hdr *metah;
    uint8_t *meta_host_key, *meta_host_iv;

    metah = (struct meta_hdr *)meta_pkt;
    host_key_size = metah->key_size;
    host_iv_size = metah->iv_size;

    meta_host_key = (uint8_t *)(metah + 1);
    meta_host_iv = (uint8_t *)(meta_host_key + host_key_size);

    memcpy(host_key, meta_host_key, host_key_size);
    memcpy(host_iv, meta_host_iv, host_iv_size);

#if VERBOSE_INIT
    fprintf(stderr, "host key (size: %u)\n", host_key_size);
    for (unsigned z = 0; z < host_key_size; z++)
        fprintf(stderr, "%02X%c", host_key[z],
				((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

    fprintf(stderr, "host iv (size: %u)\n", host_iv_size);
    for (unsigned z = 0; z < host_iv_size; z++)
        fprintf(stderr, "%02X%c", host_iv[z],
				((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

#endif /* VERBOSE_INIT */
}

static inline void
send_init_meta(uint16_t core_id, uint16_t port)
{
    uint8_t *buf;
    struct meta_hdr *metah;
    uint8_t *meta_nic_key, *meta_nic_iv;
    int payload_len;

    payload_len = nic_key_size + nic_iv_size;

    buf = get_wptr(core_id, port, sizeof(struct meta_hdr) + payload_len);
    if (!buf) {
        fprintf(stderr, "Packet Allocation Failed!\n");
        exit(0);
    }

    metah = (struct meta_hdr *)buf;
    metah->key_size = nic_key_size;
    metah->iv_size = nic_iv_size;
    metah->h_proto = rte_cpu_to_be_16(ETHER_TYPE_META);

    meta_nic_key = (uint8_t *)(metah + 1);
    meta_nic_iv = (uint8_t *)(meta_nic_key + nic_key_size);

    memcpy(meta_nic_key, nic_key, nic_key_size);
    memcpy(meta_nic_iv, nic_iv, nic_iv_size);

#if VERBOSE_INIT
    fprintf(stderr, "nic key (size: %u)\n", nic_key_size);
    for (unsigned z = 0; z < nic_key_size; z++)
        fprintf(stderr, "%02X%c", nic_key[z],
				((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

    fprintf(stderr, "nic iv (size: %u)\n", nic_iv_size);
    for (unsigned z = 0; z < nic_iv_size; z++)
        fprintf(stderr, "%02X%c", nic_iv[z],
				((z + 1) % 16 ? ' ' : '\n'));
    fprintf(stderr, "\n");

#endif /* VERBOSE_INIT */

}

static inline int
validate_packet_type(uint16_t port, uint8_t *pktbuf)
{
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;

    ethh = (struct ether_hdr *)pktbuf;

    if (ethh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_META))
        return TRUE;

    if (ethh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
        iph = (struct ipv4_hdr *)(ethh + 1);
        if (iph->next_proto_id == IPPROTO_TCP) {
            /* The packet is a TCP packet */
            tcph = (struct tcp_hdr *)(iph + 1);
            if (port % 2 == 0) {
                if (tcph->dst_port != htons(SSL_PORT)) {
#if VERBOSE_TCP
                    fprintf(stderr, "Only HTTPS is supported\n");
#endif /* VERBOSE_TCP */
                    return FALSE;
                }

                if ((tcph->tcp_flags & TCP_FLAG_SYN) &&
                    (tcph->tcp_flags & TCP_FLAG_ACK)) {
#if VERBOSE_TCP
					/* We do not currently support client side */
                    fprintf(stderr, "SYN ACK is not supported\n");
#endif /* VERBOSE_TCP */
                    return FALSE;
                }
            }

            return TRUE;
        }
        else {
#if VERBOSE_TCP
            fprintf(stderr, "\nOnly TCP packet supported\n");
#endif /* VERBOSE_TCP */
            return FALSE;
        }
    }

    return FALSE;
}

#if ONLOAD
static inline int
process_host_packet(uint16_t core_id, uint16_t port, struct thread_context *ctx,
                    uint8_t *pktbuf, int len)
{
    uint8_t *buf;
    struct tcp_session *target;
    struct ether_hdr *ethh = (struct ether_hdr *)pktbuf;
    struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
    struct tcp_hdr *tcph = (struct tcp_hdr *)(iph + 1);

    /* Check if the packet is from host */
    if(!(port % 2))
        return 0;

    /* After host successfully terminate the connection,
       it sends special packet with all TCP flag but URG */
    if (iph->type_of_service == 0xff ||
		tcph->tcp_flags & TCP_FLAG_RST) {
        /* Remove the session if exist */
        target = search_tcp_session(ctx,
                                    iph->dst_addr, tcph->dst_port, 
                                    iph->src_addr, tcph->src_port);
        if (target) {
            remove_session(target->ssl_session);
#if VERBOSE_TCP
			fprintf(stderr, "len = %d\n", len);
			fprintf(stderr, "TCP Session (with client %x.%d) is removed. flag = %x\n",
					ntohl(iph->dst_addr), ntohs(tcph->dst_port), tcph->tcp_flags);
#endif /* VERBOSE_TCP */
        }

		/* this special packet should be consumed, not forwarded to network */
		if (iph->type_of_service == 0xff) {
			return 0;
		}
    }

    /* Forward to corresponding network interface */
    buf = get_wptr(core_id, port - 1, len);
    if (!buf)
        return 0;

    memcpy(buf, pktbuf, len);

#if VERBOSE_TCP
    fprintf(stderr, "Packet with length %d is forwarded from host to network.\n", len);
#endif /* VERBOSE_TCP */

    return len;
}
#endif /* ONLOAD */

static inline int
process_fin_packet(uint16_t core_id, uint16_t port,
                   struct thread_context *ctx, uint8_t *pktbuf, int len)
{
    struct tcp_session *target;
    int ret = FALSE;

    struct ether_hdr *ethh = (struct ether_hdr *)pktbuf;
    struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
    struct tcp_hdr *tcph = (struct tcp_hdr *)(iph + 1);

    uint32_t seq_no = ntohl(tcph->sent_seq);
    uint32_t ack_no = ntohl(tcph->recv_ack);

    uint16_t payload_len = ntohs(iph->total_length) -
		IP_HEADER_LEN -
		((tcph->data_off & 0xf0) >> 2);

    uint8_t *buf;


    target = search_tcp_session(ctx,
                                iph->src_addr, tcph->src_port, 
                                iph->dst_addr, tcph->dst_port);

    if (target) {
        if (target->onload == TRUE) {
			/* forward fin to the host */
			buf = get_wptr(core_id, port + 1, len);
			assert(buf != NULL);
			memcpy(buf, pktbuf, len);
		} else {	
			/* Remove session info and send reset to network side */
            ret = TRUE;
			remove_session(target->ssl_session);
			send_raw_reset(core_id, port,
						   ethh->d_addr.addr_bytes, ethh->s_addr.addr_bytes,
						   iph->dst_addr, iph->src_addr,
						   tcph->dst_port, tcph->src_port,
						   ack_no, seq_no + payload_len);
		}
    } else {
        /* just send reset to network side */
        send_raw_reset(core_id, port,
					   ethh->d_addr.addr_bytes, ethh->s_addr.addr_bytes,
					   iph->dst_addr, iph->src_addr,
					   tcph->dst_port, tcph->src_port,
					   ack_no, seq_no + payload_len);

    }

    return ret;
}

static inline int
process_rst_packet(uint16_t core_id, uint16_t port,
                   struct thread_context *ctx, uint8_t *pktbuf, int len)
{
    struct tcp_session *target;
    int ret = FALSE;

    struct ether_hdr *ethh = (struct ether_hdr *)pktbuf;
    struct ipv4_hdr *iph = (struct ipv4_hdr *)(ethh + 1);
    struct tcp_hdr *tcph = (struct tcp_hdr *)(iph + 1);

    uint32_t seq_no = ntohl(tcph->sent_seq);
    uint32_t ack_no = ntohl(tcph->recv_ack);
    uint8_t *buf;

    target = search_tcp_session(ctx,
                                iph->src_addr, tcph->src_port, 
                                iph->dst_addr, tcph->dst_port);

	if (target) {
        if (target->onload == TRUE) {
			/* forward fin to the host */
			buf = get_wptr(core_id, port + 1, len);
			assert(buf != NULL);
			memcpy(buf, pktbuf, len);
		} else {	
			/* Remove session info and send reset to network side */
			remove_session(target->ssl_session);
			send_raw_reset(core_id, port + 1,
						   ethh->s_addr.addr_bytes, ethh->d_addr.addr_bytes,
						   iph->src_addr, iph->dst_addr,
						   tcph->src_port, tcph->dst_port,
						   seq_no, ack_no);
			ret = TRUE;
		}
    } else {
        /* just send reset to network side */
		send_raw_reset(core_id, port + 1,
					   ethh->s_addr.addr_bytes, ethh->d_addr.addr_bytes,
					   iph->src_addr, iph->dst_addr,
					   tcph->src_port, tcph->dst_port,
					   seq_no, ack_no);
    }

    return ret;
}

static inline void
process_packet(uint16_t core_id, uint16_t port, uint8_t *pktbuf, int len)
{
    uint8_t* buf;
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;
    uint16_t ip_len;
    struct tcp_hdr *tcph;
    uint8_t *option;
    uint16_t option_len;
    uint8_t *payload;
    uint16_t payload_len;
    uint32_t seq_no, ack_no;
    struct thread_context *ctx;
    int ret;
    struct tcp_session *result;

#if VERBOSE_TCP
    char recv_dst_hw[20];
    char recv_src_hw[20];
#endif /* VERBOSE_TCP */

    uint32_t cookie;

    ctx = ctx_array[core_id];

    /* Filter invalid packets */
    if (!validate_packet_type(port, pktbuf))
        return;

    ethh = (struct ether_hdr *)pktbuf;

    /* Process initialization metadata packet.
     * This packet includes host key and host iv. */
    if (ethh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_META)) {
        process_init_meta(pktbuf);
        send_init_meta(core_id, port);
        return;
    }

    /* Process packets from the host */
#if ONLOAD
    if (port_type[port]) {
        /* Packets from host side */
        ret = process_host_packet(core_id, port, ctx, pktbuf, len);
#if VERBOSE_TCP
        fprintf(stderr, "Process %d length host packet.\n", ret);
#endif /* VERBOSE_TCP */
        return;
    }
#else /* ONLOAD */
    UNUSED(len);
#endif /* !ONLOAD */

    iph = (struct ipv4_hdr *)(ethh + 1);

    ip_len = ntohs(iph->total_length);

    tcph = (struct tcp_hdr *)(iph + 1);
    seq_no = ntohl(tcph->sent_seq);
    ack_no = ntohl(tcph->recv_ack);

    option = (uint8_t *)(tcph + 1);
    payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);

    option_len = payload - option;
    payload_len = ip_len - (payload - (u_char *)iph);

    UNUSED(option_len);

#if VERBOSE_TCP
    memset(recv_dst_hw, 0, 10);
    memset(recv_src_hw, 0, 10);

    sprintf(recv_dst_hw, "%x:%x:%x:%x:%x:%x",
            ethh->d_addr.addr_bytes[0],
            ethh->d_addr.addr_bytes[1],
            ethh->d_addr.addr_bytes[2],
            ethh->d_addr.addr_bytes[3],
            ethh->d_addr.addr_bytes[4],
            ethh->d_addr.addr_bytes[5]);

    sprintf(recv_src_hw, "%x:%x:%x:%x:%x:%x",
            ethh->s_addr.addr_bytes[0],
            ethh->s_addr.addr_bytes[1],
            ethh->s_addr.addr_bytes[2],
            ethh->s_addr.addr_bytes[3],
            ethh->s_addr.addr_bytes[4],
            ethh->s_addr.addr_bytes[5]);

    fprintf(stderr, "\nPacket Receive Info---------------------------------\n"
			"core: %d\n"
			"dest hwaddr: %s\n"
			"source hwaddr: %s\n"
			"%x : %u -> %x : %u\n"
			"seq: %u, ack: %u, flag: %x\n"
			"len: %u, option_len: %u, payload_len: %u\n\n",
			core_id, recv_dst_hw, recv_src_hw,
			ntohl(iph->src_addr), ntohs(tcph->src_port),
			ntohl(iph->dst_addr), ntohs(tcph->dst_port),
			seq_no, ack_no, tcph->tcp_flags,
			len, option_len, payload_len);
#endif /* VERBOSE_TCP */

    if (tcph->tcp_flags & (TCP_FLAG_FIN)) {
        /* Handle TCP FIN packets from the network */
        if (process_fin_packet(core_id, port, ctx, pktbuf, len)) {
#if VERBOSE_TCP
            fprintf(stderr, "A session is removed by FIN packet.\n");
#endif /* VERBOSE_TCP */
        }

        return;
    }
    if (tcph->tcp_flags & TCP_FLAG_RST) {
        /* Handle TCP RST packets from the network */
        if (process_rst_packet(core_id, port, ctx, pktbuf, len)) {
#if VERBOSE_TCP
            fprintf(stderr, "A session is removed by RST packet.\n");
#endif /* VERBOSE_TCP */
        }

        return;
    }

    /* Make cookie with 4 tuples */
    cookie = get_cookie(iph->src_addr, tcph->src_port,
                        iph->dst_addr, tcph->dst_port);

    if (tcph->tcp_flags & TCP_FLAG_SYN) {
        /* Handle TCP SYN Packet */
        send_synack_packet(core_id, port, pktbuf, cookie);
        return;
    }
    else {
        /* Handle Handshake ACK or Established Packet */
        if (ack_no == cookie + 1 && payload_len == 0) {
            /* Should be handshake ACK */
            if (search_tcp_session(ctx,
								   iph->src_addr, tcph->src_port,
								   iph->dst_addr, tcph->dst_port)) {
#if VERBOSE_TCP
                fprintf(stderr, "Handshake ACK Retransmission!\n");
#endif
                return;
            }

            /* Handle Handshake ACK */
            result = insert_tcp_session(ctx, port,
										ethh->s_addr.addr_bytes,
										iph->src_addr, tcph->src_port,
										ethh->d_addr.addr_bytes,
										iph->dst_addr, tcph->dst_port,
										seq_no, ack_no, cookie,
										ntohs(tcph->rx_win), payload_len);
            if (unlikely(!result)) {
                fprintf(stderr, "insert_tcp_session failed.\n");
                exit(EXIT_FAILURE);
            }

#if ONLOAD
            /* Check overload */
            if (is_overloaded(ctx, ethh)) {
#if VERBOSE_TCP
                fprintf(stderr, "Overloaded!\n");
#endif /* VERBOSE_TCP */
                result->onload = TRUE;
                send_meta_packet(core_id, port + 1, result,
                                 htonl(seq_no), htonl(ack_no),
                                 NULL, 0);
                ctx->stat.only_tcp++;

                return;
            }
#endif /* ONLOAD */

            /* Record the time of last response */
	    /* ToDo: replace it to clock_gettime */
            gettimeofday(&result->last_interaction, NULL);

            return;
        }

        /* Handle Established Packet */
        result = search_tcp_session(ctx,
									iph->src_addr, tcph->src_port, 
									iph->dst_addr, tcph->dst_port);

        if (result == NULL) {
            /* Weird Packet */
#if VERBOSE_TCP
            fprintf(stderr, "Weird Packet!\n"
					"Maybe the packet of aborted session.\n");
#endif /* VERBOSE_TCP */
            return;
        }
        else {
            if ((seq_no < result->last_recv_seq) ||
                (ack_no < result->last_recv_ack) ||
				(seq_no == result->last_recv_seq && 
                 ack_no == result->last_recv_ack &&
                 payload_len == result->last_recv_len)) {
#if VERBOSE_TCP
                fprintf(stderr, "Retransmission!, seq_no: %u, last: %u, current_ssl_state: %d\n",
						seq_no, result->last_recv_seq, result->ssl_session->handshake_state);
#endif /* VERBOSE_TCP */

#if DEBUG_FLAG
				/* debug */
                fprintf(stderr, "Retransmission!, client_port = %u, seq_no: %u, last: %u,\n"
						"ack_no: %u, last: %u\n"
						"current_ssl_state: %d\n",
						htons(result->client_port),
						seq_no, result->last_recv_seq, ack_no, result->last_recv_ack,
						result->ssl_session->handshake_state);
#endif	/* DEBUG_FLAG */

#if 0
                /* Retransmission with payload */
                if (payload_len > 0) {
                    int hs = result->ssl_session->handshake_state;
                    ret = 0;

                    if ((hs > CLIENT_HELLO) && (hs < CLIENT_KEY_EXCHANGE)) {
#if VERBOSE_TCP
                        fprintf(stderr, "Retransmit certificate\n");
#endif /* VERBOSE_TCP */
                        ret += send_server_hello(result->ssl_session);
                        ret += send_certificate(result->ssl_session);
                        ret += send_server_hello_done(result->ssl_session);
                        ret += 3 * TOTAL_HEADER_LEN;
                    }
                    else if (hs > CLIENT_FINISHED) {
#if VERBOSE_TCP
                        fprintf(stderr, "Retransmit server finish\n");
#endif /* VERBOSE_TCP */
                        security_params_t *pending_sp = &result->ssl_session->pending_sp;
                        security_params_t *write_sp = &result->ssl_session->write_sp;

                        memset(write_sp, 0, sizeof(*write_sp));
                        ret += send_change_cipher_spec(result->ssl_session);

                        memcpy(write_sp, pending_sp, sizeof(*pending_sp));
                        result->ssl_session->send_seq_num_ = 0;
                        result->ssl_session->server_write_IV_seq_num = 0;

                        ret += send_server_finish(result->ssl_session,
                                                  result->ssl_session->server_finish_digest);
                        ret += 2 * TOTAL_HEADER_LEN;
                    }
                    else {
						fprintf(stderr, "Wrong State!! current state is %d\n", hs);
						abort_session(result->ssl_session);
                        exit(EXIT_FAILURE);
                    }
                    
                    result->ctx->stat.rtx_pkts[result->portid] += 1;
                    result->ctx->stat.rtx_bytes[result->portid] += ret;

                }
/* #else  /\* 0 *\/ */
/* 		abort_session(result->ssl_session); */
#endif /* !0 */
                return;
            }

#if ONLOAD
            /* Forward onloaded packet */
            if (result->onload) {
                /* The connection is already onloaded to host */
                assert(!(port % 2));
                buf = get_wptr(core_id, port + 1, len);
                assert(buf != NULL);

#if VERBOSE_TCP
                fprintf(stderr, "Packet with length %d forwarded from network to host.\n", len);
#endif /* VERBOSE_TCP */

                memcpy(buf, pktbuf, len);

                return;
            }
#else /* ONLOAD */
            UNUSED(buf);
#endif /* !ONLOAD */

            ret = validate_sequence(result, seq_no);
            if (ret < 0) {
				/* Wrong Sequence */
#if VERBOSE_TCP
				fprintf(stderr, "Wrong Sequence!\n");
#endif /* VERBOSE_TCP */
				if (ret == -2) {
#if VERBOSE_TCP
					fprintf(stderr, "Over Sequence Case\n");
#endif /* VERBOSE_TCP */
					/* Over Seq Case: Retransmission */
					ret = send_tcp_packet(result,
										  NULL,
										  0,
										  TCP_FLAG_ACK);
					if (unlikely(ret < 0)) {
						fprintf(stderr, "Sending ACK Failed.\n");
						exit(EXIT_FAILURE);
					}

				}

				if (ret == -1) {
					/* Under Seq Case */
					ret = send_tcp_packet(result,
										  NULL,
										  0,
										  TCP_FLAG_ACK);
					if (unlikely(ret < 0)) {
						fprintf(stderr, "Sending ACK Failed.\n");
						exit(EXIT_FAILURE);
					}
				}

				return;
            }

            /* Handle Established Packet */
            result->last_recv_ack = ack_no;
            result->last_recv_seq = seq_no;
            result->last_recv_len = payload_len;

            result->state = TCP_SESSION_RECEIVED;


            /* Record the time of last response (only for SSL handshake case) */
            gettimeofday(&result->last_interaction, NULL);

            if (payload_len > 0) {
                /* Got a payload */
                if (0 > process_ssl_packet(result,
                                           payload,
                                           payload_len)) {
                    /* We need next packet */
                    ret = send_tcp_packet(result,
                                          NULL,
                                          0,
                                          TCP_FLAG_ACK);
                    if (unlikely(ret < 0)) {
                        fprintf(stderr, "Sending ACK Failed.\n");
                        exit(EXIT_FAILURE);
                    }
                }


            }
            else {
#if VERBOSE_TCP
                fprintf(stderr, "ACK packet!\n");
#endif /* VERBOSE_TCP */
            }
        }
    }
}

static inline unsigned
check_ready(void)
{
    unsigned ready = 0;
    unsigned i;

    for (i = 0; i < rte_lcore_count(); i++)
        ready += ctx_array[i]->ready;

    if (ready > rte_lcore_count())
        assert(0);
    else if (ready == rte_lcore_count())
        return true;

    return false;
}

static inline int
process_session_health_check(struct tcp_session *sess)
{
    struct timeval cur_tv;
    int ret;
    long diff;

#if ONLOAD
    if (sess->onload) {
        return 0;
    }
#endif /* ONLOAD */

	/* ToDo: implement timeout */

    gettimeofday(&cur_tv,NULL);
    diff = ((cur_tv.tv_sec - sess->last_interaction.tv_sec) * 1000000) + 
		cur_tv.tv_usec - sess->last_interaction.tv_usec;

    if (unlikely(diff > HEALTH_CHECK * 1000)) {
        /* Probe if it is alive */
        ret = send_tcp_packet(sess,
                              NULL,
                              0,
                              TCP_FLAG_ACK);
        if (unlikely(ret < 0)) {
            fprintf(stderr, "Sending RST Failed.\n");
            exit(EXIT_FAILURE);
        }

        /* Update Last Interaction */
        sess->last_interaction.tv_sec = cur_tv.tv_sec;
        sess->last_interaction.tv_usec = cur_tv.tv_usec;

        return -1;
    }

    return 0;
}
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
int
ssloff_main_loop(__attribute__((unused)) void *arg)
{
    uint16_t port, core_id;
    struct thread_context *ctx;
    int recv_cnt;
    int i;
    int num_core;
    struct timeval cur_tv, prev_tv;
    uint64_t complete_last[MAX_CPUS];
    uint64_t only_tcp_last[MAX_CPUS];
    uint64_t rx_bytes_last[MAX_DPDK_PORT][MAX_CPUS];
    uint64_t rx_pkts_last[MAX_DPDK_PORT][MAX_CPUS];
    uint64_t tx_bytes_last[MAX_DPDK_PORT][MAX_CPUS];
    uint64_t tx_pkts_last[MAX_DPDK_PORT][MAX_CPUS];
    uint64_t rtx_bytes_last[MAX_DPDK_PORT][MAX_CPUS];
    uint64_t rtx_pkts_last[MAX_DPDK_PORT][MAX_CPUS];

    uint64_t global_complete_last;
    uint64_t global_only_tcp_last;
    uint64_t global_rx_bytes_last[MAX_DPDK_PORT];
    uint64_t global_rx_pkts_last[MAX_DPDK_PORT];
    uint64_t global_tx_bytes_last[MAX_DPDK_PORT];
    uint64_t global_tx_pkts_last[MAX_DPDK_PORT];
    uint64_t global_rtx_bytes_last[MAX_DPDK_PORT];
    uint64_t global_rtx_pkts_last[MAX_DPDK_PORT];
    int send_cnt;
    int processed_cnt;
    struct tcp_session* target;

    core_id = rte_lcore_id();
    thread_local_init(core_id);
    ctx = ctx_array[core_id];
    ctx->ready = 1;
    if (check_ready()) {
        fprintf(stderr, "CPU[%d] Initialization finished\n"
          		"Now start forwarding.\n\n", rte_lcore_id());
    }
    else {
        fprintf(stderr, "CPU[%d] Initialization finished\n"
	        	"Wait for other cores.\n\n", rte_lcore_id());
        while(!check_ready()) {}
        usleep(100);
    }
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
				   "polling thread.\n\tPerformance will "
				   "not be optimal.\n", port);

    printf("Core %u forwarding packets. [Ctrl+C to quit]\n\n",
		   rte_lcore_id());

    num_core = rte_lcore_count();
    gettimeofday(&cur_tv, NULL);
    prev_tv = cur_tv;
    for (i = 0; i < MAX_CPUS; i++) {
        complete_last[i] = 0;
        only_tcp_last[i] = 0;
        RTE_ETH_FOREACH_DEV (port) {
            rx_bytes_last[port][i] = 0;
            rx_pkts_last[port][i] = 0;
            tx_bytes_last[port][i] = 0;
            tx_pkts_last[port][i] = 0;
            rtx_bytes_last[port][i] = 0;
            rtx_pkts_last[port][i] = 0;
        }
    }
    global_complete_last = 0;
    global_only_tcp_last = 0;
    RTE_ETH_FOREACH_DEV (port) {
        global_rx_bytes_last[port] = 0;
        global_rx_pkts_last[port] = 0;
        global_tx_bytes_last[port] = 0;
        global_tx_pkts_last[port] = 0;
        global_rtx_bytes_last[port] = 0;
        global_rtx_pkts_last[port] = 0;
    }

#if !VERBOSE_STAT
    UNUSED(complete_last);
    UNUSED(only_tcp_last);
    UNUSED(rx_bytes_last);
    UNUSED(rx_pkts_last);
    UNUSED(tx_bytes_last);
    UNUSED(tx_pkts_last);
    UNUSED(rtx_bytes_last);
    UNUSED(rtx_pkts_last);
    UNUSED(global_complete_last);
    UNUSED(global_only_tcp_last);
    UNUSED(global_rx_bytes_last);
    UNUSED(global_rx_pkts_last);
    UNUSED(global_tx_bytes_last);
    UNUSED(global_tx_pkts_last);
    UNUSED(global_rtx_bytes_last);
    UNUSED(global_rtx_pkts_last);
#endif /* !VERBOSE_STAT */

    /* Run until the application is quit or killed. */
    for (;;) {
		/* Aggregate Global Stat in Core 0*/
		if (core_id == 0) {
			/* Initialize All Global Stat to 0 */
			global_stat.completes = 0;
			global_stat.only_tcp = 0;

			RTE_ETH_FOREACH_DEV(port) {
				global_stat.rx_bytes[port] = 0;
				global_stat.rx_pkts[port] = 0;

				global_stat.tx_bytes[port] = 0;
				global_stat.tx_pkts[port] = 0;

				global_stat.rtx_bytes[port] = 0;
				global_stat.rtx_pkts[port] = 0;
			}

			for (i = 0; i < num_core; i++) {
				global_stat.completes += ctx_array[i]->stat.completes;
				global_stat.only_tcp += ctx_array[i]->stat.only_tcp;

				RTE_ETH_FOREACH_DEV(port) {
					global_stat.rx_bytes[port] += ctx_array[i]->stat.rx_bytes[port];
					global_stat.rx_pkts[port] += ctx_array[i]->stat.rx_pkts[port];

					global_stat.tx_bytes[port] += ctx_array[i]->stat.tx_bytes[port];
					global_stat.tx_pkts[port] += ctx_array[i]->stat.tx_pkts[port];

					global_stat.rtx_bytes[port] += ctx_array[i]->stat.rtx_bytes[port];
					global_stat.rtx_pkts[port] += ctx_array[i]->stat.rtx_pkts[port];
				}
			}

			/* Now Print the Stat */
			gettimeofday(&cur_tv, NULL);
			if (unlikely(cur_tv.tv_sec > prev_tv.tv_sec)) {

				/* Cookie Timevalue Update */

				if (t_minor == 63) {
					if (t_major == 31) {
						t_major = 0;
						t_minor = 0;
					}
					else {
						t_major++;
						t_minor = 0;
					}
				}
				else
					t_minor++;

				/* Per-Core Stat */
				for (i = 0; i < num_core; i++) {
					ctx_array[i]->stat.throughput = ctx_array[i]->stat.completes - complete_last[i];
					ctx_array[i]->stat.only_tcp_throughput = ctx_array[i]->stat.only_tcp - only_tcp_last[i];
#if VERBOSE_STAT
					fprintf(stderr,
							"[CPU %2d] %5lu conns/s, %5lu only tcp handshake/s"
							"%4d active sessions, %4d free sessions, "
							"%4d free records, %4d free ops\n",
							i, ctx_array[i]->stat.throughput, ctx_array[i]->stat.only_tcp_throughput,
							ctx_array[i]->active_cnt, ctx_array[i]->free_cnt,
							ctx_array[i]->free_record_cnt,
							ctx_array[i]->free_op_cnt);
#endif /* VERBOSE_STAT */
					complete_last[i] = ctx_array[i]->stat.completes;
					only_tcp_last[i] = ctx_array[i]->stat.only_tcp;

					RTE_ETH_FOREACH_DEV(port) {
#if VERBOSE_STAT
						fprintf(stderr,
								"[CPU %2d] Port %d "
								"RX: %7lu(pps), %6.2f(Mbps), "
								"TX: %7lu(pps), %6.2f(Mbps), "
								"RTX: %7lu(pps), %6.2f(Mbps)\n",
								i, port,
								ctx_array[i]->stat.rx_pkts[port] - rx_pkts_last[port][i],
								B_TO_Mb((float)(ctx_array[i]->stat.rx_bytes[port] - rx_bytes_last[port][i])),
								ctx_array[i]->stat.tx_pkts[port] - tx_pkts_last[port][i],
								B_TO_Mb((float)(ctx_array[i]->stat.tx_bytes[port] - tx_bytes_last[port][i])),
								ctx_array[i]->stat.rtx_pkts[port] - rtx_pkts_last[port][i],
								B_TO_Mb((float)(ctx_array[i]->stat.rtx_bytes[port] - rtx_bytes_last[port][i])));
#endif /* VERBOSE_STAT */
						rx_pkts_last[port][i] = ctx_array[i]->stat.rx_pkts[port];
						rx_bytes_last[port][i] = ctx_array[i]->stat.rx_bytes[port];
						tx_pkts_last[port][i] = ctx_array[i]->stat.tx_pkts[port];
						tx_bytes_last[port][i] = ctx_array[i]->stat.tx_bytes[port];
						rtx_pkts_last[port][i] = ctx_array[i]->stat.rtx_pkts[port];
						rtx_bytes_last[port][i] = ctx_array[i]->stat.rtx_bytes[port];
					}
				}

				/* Global Stat */
				global_stat.throughput = global_stat.completes - global_complete_last;
				global_stat.only_tcp_throughput = global_stat.only_tcp - global_only_tcp_last;
#if VERBOSE_STAT
				fprintf(stderr,
						"\n[TOTAL] %lu conns/s, %lu only tcp handshake/s\n",
						global_stat.throughput, global_stat.only_tcp_throughput);
#endif /* VERBOSE_STAT */
				global_complete_last = global_stat.completes;
				global_only_tcp_last = global_stat.only_tcp;

				RTE_ETH_FOREACH_DEV(port) {
#if VERBOSE_STAT
					fprintf(stderr,
							"[TOTAL] Port %d "
							"RX: %7lu (pps), %6.2f(Mbps), "
							"TX: %7lu(pps), %6.2f(Mbps), "
							"RTX: %7lu(pps), %6.2f(Mbps)\n",
							port,
							global_stat.rx_pkts[port] - global_rx_pkts_last[port],
							B_TO_Mb((float)(global_stat.rx_bytes[port] - global_rx_bytes_last[port])),
							global_stat.tx_pkts[port] - global_tx_pkts_last[port],
							B_TO_Mb((float)(global_stat.tx_bytes[port] - global_tx_bytes_last[port])),
							global_stat.rtx_pkts[port] - global_rtx_pkts_last[port],
							B_TO_Mb((float)(global_stat.rtx_bytes[port] - global_rtx_bytes_last[port])));
#endif /* VERBOSE_STAT */
					global_rx_pkts_last[port] = global_stat.rx_pkts[port];
					global_rx_bytes_last[port] = global_stat.rx_bytes[port];
					global_tx_pkts_last[port] = global_stat.tx_pkts[port];
					global_tx_bytes_last[port] = global_stat.tx_bytes[port];
					global_rtx_pkts_last[port] = global_stat.rtx_pkts[port];
					global_rtx_bytes_last[port] = global_stat.rtx_bytes[port];
				}
				fprintf(stderr, "\n");

				prev_tv = cur_tv;
			}
		}
	    
		RTE_ETH_FOREACH_DEV(port) {
			static uint16_t len;
			static uint8_t *pktbuf;

			/* Receive Packets */
			recv_cnt = recv_pkts(core_id, port);
#if VERBOSE_TCP
			if (recv_cnt > 0)
				fprintf(stderr, "recv_pkts: %d\n", recv_cnt);
#endif /* VERBOSE_TCP */

			/* Process Received Packets */
			for (i = 0; i < recv_cnt; i++) {
				pktbuf = get_rptr(core_id, port, i, &len);
				if (likely(pktbuf != NULL)) {
#if 0
					fprintf(stderr, "\nReceived Packet from port %d\n", port);
					for (unsigned z = 0; z < len; z++)
						fprintf(stderr, "%02X%c", pktbuf[z],
								((z + 1) % 16 ? ' ' : '\n'));
					fprintf(stderr, "\n");
#endif /* VERBOSE_TCP */
					process_packet(core_id, port, pktbuf, len);
				}
			}

			/* Process Cyptos Done by PKA Engine */
			processed_cnt = process_crypto(ctx);
#if VERBOSE_TCP
			if (processed_cnt)
				fprintf(stderr, "\nprocessed: %d\n", processed_cnt);
#else /* VERBOSE_TCP */
			UNUSED(processed_cnt);
#endif /* !VERBOSE_TCP */

#if USE_HASHTABLE_FOR_ACTIVE_SESSION
			for (i = 0; i < NUM_BINS; i++) {
				struct hashtable *ht = ctx->active_session_table;
				TAILQ_FOREACH(target, &ht->ht_table[i], active_session_link) {
					process_session_read(target->ssl_session);
					process_session_health_check(target);
				}
			}
#else /* USE_HASHTABLE_FOR_ACTIVE_SESSION */
			/* Process SSL Steps of Each Session */
			TAILQ_FOREACH(target, &ctx->active_session_q, active_session_link) {
				process_session_read(target->ssl_session);
				process_session_health_check(target);
			}
#endif /* !USE_HASHTABLE_FOR_ACTIVE_SESSION */

			/* Send Packets */
			send_cnt = send_pkts(core_id, port);
#if VERBOSE_TCP
			if (send_cnt > 0)
				fprintf(stderr, "send_pkts: %d\n", send_cnt);
#else /* VERBOSE_TCP */
			UNUSED(send_cnt);
#endif /* !VERBOSE_TCP */
		}
    }

    thread_local_destroy(rte_lcore_id());
    return 0;
}

