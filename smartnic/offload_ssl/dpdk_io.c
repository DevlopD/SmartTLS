#include "ssloff.h"

inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
    unsigned i;

    for (i = 0; i < len; i++) {
        rte_pktmbuf_free(mtable[i]);
        RTE_MBUF_PREFETCH_TO_FREE(mtable[i+1]);
    }
}

inline int32_t
recv_pkts(uint16_t core_id, uint16_t port) {
    struct dpdk_private_context* dpc;
    int ret;
    struct ssl_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    if (dpc->rmbufs[port].len != 0) {
        free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
        dpc->rmbufs[port].len = 0;
    }

    ret = rte_eth_rx_burst((uint8_t)port, core_id,
                           dpc->pkts_burst, MAX_PKT_BURST);

    dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
    dpc->rmbufs[port].len = ret;

    stat->rx_pkts[port] += ret;

    return ret;
}

inline uint8_t *
get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t *len) {
    struct dpdk_private_context* dpc;
    struct rte_mbuf *m;
    uint8_t *pktbuf;
    struct ssl_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    m = dpc->pkts_burst[index];

    *len = m->pkt_len;
    pktbuf = rte_pktmbuf_mtod(m, uint8_t *);

    dpc->rmbufs[port].m_table[index] = m;

    if ((m->ol_flags & (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD)) != 0) {
        fprintf(stderr,
                "[CPU %d][Port %d] mbuf(index: %d) with invalid checksum: "
                "%p(%lu);\n",
                core_id, port, index, m, m->ol_flags);
        pktbuf = NULL;
    }

    stat->rx_bytes[port] += *len;

    return pktbuf;
}

#if OFFLOAD_AES_GCM
inline struct rte_mbuf *
get_wmbuf(uint16_t core_id, uint16_t port, uint16_t pktsize) {
    struct dpdk_private_context *dpc;
    struct rte_mbuf *m;
    int len_mbuf;
    int send_cnt;
    struct ssl_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
        while(1) {
            send_cnt = send_pkts(core_id, port);
            if (likely(send_cnt))
                break;
        }
    }

    /* sanity check */
    len_mbuf = dpc->wmbufs[port].len;
    m = dpc->wmbufs[port].m_table[len_mbuf];

    m->pkt_len = m->data_len = pktsize;
    m->nb_segs = 1;
    m->next = NULL;
#if OFFLOAD_AES_GCM
	m->tls_ctx = NULL;
#endif

	m->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
		PKT_TX_TCP_CKSUM;

    dpc->wmbufs[port].len = len_mbuf + 1;

    stat->tx_bytes[port] += pktsize;

    return m;
}
#endif	/* OFFLOAD_AES_GCM */

inline uint8_t *
get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize) {
    struct dpdk_private_context *dpc;
    struct rte_mbuf *m;
    uint8_t *ptr;
    int len_mbuf;
    int send_cnt;
    struct ssl_stat *stat = &ctx_array[core_id]->stat;

    dpc = ctx_array[core_id]->dpc;

    if (unlikely(dpc->wmbufs[port].len == MAX_PKT_BURST)) {
        while(1) {
            send_cnt = send_pkts(core_id, port);
            if (likely(send_cnt))
                break;
        }
    }

    /* sanity check */
    len_mbuf = dpc->wmbufs[port].len;
    m = dpc->wmbufs[port].m_table[len_mbuf];

    ptr = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    m->pkt_len = m->data_len = pktsize;
    m->nb_segs = 1;
    m->next = NULL;
#if OFFLOAD_AES_GCM
	m->tls_ctx = NULL;
#endif

    dpc->wmbufs[port].len = len_mbuf + 1;

    stat->tx_bytes[port] += pktsize;

    return (uint8_t *)ptr;
}

inline int
send_pkts(uint16_t core_id, uint16_t port) {
    struct dpdk_private_context *dpc;
    struct ssl_stat *stat = &ctx_array[core_id]->stat;
    int ret, i;

    dpc = ctx_array[core_id]->dpc;
    ret = 0;

    if (dpc->wmbufs[port].len > 0) {
        struct rte_mbuf **pkts;
        int cnt = dpc->wmbufs[port].len;
        pkts = dpc->wmbufs[port].m_table;

        do {
            ret = rte_eth_tx_burst(port, core_id, pkts, cnt);
            pkts += ret;
            cnt -= ret;
        } while (cnt > 0);

        for (i = 0; i < dpc->wmbufs[port].len; i++) {
            dpc->wmbufs[port].m_table[i] =
                            rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
            if (unlikely(dpc->wmbufs[port].m_table[i] == NULL)) {
                rte_exit(EXIT_FAILURE,
                         "[CPU %d] Failed to allocate wmbuf[%d] on port %d\n",
                         core_id, i, port);
                fflush(stdout);
            }
        }
        dpc->wmbufs[port].len = 0;
    }

    stat->tx_pkts[port] += ret;

    return ret;
}
