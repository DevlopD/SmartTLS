/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "ssloff.h"
#include "option.h"

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode        =   ETH_MQ_RX_RSS,
        .max_rx_pkt_len =   ETHER_MAX_LEN,
#if RTE_VERSION > RTE_VERSION_NUM(17, 8, 0, 0)
        .offloads       =   (
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
                                DEV_RX_OFFLOAD_CRC_STRIP |
#endif /* !18.05 */
                                DEV_RX_OFFLOAD_CHECKSUM
                            ),
#endif /* !17.08 */
        .split_hdr_size =   0,
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
        .header_split   =   0,
        .hw_ip_checksum =   1,
        .hw_vlan_filter =   0,
        .jumbo_frame    =   0,
        .hw_strip_crc   =   1,
#endif /* !18.05 */
    },
    .rx_adv_conf = {
        .rss_conf   =   {
            .rss_key    =   NULL,
            .rss_hf     =   ETH_RSS_TCP | ETH_RSS_UDP |
                            ETH_RSS_IP | ETH_RSS_L2_PAYLOAD
        },
    },
    .txmode = {
        .mq_mode    =   ETH_MQ_TX_NONE,
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        .offloads   =   (
                            DEV_TX_OFFLOAD_IPV4_CKSUM |
                            DEV_TX_OFFLOAD_UDP_CKSUM |
                            DEV_TX_OFFLOAD_TCP_CKSUM
                        )
#endif
    },
};

struct ssl_stat global_stat;

uint8_t nic_key[MAX_KEY_SIZE];
uint8_t nic_iv[MAX_KEY_SIZE];
uint8_t nic_key_size;
uint8_t nic_iv_size;
uint8_t host_key[MAX_KEY_SIZE];
uint8_t host_iv[MAX_KEY_SIZE];
uint8_t host_key_size;
uint8_t host_iv_size;

struct rte_mempool *pktmbuf_pool[MAX_CPUS] = {NULL};
struct thread_context* ctx_array[MAX_CPUS] = {NULL};
uint32_t complete_conn[MAX_CPUS] = {0};
uint8_t port_type[MAX_DPDK_PORT] = {0};
static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
int max_conn;
int local_max_conn;

uint8_t t_major = 0;
uint8_t t_minor = 0;

static const uint16_t nb_rxd    =   RTE_TEST_RX_DESC_DEFAULT;
static const uint16_t nb_txd    =   RTE_TEST_TX_DESC_DEFAULT;

pka_instance_t instance;
pka_barrier_t thread_start_barrier;
pka_handle_t handle[MAX_CPUS];

option_t option;
ssl_context_t ctx_example;

static void
global_init(void)
{
    int nb_ports, num_core, portid, rxlcore_id, ret;
    struct rte_eth_fc_conf fc_conf;
    char if_name[RTE_ETH_NAME_MAX_LEN];

    const char* original_key_file =
            "/root/ssl_offload/dpdk-19.05/examples/offload_ssl/cert/my_cert.pem";
    const char* original_key_passwd = "1234";

    static uint8_t key[] = {
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
    };

    num_core = rte_lcore_count();
    if (num_core <= 0) {
        fprintf(stderr, "Zero or negative number of cores activated.\n");
        exit(EXIT_FAILURE);
    }

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports <= 0) {
        fprintf(stderr, "Zero or negative number of ports activated.\n");
        exit(EXIT_FAILURE);
    }

    /* Setting RSS Key */    
    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)key;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    /* Packet mbuf pool Creation */
    for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
        char name[RTE_MEMPOOL_NAMESIZE];
        sprintf(name, "mbuf_pool-%d", rxlcore_id);

        pktmbuf_pool[rxlcore_id] =
	        rte_pktmbuf_pool_create(name, NUM_MBUFS * nb_ports,
		    MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

        if (pktmbuf_pool[rxlcore_id] == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool, errno: %d\n",
                     rte_errno);
            fflush(stdout);
        }
    }
    fprintf(stderr, "mbuf_pool Created\n");

    /* Port Configuration and Activation */
    RTE_ETH_FOREACH_DEV(portid) {
        rte_eth_dev_get_name_by_port(portid, if_name);
        rte_eth_dev_info_get(portid, &dev_info[portid]);
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        port_conf.rx_adv_conf.rss_conf.rss_hf &=
                    dev_info[portid].flow_type_rss_offloads;
#endif
        fprintf(stderr, "Initializaing port %u (%s) ... for %d cores\n",
                        (unsigned) portid, if_name, num_core);
        ret = rte_eth_dev_configure(portid, num_core, num_core, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: "
                                   "err=%d, port=%u, cores: %d\n",
                                   ret, (unsigned) portid, num_core);

        for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
            ret = rte_eth_rx_queue_setup(portid, rxlcore_id, nb_rxd,
                                         rte_eth_dev_socket_id(portid),
                                         &rx_conf, pktmbuf_pool[rxlcore_id]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: "
                         "err=%d, port=%u, queueid: %d\n",
                         ret, (unsigned) portid, rxlcore_id);
        }

        for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
            ret = rte_eth_tx_queue_setup(portid, rxlcore_id, nb_txd,
                                         rte_eth_dev_socket_id(portid),
                                         &tx_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: "
                         "err=%d, port=%u, queueid: %d\n",
                         ret, (unsigned) portid, rxlcore_id);
        }

        ret = rte_eth_dev_start(portid);

        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "rte_eth_dev_start:err=%d, port=%u\n",
                     ret, (unsigned) portid);

        rte_eth_promiscuous_enable(portid);

        /* Do not have to change flow control info for host side interface
         * 12 is the length of "0000:00:00.0" */
        if (strlen(if_name) > 12) {
            port_type[portid] = 1;
            continue;
        }

        memset(&fc_conf, 0, sizeof(fc_conf));
        ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
        if (ret != 0)
            fprintf(stderr, "Failed to get flow control info!\n");

        fc_conf.mode = RTE_FC_NONE;
        ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
        if (ret != 0)
            fprintf(stderr, "Failed to set flow control info!: errno: %d\n",
                            ret);

    }
    fprintf(stderr, "Port Initialization Complete\n");

    /* PKA Initialization */
	if(rte_lcore_count() == 1) {
		fprintf(stderr, "Initialize Single core mode\n");
		instance = pka_init_global("ssl offload", PKA_F_PROCESS_MODE_SINGLE |
								   PKA_F_SYNC_MODE_DISABLE,
								   PKA_RING_CNT, PKA_QUEUE_CNT,
								   CMD_QUEUE_SIZE, RSLT_QUEUE_SIZE);
	} else {
		instance = pka_init_global("ssl offload", PKA_F_PROCESS_MODE_SINGLE |
								   PKA_F_SYNC_MODE_ENABLE,
								   PKA_RING_CNT, PKA_QUEUE_CNT,
								   CMD_QUEUE_SIZE, RSLT_QUEUE_SIZE);
	}

    if (instance == PKA_INSTANCE_INVALID) {
        perror("pka_init_global");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "PKA Engine Initialized\n");

    pka_barrier_init(&thread_start_barrier, num_core);
    fprintf(stderr, "PKA Thread Barrier Initialized\n");

    option.key_file = (char *)calloc(1, strlen(original_key_file));
    option.key_passwd = (char *)calloc(1, strlen(original_key_passwd));
    strncpy(option.key_file, original_key_file,
            strlen(original_key_file));
    strncpy(option.key_passwd, original_key_passwd,
            strlen(original_key_passwd));

    if (cert_load_key(&ctx_example) < 0) {
        fprintf(stderr, "cert_load_key fail\n");
        exit(EXIT_FAILURE);
    }

    assert(ctx_example.certificate != NULL);
    assert(ctx_example.rsa != NULL);
    assert(ctx_example.pka != NULL);

    fprintf(stderr, "Certification Initialization Complete\n");

    global_stat.completes = 0;
    global_stat.only_tcp = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        global_stat.rx_bytes[portid] = 0;
        global_stat.rx_pkts[portid] = 0;

        global_stat.tx_bytes[portid] = 0;
        global_stat.tx_pkts[portid] = 0;

        global_stat.rtx_bytes[portid] = 0;
        global_stat.rtx_pkts[portid] = 0;
    }

    srand(time(NULL));
    nic_key_size = INIT_KEY_SIZE;
    nic_iv_size = INIT_IV_SIZE;

    int i;
    for (i = 0; i < nic_key_size; i++)
        nic_key[i] = rand() % 256;

    for (i = 0; i < nic_iv_size; i++)
        nic_iv[i] = rand() % 256;
}

void
global_destroy(void)
{
    int portid;

    free(ctx_example.rsa);
    free(ctx_example.pka);

    RTE_ETH_FOREACH_DEV(portid) {
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
    }

    pka_term_global(instance);
}

static int
parse_args(int argc, char *argv[])
{
    int o;

    while(-1 != (o = getopt(argc, argv, "m:h:"))) {
        switch(o) {
            case 'm':
                max_conn = atoi(optarg);
                if (max_conn > MAX_TCP_PORT) {
                    fprintf(stderr,
                            "max_conn cannot exceed maximum number of ports");
                    return false;
                }
                break;
            case 'h':
            default:
                break;
        }
    }
    return true;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    unsigned lcore_id;
    unsigned i;
    int ret;

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

    fprintf(stderr, "\nRTE EAL Initialization Complete\n");
    fprintf(stderr, "---------------------------------------------------\n\n");

    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid Arguments\n");

    if (max_conn % rte_lcore_count()) {
        rte_exit(EXIT_FAILURE,
                 "max_conn should be a multiple of core num."
                 "max_conn: %d, num_core: %d\n",
                 max_conn, rte_lcore_count());
    }
    local_max_conn = max_conn / rte_lcore_count();
    fprintf(stderr, "Global Maximum Connection: %d\n"
                    "Maximum Connections per Thread: %d\n",
                    max_conn, local_max_conn);

    fprintf(stderr, "\nArgument Parsing Complete\n");
    fprintf(stderr, "---------------------------------------------------\n\n");

    global_init();

    fprintf(stderr, "\nGlobal Initialization Complete\n");
    fprintf(stderr, "---------------------------------------------------\n\n");

    fprintf(stderr, "Use Following Cores for SSL Offloaded Server\n");
    for (i = 0; i < rte_lcore_count(); i++) {
        fprintf(stderr, "%d", i);
        if (i != rte_lcore_count() - 1 )
            fprintf(stderr, ", ");
    }
    fprintf(stderr, "\n\n");

	/* Call lcore_main on the master core only. */
    rte_eal_mp_remote_launch(ssloff_main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    global_destroy();

	return 0;
}
