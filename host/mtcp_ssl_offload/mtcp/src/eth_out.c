#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/ip.h>

#include "mtcp.h"
#include "arp.h"
#include "eth_out.h"
#include "debug.h"
#include "mtcp_ssloff.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define MAX_WINDOW_SIZE 65535

/*----------------------------------------------------------------------------*/
uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto, 
			   int nif, unsigned char* dst_haddr, uint16_t iplen, uint8_t **opaque)
{
	uint8_t *buf;
	struct ethhdr *ethh;
	int i, eidx;

	/* 
 	 * -sanity check- 
	 * return early if no interface is set (if routing entry does not exist)
	 */
	if (nif < 0) {
		TRACE_INFO("No interface set!\n");
		return NULL;
	}

	eidx = CONFIG.nif_to_eidx[nif];
	if (eidx < 0) {
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

#if GSO_ENABLED
	buf = mtcp->iom->get_gso_wptr(mtcp->ctx, eidx, iplen + ETHERNET_HEADER_LEN, opaque);
#else
	buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, iplen + ETHERNET_HEADER_LEN);
#endif
	if (!buf) {
		//TRACE_DBG("Failed to get available write buffer\n");
		return NULL;
	}
	//memset(buf, 0, ETHERNET_HEADER_LEN + iplen);

#if 0
	TRACE_DBG("dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				dst_haddr[0], dst_haddr[1], 
				dst_haddr[2], dst_haddr[3], 
				dst_haddr[4], dst_haddr[5]);
#endif

	ethh = (struct ethhdr *)buf;

	for (i = 0; i < ETH_ALEN; i++) {
		ethh->h_source[i] = CONFIG.eths[eidx].haddr[i];
		ethh->h_dest[i] = dst_haddr[i];
	}
	ethh->h_proto = htons(h_proto);

	return (uint8_t *)(ethh + 1);
}
/*----------------------------------------------------------------------------*/

#ifdef USE_BLUEFIELD
uint8_t *
EthernetInitMetaOutput(struct mtcp_manager *mtcp)
{
	uint8_t *buf;
	struct meta_hdr *metah;
	uint8_t *meta_host_key, *meta_host_iv;
	int eidx;
	int payload_len;
	int i;

	payload_len = host_key_size + host_iv_size;

	eidx = CONFIG.nif_to_eidx[0];
	if (eidx < 0) {
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

	buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, sizeof(struct meta_hdr) + payload_len);
	if (!buf) {
		TRACE_ERROR("get_wptr() failed\n");
		return NULL;
	}

	metah = (struct meta_hdr *)buf;
	metah->key_size = host_key_size;
	metah->iv_size = host_iv_size;
	metah->h_proto = htons(ETH_P_INIT_META);

	meta_host_key = (uint8_t *)(metah + 1);
	for (i = 0; i < host_key_size; i++)
		meta_host_key[i] = host_key[i];

	meta_host_iv = (uint8_t *)(meta_host_key + host_key_size);
	for (i = 0; i < host_iv_size; i++)
		meta_host_iv[i] = host_iv[i];

#if VERBOSE
	unsigned z;
	fprintf(stdout, "host key size: %u\n", host_key_size);
	fprintf(stdout, "\nhost key\n");
	for (z = 0; z < host_key_size; z++)
		fprintf(stdout, "%02X%c", host_key[z],
				((z + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");

	fprintf(stdout, "host iv size: %u\n", host_iv_size);
	fprintf(stdout, "\nhost iv\n");
	for (z = 0; z < host_iv_size; z++)
		fprintf(stdout, "%02X%c", host_iv[z],
				((z + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");

	fflush(stdout);
#endif /* VERBOSE */

	return (uint8_t *)(metah + 1);
}
#endif /* USE_BLUEFIELD */
