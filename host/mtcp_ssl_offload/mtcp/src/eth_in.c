#include "ps.h"
#include "ip_in.h"
#include "eth_in.h"
#include "arp.h"
#include "debug.h"

#if SSL_OFF
#include "mtcp_ssloff.h"
#endif /* SSL_OFF */

/*----------------------------------------------------------------------------*/
int
ProcessPacket(mtcp_manager_t mtcp, const int ifidx, 
		uint32_t cur_ts, unsigned char *pkt_data, int len)
{
	struct ethhdr *ethh = (struct ethhdr *)pkt_data;
	u_short ip_proto = ntohs(ethh->h_proto);
	int ret;

/* #if 1 */
#ifdef PKTDUMP
	fprintf(stderr, "DumpPacket\n");
	fprintf(stderr, "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
				  ethh->h_source[0],
				  ethh->h_source[1],
				  ethh->h_source[2],
				  ethh->h_source[3],
				  ethh->h_source[4],
				  ethh->h_source[5],
				  ethh->h_dest[0],
				  ethh->h_dest[1],
				  ethh->h_dest[2],
				  ethh->h_dest[3],
				  ethh->h_dest[4],
				  ethh->h_dest[5]);
#endif

#ifdef NETSTAT
	mtcp->nstat.rx_packets[ifidx]++;
	mtcp->nstat.rx_bytes[ifidx] += len + 24;
#endif /* NETSTAT */

#if 0
	/* ignore mac address which is not for current interface */
	int i;
	for (i = 0; i < 6; i ++) {
		if (ethh->h_dest[i] != CONFIG.eths[ifidx].haddr[i]) {
			return FALSE;
		}
	}
#endif

	if (ip_proto == ETH_P_IP) {
		/* process ipv4 packet */
		ret = ProcessIPv4Packet(mtcp, cur_ts, ifidx, pkt_data, len);
	} else if (ip_proto == ETH_P_INIT_META) {
		ret = ProcessInitMetaPacket(mtcp, cur_ts, ifidx, pkt_data, len);
	} else if (ip_proto == ETH_P_ARP) {
		ProcessARPPacket(mtcp, cur_ts, ifidx, pkt_data, len);
		return TRUE;

	} else {
		fprintf(stderr, "Protocol Unmatched!!\n");
		//DumpPacket(mtcp, (char *)pkt_data, len, "??", ifidx);
		mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
		return TRUE;
	}

#ifdef NETSTAT
	if (ret < 0) {
		mtcp->nstat.rx_errors[ifidx]++;
	}
#endif

	return ret;
}
