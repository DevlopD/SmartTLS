#ifndef SSLOFF_H
#define SSLOFF_H

#include "mtcp_ssl.h"

int
ProcessInitMetaPacket(mtcp_manager_t mtcp, uint32_t cur_ts,
			const int ifidx, unsigned char *pkt_data, int len);

#endif /* SSLOFF_H */
