#include <netinet/ip.h>

#include "mtcp.h"
#include "mtcp_api.h"
#include "mtcp_ssl.h"
#include "mtcp_ssloff.h"
#include "ip_in.h"
#include "tcp_in.h"
#include "debug.h"

#if USE_BLUEFIELD
int
ProcessInitMetaPacket(mtcp_manager_t mtcp, uint32_t cur_ts,
			const int ifidx, unsigned char *pkt_data, int len)
{
	struct meta_hdr *metah;
	uint8_t *meta_nic_key, *meta_nic_iv;

	metah = (struct meta_hdr *)pkt_data;
	nic_key_size = metah->key_size;
	nic_iv_size = metah->iv_size;

	meta_nic_key = (uint8_t *)(metah + 1);
	meta_nic_iv = (uint8_t *)(meta_nic_key + nic_key_size);

	memcpy(nic_key, meta_nic_key, nic_key_size);
	memcpy(nic_iv, meta_nic_iv, nic_iv_size);

#if VERBOSE
	unsigned z;
	fprintf(stdout, "nic key size: %u\n", nic_key_size);
	fprintf(stdout, "\nnic key\n");
	for (z = 0; z < nic_key_size; z++)
		fprintf(stdout, "%02X%c", nic_key[z],
				((z + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");

	fprintf(stdout, "nic iv size: %u\n", nic_iv_size);
	fprintf(stdout, "\nnic iv\n");
	for (z = 0; z < nic_iv_size; z++)
		fprintf(stdout, "%02X%c", nic_iv[z],
				((z + 1) % 16 ? ' ' : '\n'));
	fprintf(stdout, "\n");

	fflush(stdout);
#endif /* VERBOSE */

	return len;
}

int
mtcp_accept_tls(mctx_t mctx, int sockid,
		struct sockaddr *addr, socklen_t *addrlen,
		ssl_info_t *info)
{
	mtcp_manager_t mtcp;
	struct tcp_listener *listener;
	socket_map_t socket;
	tcp_stream *accepted = NULL;

	mtcp = GetMTCPManager(mctx);
	if (!mtcp) {
		return -1;
	}

	if (!info) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		TRACE_API("Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	/* requires listening socket */
	if (mtcp->smap[sockid].socktype != MTCP_SOCK_LISTENER) {
		errno = EINVAL;
		return -1;
	}

	listener = mtcp->smap[sockid].listener;

	/* dequeue from the acceptq without lock first */
	/* if nothing there, acquire lock and cond_wait */
	accepted = StreamDequeue(listener->acceptq);
	if (!accepted) {
		if (listener->socket->opts & MTCP_NONBLOCK) {
			errno = EAGAIN;
			return -1;

		} else {
			pthread_mutex_lock(&listener->accept_lock);
			while ((accepted = StreamDequeue(listener->acceptq)) == NULL) {
				pthread_cond_wait(&listener->accept_cond, &listener->accept_lock);
		
				if (mtcp->ctx->done || mtcp->ctx->exit) {
					pthread_mutex_unlock(&listener->accept_lock);
					errno = EINTR;
					return -1;
				}
			}
			pthread_mutex_unlock(&listener->accept_lock);
		}
	}

	if (!accepted) {
		TRACE_ERROR("[NEVER HAPPEN] Empty accept queue!\n");
	}

	if (!accepted->socket) {
		socket = AllocateSocket(mctx, MTCP_SOCK_STREAM, FALSE);
		if (!socket) {
			TRACE_ERROR("Failed to create new socket!\n");
			/* TODO: destroy the stream */
			errno = ENFILE;
			return -1;
		}
		socket->stream = accepted;
		accepted->socket = socket;

		/* set socket parameters */
		socket->saddr.sin_family = AF_INET;
		socket->saddr.sin_port = accepted->dport;
		socket->saddr.sin_addr.s_addr = accepted->daddr;
	}

	if (!(listener->socket->epoll & MTCP_EPOLLET) &&
	    !StreamQueueIsEmpty(listener->acceptq))
		AddEpollEvent(mtcp->ep, 
			      USR_SHADOW_EVENT_QUEUE,
			      listener->socket, MTCP_EPOLLIN);

	TRACE_API("Stream %d accepted.\n", accepted->id);

	if (addr && addrlen) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = accepted->dport;
		addr_in->sin_addr.s_addr = accepted->daddr;
		*addrlen = sizeof(struct sockaddr_in);
	}

	if (accepted->ssl_onload) {
		memcpy(info, accepted->ssl_info, sizeof(ssl_info_t));
	}
	else {
		info->active = FALSE;
	}

	return accepted->socket->id;
}
#endif /* USE_BLUEFIELD */
