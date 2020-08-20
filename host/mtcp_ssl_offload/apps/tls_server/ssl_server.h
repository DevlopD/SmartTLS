#ifndef __SSL_SERVER_H__
#define __SSL_SERVER_H__

#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <ssl_api.h>

#define MAX_FLOW_NUM  (10000)

#define RCVBUF_SIZE (2*1024)
#define SNDBUF_SIZE (60000)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define HTTP_HEADER_LEN 1024
#define MAX_KEY_SIZE 32
#define MAX_HEADER_LEN (HTTP_HEADER_LEN + MAX_KEY_SIZE)

#define URL_LEN 128

#define MAX_FILES 30

#define NAME_LIMIT 256
#define FULLNAME_LIMIT 512

enum
{
	UNUSED,
	SSL_UNUSED,
	SSL_ACCEPT_INCOMPLETED,
	SSL_ACCEPT_COMPLETED,
	SSL_ACCEPT_OFFLOAD,
};

struct server_vars
{
	int sockid;
	char request[HTTP_HEADER_LEN];
	int recv_len;
	int request_len;
	long int total_read, total_sent;
	uint8_t done;
	uint8_t rspheader_sent;
	char rspheader[HTTP_HEADER_LEN];
	int rspheader_len;
	uint8_t keep_alive;

	int fidx;						// file cache index
	char fname[NAME_LIMIT];				// file name
	long int fsize;					// file size

	/* SSL related variables */
	int state;
	mtcp_SSL* ssl;
};
/*----------------------------------------------------------------------------*/
struct server_stat
{
	uint64_t completes;
};

struct thread_context
{
	mctx_t mctx;
	uint16_t coreid;
	int ep;
	struct server_vars *svars;
	struct server_stat stat;

	mtcp_SSL_CTX *ssl_ctx;
};
/*----------------------------------------------------------------------------*/

#endif /* __SSL_SERVER_H__ */
