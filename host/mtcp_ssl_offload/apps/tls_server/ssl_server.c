#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>

#include "ssl_server.h"
#include "ssl_cert.h"

#include "cpu.h"
#include "http_parsing.h"
#include "netlib.h"
#include "debug.h"


#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define HT_SUPPORT FALSE

#ifndef MAX_CPUS
#define MAX_CPUS		16
#endif

#define SERVER_PORT 443

#define VERBOSE FALSE

mtcp_PUBLIC_CRYPTO_CTX public_crypto_ctx[MAX_CPUS];
int local_max_conn;
/*----------------------------------------------------------------------------*/
struct file_cache
{
	char name[NAME_LIMIT];
	char fullname[FULLNAME_LIMIT];
	uint64_t size;
	char *file;
};

/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];
static char *conf_file = NULL;
static int backlog = -1;
static struct server_stat *g_stat[MAX_CPUS] = {0};
/*----------------------------------------------------------------------------*/
const char *www_main;
static struct file_cache fcache[MAX_FILES];
static int nfiles;
/*----------------------------------------------------------------------------*/
static int finished;
/*----------------------------------------------------------------------------*/
static char *
StatusCodeToString(int scode)
{
	switch (scode) {
		case 200:
			return "OK";
			break;

		case 404:
			return "Not Found";
			break;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
CleanServerVariable(struct server_vars *sv)
{
	sv->recv_len = 0;
	sv->request_len = 0;
	sv->total_read = 0;
	sv->total_sent = 0;
	sv->done = 0;
	sv->rspheader_sent = 0;
	sv->rspheader_len = 0;
	sv->keep_alive = 0;
	sv->state = UNUSED;
}
/*----------------------------------------------------------------------------*/
void 
CloseConnection(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
#if VERBOSE
	fprintf(stderr, "Close Connection %d\n", sockid);
#endif
	if(sv->state != SSL_UNUSED){
		mtcp_SSL_shutdown(sv->ssl);
	}

#if VERBOSE
	fprintf(stderr, "mtcp_SSL_shutdown done\n");
#endif
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(ctx->mctx, sockid);
	sv->state = SSL_UNUSED;
}
/*----------------------------------------------------------------------------*/
void 
AbortConnection(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	if(sv->state != SSL_UNUSED) {
		mtcp_SSL_shutdown(sv->ssl);
	}
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_abort(ctx->mctx, sockid);
	sv->state = SSL_UNUSED;
}
/*----------------------------------------------------------------------------*/
int
AcceptSSL(struct thread_context *ctx, mtcp_SSL *ssl, int sockid)
{
	int accept_ret, accept_err_num;
	struct mtcp_epoll_event ev;

	if ((accept_ret = mtcp_SSL_accept(ssl)) == FAIL) {
		accept_err_num = mtcp_SSL_get_error(ssl, accept_ret);
#if VERBOSE
		fprintf(stderr, "mtcp_SSL_accept error: %d\n", accept_err_num);
#endif /* VERBOSE */
		if (accept_err_num == mtcp_SSL_ERROR_WANT_READ) {
			return SSL_ACCEPT_INCOMPLETED;
		}
		else if (accept_err_num == mtcp_SSL_ERROR_WANT_WRITE) {
			ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
			ev.data.sockid = sockid;
			mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
			return SSL_ACCEPT_INCOMPLETED;
		} else {
			return FAIL;
		}
	}
	else {
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = sockid;
		mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

		if (accept_ret == mtcp_SSL_SUCCESS_NORMAL)
			return SSL_ACCEPT_COMPLETED;
		else if (accept_ret == mtcp_SSL_SUCCESS_OFFLOAD)
			return SSL_ACCEPT_OFFLOAD;
	}

	return FAIL;
}

/*----------------------------------------------------------------------------*/
static int 
SendUntilAvailable(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	int ret;
	int sent;
	int len;
	int err;

	if (sv->done || !sv->rspheader_sent) {
		return 0;
	}

	sent = 0;
	ret = 1;
	while (ret > 0) {
		len = MIN(SNDBUF_SIZE, sv->fsize - sv->total_sent);
		if (len <= 0) {
			break;
		}
		ret = mtcp_SSL_write(sv->ssl,  
				fcache[sv->fidx].file + sv->total_sent, len);
		if (ret == FAIL) {
			err = mtcp_SSL_get_error(sv->ssl, ret);
			if (err == mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE) {
				TRACE_APP("Connection closed with client.\n");
				break;
			}
			else if (err == mtcp_SSL_ERROR_WANT_WRITE ||
						err == mtcp_SSL_ERROR_WANT_READ) {
				break;
			}
			else {
				/* ToDo: remove exit() */
				fprintf(stderr, "[SendUntilAvailable] Error num: %d\n", err);
				break;
				exit(EXIT_FAILURE);
			}
		}
		sent += ret;
		sv->total_sent += ret;
	}

#if VERBOSE
	fprintf(stderr, "total_sent: %lu, file size: %lu\n",
					sv->total_sent, fcache[sv->fidx].size);
#endif /* VERBOSE */
	if (sv->total_sent >= fcache[sv->fidx].size) {
		struct mtcp_epoll_event ev;
		sv->done = TRUE;
		finished++;
		g_stat[ctx->coreid]->completes++;

		if (sv->keep_alive) {
			/* if keep-alive connection, wait for the incoming request */
			ev.events = MTCP_EPOLLIN;
			ev.data.sockid = sockid;
			mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

			CleanServerVariable(sv);
			sv->keep_alive = TRUE;
			sv->state = SSL_ACCEPT_COMPLETED;
		} else {
			/* else, close connection */
			CloseConnection(ctx, sockid, sv);
		}
	}

	return sent;
}
/*----------------------------------------------------------------------------*/
static int 
HandleReadEvent(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	struct mtcp_epoll_event ev;
	char buf[HTTP_HEADER_LEN];
	char url[URL_LEN];
	int scode;						// status code
	time_t t_now;
	char t_str[128];
	char keepalive_str[128];
	int rd;
	int i;
	//int len;
	int sent;
	int ret;
	int err;

	/* Do SSL Handshake */
	if (sv->state == SSL_UNUSED || sv->state == SSL_ACCEPT_INCOMPLETED) {
		/* FD of SSL is already set */
		mtcp_SSL *ssl = sv->ssl;
		ret = AcceptSSL(ctx, ssl, sockid);
		if (ret == FAIL) {
			return -1;
		}
		else if (ret == SSL_ACCEPT_OFFLOAD) {
			sv->state = SSL_ACCEPT_COMPLETED;
			goto do_app;
		}
		else {
			sv->state = ret;
		}
		return ret;
	}
	else if (sv->state == SSL_ACCEPT_COMPLETED) {
		goto do_app;
	}
	else {
		fprintf(stderr, "What ever kill, sv->state: %d\n", sv->state);
		exit(EXIT_FAILURE);
	}

do_app:
	while (1) {
		rd = mtcp_SSL_read(sv->ssl, buf, HTTP_HEADER_LEN);
		if (rd < 0) {
			fprintf(stderr, "rd -1\n");
			break;
		}
		else if (rd == 0) {
			ret = mtcp_SSL_get_error(sv->ssl, rd);
#if VERBOSE
			fprintf(stderr, "ret: %d\n", ret);
#endif /* VERBOSE */
			if (ret == mtcp_SSL_ERROR_WANT_READ) {
				return 1;
			}
			else if (ret == mtcp_SSL_ERROR_TCP_RETURN_ZERO) {
				return 0;
			}
			else {
				return -1;
			}
		}
		else {
#if VERBOSE
			fprintf(stderr, "APP DATA: %d\n"
							"%s\n",
							rd, buf);
#endif /* VERBOSE */
			memcpy(sv->request + sv->recv_len, 
					(char *)buf, MIN(rd, HTTP_HEADER_LEN - sv->recv_len));
			sv->recv_len += rd;

			sv->request_len = find_http_header(sv->request, sv->recv_len);

			if (sv->request_len <= 0) {
				TRACE_ERROR("Socket %d: Failed to parse HTTP request header.\n"
						"read bytes: %d, recv_len: %d, "
						"request_len: %d, strlen: %ld, request: \n%s\n", 
						sockid, rd, sv->recv_len, 
						sv->request_len, strlen(sv->request), sv->request);
				return rd;
			}

			http_get_url(sv->request, sv->request_len, url, URL_LEN);
			TRACE_APP("Socket %d URL: %s\n", sockid, url);
			sprintf(sv->fname, "%s%s", www_main, url);
			TRACE_APP("Socket %d File name: %s\n", sockid, sv->fname);

			sv->keep_alive = FALSE;
			if (http_header_str_val(sv->request, "Connection: ", 
						strlen("Connection: "), keepalive_str, 128)) {	
				if (strstr(keepalive_str, "Keep-Alive")) {
					sv->keep_alive = TRUE;
				} else if (strstr(keepalive_str, "Close")) {
					sv->keep_alive = FALSE;
				}
			}

			/* Find file in cache */
			scode = 404;
			for (i = 0; i < nfiles; i++) {
				if (strcmp(sv->fname, fcache[i].fullname) == 0) {
					sv->fsize = fcache[i].size;
					sv->fidx = i;
					scode = 200;
					break;
				}
			}
			TRACE_APP("Socket %d File size: %ld (%ldMB)\n", 
					sockid, sv->fsize, sv->fsize / 1024 / 1024);

			/* Response header handling */
			time(&t_now);
			strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now));
			if (sv->keep_alive)
				sprintf(keepalive_str, "Keep-Alive");
			else
				sprintf(keepalive_str, "Close");

			sprintf(sv->rspheader, "HTTP/1.1 %d %s\r\n"
					"Date: %s\r\n"
					"Server: Webserver on Middlebox TCP (Ubuntu)\r\n"
					"Content-Length: %ld\r\n"
					"Connection: %s\r\n\r\n", 
					scode, StatusCodeToString(scode), t_str, sv->fsize, keepalive_str);
			sv->rspheader_len = strlen(sv->rspheader);
			TRACE_APP("Socket %d HTTP Response: \n%s", sockid, sv->rspheader);
			sent = mtcp_SSL_write(sv->ssl, sv->rspheader, sv->rspheader_len);
			if (sent == FAIL) {
				err = mtcp_SSL_get_error(sv->ssl, sent);
				if (err == mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE) {
					TRACE_APP("Connection closed with client.\n");
					return -1;
				}
				else if (err == mtcp_SSL_ERROR_WANT_WRITE) {
					ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
					ev.data.sockid = sockid;
					mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
					return 1;
				}
				else if (err == mtcp_SSL_ERROR_WANT_READ) {
					return 1;
				}
				else {
					fprintf(stderr, "[HandleReadEvent] Error num: %d\n", err);
					exit(EXIT_FAILURE);
				}
			}

			TRACE_APP("Socket %d Sent response header: try: %d, sent: %d\n", 
					sockid, sv->rspheader_len, sent);
			sv->rspheader_sent = TRUE;

			ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
			ev.data.sockid = sockid;
			mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

#if VERBOSE
			fprintf(stderr, "Response message: "
							"%s\n", sv->rspheader);
#endif /* VERBOSE */
			SendUntilAvailable(ctx, sockid, sv);

			return rd;

			break;
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
int 
AcceptConnection(struct thread_context *ctx, int listener)
{
	mctx_t mctx = ctx->mctx;
	struct server_vars *sv;
	struct mtcp_epoll_event ev;
	int c;

	c = mtcp_accept(mctx, listener, NULL, NULL);
	if (c >= 0) {
		if (c >= MAX_FLOW_NUM) {
			TRACE_ERROR("Invalid socket id %d.\n", c);
			return -1;
		}

		sv = &ctx->svars[c];
		CleanServerVariable(sv);
		sv->state = SSL_UNUSED;
		mtcp_SSL_clear(sv->ssl);
		mtcp_SSL_set_fd(sv->ssl, c);

		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_setsock_nonblock(ctx->mctx, c);
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
#if VERBOSE
		fprintf(stderr, "Socket %d accepted.\n", c);
#endif /* VERBOSE */

	} else {
		if (errno != EAGAIN) {
			TRACE_ERROR("mtcp_accept() error %s\n", 
					strerror(errno));
		}
	}

	return c;
}
/*----------------------------------------------------------------------------*/
void
InitializeSSLContext(struct thread_context *t_ctx, int core)
{
	int j;
	mtcp_SSL_CTX *ssl_ctx;

	assert(t_ctx != NULL);

	ssl_ctx = t_ctx->ssl_ctx;

	for (j = 0; j < MAX_FLOW_NUM; j++) {
		t_ctx->svars[j].ssl = mtcp_SSL_new(ssl_ctx);
		if (t_ctx->svars[j].ssl == NULL) {
			fprintf(stderr, "Cannot allocate memory for"
					"%dth ssl array of core[%d]\n",
					j, core);
			exit(EXIT_FAILURE);
		}
		mtcp_SSL_set_fd(t_ctx->svars[j].ssl, j);
	}
}
/*----------------------------------------------------------------------------*/
mtcp_SSL_CTX *
InitializeServerCTX(mctx_t mctx)
{
	mtcp_SSL_CTX *ctx;
	const mtcp_SSL_METHOD *method;

	method = mtcp_TLSv1_2_server_method();
	ctx = mtcp_SSL_CTX_new(mctx, method);

	if (!ctx) {
		fprintf(stdout, "ServerCTX Initizilization Error\n");
		fflush(stdout);
		return NULL;
	}

	return ctx;
}
/*----------------------------------------------------------------------------*/
struct thread_context *
InitializeServerThread(int core)
{
	int i, ret;
	struct thread_context *ctx;

	/* affinitize application thread to a CPU core */
#if HT_SUPPORT
	mtcp_core_affinitize(core + (num_cores / 2));
#else
	mtcp_core_affinitize(core);
#endif /* HT_SUPPORT */

	ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		TRACE_ERROR("Failed to create thread context!\n");
		return NULL;
	}

	/* create mtcp context: this will spawn an mtcp thread */
	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		free(ctx);
		return NULL;
	}

	/* create epoll descriptor */
	ctx->ep = mtcp_epoll_create(ctx->mctx, MAX_EVENTS);
	if (ctx->ep < 0) {
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}

#if VERBOSE
	fprintf(stderr, "Epoll Socket %d created.\n", ctx->ep);
#endif /* VERBOSE */

	/* allocate memory for server variables */
	ctx->svars = (struct server_vars *)
			calloc(MAX_FLOW_NUM, sizeof(struct server_vars));
	if (!ctx->svars) {
		mtcp_close(ctx->mctx, ctx->ep);
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create server_vars struct!\n");
		return NULL;
	}
	for (i = 0; i < MAX_FLOW_NUM; i++)
	{
		ctx->svars[i].sockid = i;
	}

	ctx->ssl_ctx = InitializeServerCTX(ctx->mctx);
	if (!ctx->ssl_ctx) {
		mtcp_close(ctx->mctx, ctx->ep);
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create server_vars struct!\n");
		return NULL;
	}

	ret = mtcp_SSL_CTX_use_CRYPTO_CTX(ctx->ssl_ctx, &public_crypto_ctx[core]);

	if (ret < 0) {
		fprintf(stderr, "Certificate & key loading failed.\n");
		mtcp_SSL_CTX_free(ctx->ssl_ctx);
		mtcp_close(ctx->mctx, ctx->ep);
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		return NULL;
	}

	InitializeSSLContext(ctx, core);
	ctx->coreid = core;

	return ctx;
}
/*----------------------------------------------------------------------------*/
int 
CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	struct mtcp_epoll_event ev;
	struct sockaddr_in saddr;
	int ret;

	/* create socket and set it as nonblocking */
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	/* bind to port 80 */
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(SERVER_PORT);
	ret = mtcp_bind(ctx->mctx, listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* listen (backlog: can be configured) */
	ret = mtcp_listen(ctx->mctx, listener, backlog);
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}

#if VERBOSE
	fprintf(stderr, "Listening at socket %d\n", listener);
#endif /* VERBOSE */
	
	/* wait for incoming accept events */
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, listener, &ev);

	return listener;
}
/*----------------------------------------------------------------------------*/
void
PrintStats(void)
{
	struct server_stat total = {0};
	int i;

	for (i = 0; i < core_limit; i++) {
		total.completes += g_stat[i]->completes;
		memset(g_stat[i], 0, sizeof(struct server_stat));
	}
    fprintf(stderr, "[ ALL ] completes: %7lu \n",
            total.completes);
}
/*----------------------------------------------------------------------------*/
void
RunServerContext(void *arg)
{
	mctx_t mctx;
	int core, nevents;
	struct thread_context *ctx;
	int i, ret, ep;
	int do_accept;
	int listener;
	struct mtcp_epoll_event *events;
	struct timeval cur_tv, prev_tv;

	ctx = (struct thread_context *) arg;
	mctx = ctx->mctx;
	ep = ctx->ep;
	core = ctx->coreid;

	g_stat[core] = &ctx->stat;

	events = (struct mtcp_epoll_event *)
			calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	listener = CreateListeningSocket(ctx);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket.\n");
		exit(-1);
	}

	gettimeofday(&cur_tv, NULL);
	prev_tv = cur_tv;

	while (!done[core]) {
		gettimeofday(&cur_tv, NULL);
        if (core == 0 && cur_tv.tv_sec > prev_tv.tv_sec) {
            PrintStats();
            prev_tv = cur_tv;
        }

		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}

		do_accept = FALSE;
		for (i = 0; i < nevents; i++) {

			if (events[i].data.sockid == listener) {
				/* if the event is for the listener, accept connection */
				do_accept = TRUE;

			} else if (events[i].events & MTCP_EPOLLERR) {
				int err;
				socklen_t len = sizeof(err);

				/* error on the connection */
				TRACE_APP("[CPU %d] Error on socket %d\n", 
						core, events[i].data.sockid);
				if (mtcp_getsockopt(mctx, events[i].data.sockid, 
						SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
					if (err != ETIMEDOUT) {
						fprintf(stderr, "Error on socket %d: %s\n", 
								events[i].data.sockid, strerror(err));
					}
				} else {
					perror("mtcp_getsockopt");
				}
				CloseConnection(ctx, events[i].data.sockid, 
						&ctx->svars[events[i].data.sockid]);

			} else if (events[i].events & MTCP_EPOLLIN) {
				ret = HandleReadEvent(ctx, events[i].data.sockid, 
						&ctx->svars[events[i].data.sockid]);

#if VERBOSE_APP
				fprintf(stderr, "[RunServerContext] received %d byte!\n", ret);
#endif

				if (ret == 0) {
					/* connection closed by remote host */
					CloseConnection(ctx, events[i].data.sockid, 
							&ctx->svars[events[i].data.sockid]);
				} else if (ret < 0) {
					/* if not EAGAIN, it's an error */
					if (errno != EAGAIN) {
						CloseConnection(ctx, events[i].data.sockid, 
								&ctx->svars[events[i].data.sockid]);
					}
				}

			} else if (events[i].events & MTCP_EPOLLOUT) {
				struct server_vars *sv = &ctx->svars[events[i].data.sockid];
				if (sv->state == SSL_ACCEPT_INCOMPLETED) {
					mtcp_SSL *ssl = sv->ssl;
					ret = AcceptSSL(ctx, ssl, events[i].data.sockid);
					if (ret == FAIL) {
						fprintf(stderr, "Error in AcceptSSL\n");
						exit(EXIT_FAILURE);
					}
					else {
						sv->state = ret;
					}
				}
				else if (sv->state == SSL_ACCEPT_COMPLETED) {
					if (sv->rspheader_sent) {
						SendUntilAvailable(ctx, events[i].data.sockid, sv);
					} else {
						int sent;
						int err;
						sent = mtcp_SSL_write(sv->ssl, sv->rspheader, sv->rspheader_len);
						if (sent == FAIL) {
							err = mtcp_SSL_get_error(sv->ssl, sent);
							if (err == mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE) {
								TRACE_APP("Connection closed with client.\n");
							}
							else if (err == mtcp_SSL_ERROR_WANT_WRITE) {
								struct mtcp_epoll_event ev;
								ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
								ev.data.sockid = events[i].data.sockid;
								mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, events[i].data.sockid, &ev);
							}
							else if (err == mtcp_SSL_ERROR_WANT_READ) {
								fprintf(stderr, "Cannot be happened\n");
							}
							else {
								fprintf(stderr, "[RunServerContext] Error num: %d\n", err);
								exit(EXIT_FAILURE);
							}
						}
					}
				}
				else {
					/* fprintf(stderr, "Invalid State\n"); */
				}

			} else {
				assert(0);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (1) {
				ret = AcceptConnection(ctx, listener);
				if (ret < 0)
					break;
			}
		}

	}

}

void
DestroyThreadContext(struct thread_context *ctx)
{
	int j;

	if (ctx->svars) {
		for (j = 0; j < MAX_FLOW_NUM; j++) {
			if (ctx->svars[j].ssl)
				mtcp_SSL_free(ctx->svars[j].ssl);
		}

		free(ctx->svars);
	}	

	free(ctx->ssl_ctx);

	mtcp_destroy_context(ctx->mctx);

	return;
}

void *
RunServerThread(void *arg)
{
	int core = *(int *)arg;
	struct thread_context *ctx;
	mctx_t mctx;
	
	/* initialization */
	ctx = InitializeServerThread(core);
	if (!ctx) {
		TRACE_ERROR("Failed to initialize server thread.\n");
		return NULL;
	}

	mctx = ctx->mctx;
#ifdef ENABLE_UCTX
	mtcp_create_app_context(mctx, (mtcp_app_func_t) RunServerContext, (void *) ctx);
	mtcp_run_app();
#else /* ENABLE_UCTX */
	RunServerContext(ctx);
#endif /* !ENABLE_UCTX */

	/* destroy mtcp context: this will kill the mtcp thread */
	DestroyThreadContext(ctx);
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		if (app_thread[i] == pthread_self()) {
			//TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		} else {
			if (!done[i]) {
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
static void
printHelp(const char *prog_name)
{
	TRACE_CONFIG("%s -p <path_to_www/> -f <mtcp_conf_file> "
		     "[-N num_cores] [-c <per-process core_id>] [-h]\n",
		     prog_name);
	exit(EXIT_SUCCESS);
}

void
foo(char *filename, char *passwd)
{
	BIO *key;
	RSA *rsa;
	OpenSSL_add_all_algorithms();

	key = BIO_new(BIO_s_file());
	BIO_read_filename(key, filename);
	rsa = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, (void *)passwd);

	UNUSED(rsa);
	return;
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	DIR *dir;
	struct dirent *ent;
	int fd;
	int ret;
	uint64_t total_read;
	struct mtcp_conf mcfg;
	int cores[MAX_CPUS];
	int process_cpu;
	int i, o;

	const char* original_key_file = 
		"/home/duckwoo/smartnic/branches/mtcp_ssl_offload/mtcp/apps/tls_server/cert/rsa_cert_2048.pem";
	const char* original_key_passwd = "1234";

	num_cores = GetNumCPUs();
	core_limit = num_cores;
	process_cpu = -1;
	dir = NULL;

	if (argc < 2) {
		TRACE_CONFIG("$%s directory_to_service\n", argv[0]);
		return FALSE;
	}

	while (-1 != (o = getopt(argc, argv, "N:f:p:c:b:h"))) {
		switch (o) {
		case 'p':
			/* open the directory to serve */
			www_main = optarg;
			dir = opendir(www_main);
			if (!dir) {
				TRACE_CONFIG("Failed to open %s.\n", www_main);
				perror("opendir");
				return FALSE;
			}
			break;
		case 'N':
			core_limit = mystrtol(optarg, 10);
			if (core_limit > num_cores) {
				TRACE_CONFIG("CPU limit should be smaller than the "
					     "number of CPUs: %d\n", num_cores);
				return FALSE;
			}
			/** 
			 * it is important that core limit is set 
			 * before mtcp_init() is called. You can
			 * not set core_limit after mtcp_init()
			 */
			mtcp_getconf(&mcfg);
			mcfg.num_cores = core_limit;
			mtcp_setconf(&mcfg);
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 'c':
			process_cpu = mystrtol(optarg, 10);
			if (process_cpu > core_limit) {
				TRACE_CONFIG("Starting CPU is way off limits!\n");
				return FALSE;
			}
			break;
		case 'b':
			backlog = mystrtol(optarg, 10);
			break;
		case 'h':
			printHelp(argv[0]);
			break;
		}
	}
	
	if (dir == NULL) {
		TRACE_CONFIG("You did not pass a valid www_path!\n");
		exit(EXIT_FAILURE);
	}

	nfiles = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0)
			continue;
		else if (strcmp(ent->d_name, "..") == 0)
			continue;

		snprintf(fcache[nfiles].name, NAME_LIMIT, "%s", ent->d_name);
		snprintf(fcache[nfiles].fullname, FULLNAME_LIMIT, "%s/%s",
			 www_main, ent->d_name);
		fd = open(fcache[nfiles].fullname, O_RDONLY);
		if (fd < 0) {
			perror("open");
			continue;
		} else {
			fcache[nfiles].size = lseek64(fd, 0, SEEK_END);
			lseek64(fd, 0, SEEK_SET);
		}

		fcache[nfiles].file = (char *)malloc(fcache[nfiles].size);
		if (!fcache[nfiles].file) {
			TRACE_CONFIG("Failed to allocate memory for file %s\n", 
				     fcache[nfiles].name);
			perror("malloc");
			continue;
		}

		TRACE_INFO("Reading %s (%lu bytes)\n", 
				fcache[nfiles].name, fcache[nfiles].size);
		total_read = 0;
		while (1) {
			ret = read(fd, fcache[nfiles].file + total_read, 
					fcache[nfiles].size - total_read);
			if (ret < 0) {
				break;
			} else if (ret == 0) {
				break;
			}
			total_read += ret;
		}
		if (total_read < fcache[nfiles].size) {
			free(fcache[nfiles].file);
			continue;
		}
		close(fd);
		nfiles++;

		if (nfiles >= MAX_FILES)
			break;
	}

	finished = 0;

	/* initialize mtcp */
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}

	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	mtcp_getconf(&mcfg);
	if (backlog > mcfg.max_concurrency) {
		TRACE_CONFIG("backlog can not be set larger than CONFIG.max_concurrency\n");
		return FALSE;
	}

	/* if backlog is not specified, set it to 4K */
	if (backlog == -1) {
		backlog = 4096;
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);

	TRACE_INFO("Application initialization finished.\n");

	/* load certificate & key */
	option.key_file = (char *)calloc(1, strlen(original_key_file));
	option.key_passwd = (char *)calloc(1, strlen(original_key_passwd));
	strncpy(option.key_file, original_key_file,
		strlen(original_key_file));
	strncpy(option.key_passwd, original_key_passwd,
		strlen(original_key_passwd));

	for (i = 0; i < core_limit; i++) {
		if (cert_load_key(&public_crypto_ctx[i]) < 0) {
			fprintf(stderr, "cert_load_key fail\n");
		}
	}

	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		cores[i] = i;
		done[i] = FALSE;
		
		if (pthread_create(&app_thread[i], 
				   NULL, RunServerThread, (void *)&cores[i])) {
			perror("pthread_create");
			TRACE_CONFIG("Failed to create server thread.\n");
				exit(EXIT_FAILURE);
		}
		if (process_cpu != -1)
			break;
	}
	
	fprintf(stderr, "process_cpu = %d, core_limit = %d\n", process_cpu, core_limit);

	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		fprintf(stderr, "i = %d\n", i);
		pthread_join(app_thread[i], NULL);

		if (process_cpu != -1)
			break;
	}
	
	fprintf(stderr, "end\n");
	mtcp_destroy();
	closedir(dir);
	return 0;
}
