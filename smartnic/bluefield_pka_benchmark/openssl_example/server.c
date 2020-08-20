//SSL-Server.c
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <resolv.h>
#include <signal.h>
#include <sys/time.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/engine.h"
#include "include/server.h"

#include <sched.h>

enum {
	SSL_UNUSED = 0,
	SSL_ACCEPT_INCOMPLETED,
	SSL_ACCEPT_COMPLETED,
};

struct ssl_info {
	SSL *ssl;
	uint16_t worker_id;
	uint16_t state;
};

SSL_CTX **g_ctx_arr;
char addr[MAX_ADDR_LEN + 1];
int port;
int thread_num;
size_t conn_cnt[MAX_THREAD_NUM];

struct ssl_info ssl_map[MAX_FD_NUM];

/*-----------------------------------------------------------------------------*/
void
Usage()
{
	printf("Usage: ./ssl-server -a [ip address] -p [port]\n -t [thread num]");
	exit(0);
}
/*-----------------------------------------------------------------------------*/
#if USE_PKA_ENGINE
int
InitializePkaEngine()
{
	ENGINE *e;
	const char *engine_id = "pka";
	ENGINE_load_builtin_engines();
	e = ENGINE_by_id(engine_id);
	if(!e)
		/* the engine isn't available */
		return FAIL;
	if(!ENGINE_init(e)) {
		/* the engine couldn't initialise, release 'e' */
		ENGINE_free(e);
		return FAIL;
	}
	if(!ENGINE_set_default_RSA(e))
		/*   /\* This should only happen when 'e' can't initialise, but the previous */
		/*    * statement suggests it did. *\/ */
		abort();

	/* ENGINE_set_default_DSA(e); */
	/* ENGINE_set_default_ciphers(e); */
	/* Release the functional reference from ENGINE_init() */
	ENGINE_finish(e);
	/* Release the structural reference from ENGINE_by_id() */
	ENGINE_free(e);

	return 0;
}
#endif
/*-----------------------------------------------------------------------------*/
void
InitializeSSLContext()
{
#if !USE_PKA_ENGINE
	int i;
#endif

	SSL_library_init();
	if((g_ctx_arr = (SSL_CTX**)calloc(thread_num, sizeof(SSL_CTX*))) == NULL) {
		perror("can't allocate SSL_CTX\n");
		exit(0);
	}

#if !USE_PKA_ENGINE
	for(i = 0; i < thread_num; i++) {
		g_ctx_arr[i] = InitServerCTX();
		LoadCertificates(g_ctx_arr[i], "mycert.pem", "mycert.pem");
	}
#endif
}
/*-----------------------------------------------------------------------------*/
int
OpenListener(char *addr, int port, int thread_idx)
{ 
	int sd;
	int optval = 1;
	struct sockaddr_in sockaddr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	bzero(&sockaddr, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port /* + thread_idx */);
	printf("port = %d\n", ntohs(sockaddr.sin_port));
	sockaddr.sin_addr.s_addr = inet_addr(addr);
	if ( bind(sd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) != 0 )
		{
			perror("can't bind port");
			abort();
		}
	if ( listen(sd, 10) != 0 )
		{
			perror("Can't configure listening port");
			abort();
		}
	return sd;
}
/*-----------------------------------------------------------------------------*/
int
isRoot()
{
	if (getuid() != 0)
		{
			return 0;
		}
	else
		{
			return 1;
		}

}
/*-----------------------------------------------------------------------------*/
SSL_CTX*
InitServerCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLSv1_2_server_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		printf("initserverCTX: error\n");
		ERR_print_errors_fp(stderr);
		abort();
	}

	return ctx;
}
/*-----------------------------------------------------------------------------*/
void
LoadCertificates(SSL_CTX* ctx , char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
		printf("LoadCertificates: error\n");
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
		printf("LoadCertificates: error\n");
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if(!SSL_CTX_check_private_key(ctx))	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}
/*-----------------------------------------------------------------------------*/
void
ShowCerts(SSL* ssl)
{   X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if(cert != NULL) {
		/* printf("Server certificates:\n"); */
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		/* printf("Subject: %s\n", line); */
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		/* printf("Issuer: %s\n", line); */
		free(line);
		X509_free(cert);
	}
	/* else */
	/*   printf("No certificates.\n"); */
}
/*-----------------------------------------------------------------------------*/
int
AcceptSSL(SSL* ssl) /* Serve the connection -- threadable */
{
	int accept_ret, accept_err_num;

	if((accept_ret = SSL_accept(ssl)) == FAIL) {     /* do SSL-protocol accept */
		/* printf("accept...incomplete\n"); */
		accept_err_num = SSL_get_error(ssl, accept_ret);
		if(accept_err_num == SSL_ERROR_WANT_READ
		   || accept_err_num == SSL_ERROR_WANT_WRITE) {
			return SSL_ACCEPT_INCOMPLETED;
		} else {
			printf("AcceptSSL: error1\n");
			ERR_print_errors_fp(stderr);
			return FAIL;
		}
	} 
	
	/* printf("accept...complete!\n"); */
	return SSL_ACCEPT_COMPLETED;
}
/*-----------------------------------------------------------------------------*/
int
Servlet(SSL *ssl) {
	char buf[1024];
	char reply[1024];
	int sd, bytes;
	const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

	/* printf("servlet...\n"); */

	ShowCerts(ssl);
	bytes = SSL_read(ssl, buf, sizeof(buf));
	if(bytes > 0) {
		buf[bytes] = 0;
		/* printf("thread %u, Client msg: \"%s\"\n", (int)pthread_self(), buf); */
		sprintf(reply, HTMLecho, buf);
		SSL_write(ssl, reply, strlen(reply));
	}
	else{
		ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);
	close(sd);
	return SUCCESS;
}
/*-----------------------------------------------------------------------------*/
void
PrintStatistics(int signum)
{
	int i;
	size_t conn_total_cnt = 0;

	printf("\n----------------------------------\n");
	for(i = 0; i < thread_num; i++) {
		printf("[THREAD %d]: %lu\n", i, conn_cnt[i]);
		conn_total_cnt += conn_cnt[i];
		conn_cnt[i] = 0;
	}
	printf("[TOTAL]: %lu\n", conn_total_cnt);

	alarm(1);
}
/*-----------------------------------------------------------------------------*/
void *
worker(void *arg)
{
	/* UNUSED(arg); */

	int worker_id = *(int*)arg;
	int listenfd, epollfd;
	struct epoll_event ev, *events;
	SSL_CTX *ctx;
	int event_num;
	const size_t EPOLL_SIZE = 100000;

	struct sockaddr_in recv_addr;
	socklen_t len = sizeof(addr);

	int i;
	/* printf("*arg = %d\n", *(int*)arg); */

#if USE_PKA_ENGINE
	if(worker_id == 0) {
		if (InitializePkaEngine() == FAIL) {
			fprintf(stderr, "Error: pka engine load failed\n");
			exit(0);
		}
	}
	g_ctx_arr[worker_id] = InitServerCTX();
	LoadCertificates(g_ctx_arr[worker_id], "mycert.pem", "mycert.pem");
	printf("PKA initialize completed\n");
#endif
	ctx = g_ctx_arr[worker_id];

	/* initialize epoll events */
	events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EPOLL_SIZE);
	if((epollfd = epoll_create(EPOLL_SIZE)) == -1) {
		return NULL;
	}

	/* listen and add listening socket fd into epoll fd */
	listenfd = OpenListener(addr, port, worker_id);
	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev);

	/* main loop */
	while(1) {
		event_num = epoll_wait(epollfd, events, EPOLL_SIZE, 0);
		if(event_num < 0) {
			perror("epoll_wait\n");
			break;
		}
		for(i = 0; i < event_num; i++) {
			/* listening socket */
			if(events[i].data.fd == listenfd) {
				int clientfd = accept(listenfd, (struct sockaddr*)&recv_addr, &len);
				struct epoll_event ev_client;
				
				ssl_map[clientfd].worker_id = worker_id;
				ssl_map[clientfd].state = SSL_UNUSED;

				fcntl(clientfd, F_SETFL, O_NONBLOCK);
				ev_client.events = EPOLLIN;
				ev_client.data.fd = clientfd;
				epoll_ctl(epollfd, EPOLL_CTL_ADD, clientfd, &ev_client);
			} else if(events[i].events & EPOLLIN) {
				if(worker_id != ssl_map[events[i].data.fd].worker_id) {
					fprintf(stderr, "Error: not thread safe\n");
					fprintf(stderr, "worker_id, ssl_map[clientfd].worker_id = %d, %d\n", worker_id, ssl_map[events[i].data.fd].worker_id);
					exit(0);
				}

				/* start SSL handshake */
				if(ssl_map[events[i].data.fd].state == SSL_UNUSED) {
					/* get new SSL state with context */
					SSL *ssl;
					if((ssl = SSL_new(ctx)) == NULL) {
						fprintf(stderr, "Error: ssl state create failed\n");
						exit(0);
					}
					SSL_set_fd(ssl, events[i].data.fd);      /* set connection socket to SSL state */
					if(AcceptSSL(ssl) == FAIL) {
						fprintf(stderr, "Error: can't SSL_accept\n");
						close(events[i].data.fd);
						SSL_free(ssl);
						ssl_map[events[i].data.fd].state = SSL_UNUSED;

						continue;
					}

					/* add new ssl_info into ssl_map */
					struct ssl_info ssl_info;
					ssl_info.ssl = ssl;
					ssl_info.worker_id = worker_id;
					ssl_info.state = SSL_ACCEPT_INCOMPLETED;
					ssl_map[events[i].data.fd] = ssl_info;
				}

				/* continue SSL handshake */
				else if(ssl_map[events[i].data.fd].state == SSL_ACCEPT_INCOMPLETED) {
					static int accept_ret;
					SSL *ssl;
					ssl = ssl_map[events[i].data.fd].ssl;

					if((accept_ret = AcceptSSL(ssl)) == FAIL) {
						fprintf(stderr, "Error: can't SSL_accept\n");
						close(events[i].data.fd);
						SSL_free(ssl);
						ssl_map[events[i].data.fd].state = SSL_UNUSED;

						continue;
					}
					ssl_map[events[i].data.fd].state = accept_ret;
				}

				/* receive encrypted data, reply, and end the connection */
				else if(ssl_map[events[i].data.fd].state == SSL_ACCEPT_COMPLETED) {
					SSL *ssl;
					ssl = ssl_map[events[i].data.fd].ssl;

					Servlet(ssl);
					SSL_free(ssl);         /* release SSL state */

					ssl_map[events[i].data.fd].state = SSL_UNUSED;

					/* one connection established and closed successfully */
					conn_cnt[worker_id]++;
				}
			}
		}
	}
	close(listenfd);          /* close server socket */
	SSL_CTX_free(ctx);         /* release context */

	return NULL;
}
/*-----------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	pthread_t p_thread[MAX_THREAD_NUM];
	pthread_attr_t attr[MAX_THREAD_NUM];
	int tid[MAX_THREAD_NUM];

	cpu_set_t *cpusetp[MAX_THREAD_NUM];
	int cpu_size;

	int i, c;

	if(!isRoot())
		{
			printf("This program must be run as root/sudo user!!");
			exit(0);
		}

	/* initialize default option */
	thread_num = 1;
	memcpy(addr, "localhost", 10);
	port = 4888;

	/* parse options */
	while ((c = getopt(argc, argv, "a:p:t:h")) != -1) {
		if (c == 'a') {
			if (strlen(optarg) > MAX_ADDR_LEN) {
				fprintf(stderr, "error: invalid ip address\n");
				exit(0);
			}
			memcpy(addr, optarg, strlen(optarg));
			addr[strlen(optarg)] = '\0';
		} else if (c == 'p') {
			port = atoi(optarg);
		} else if (c == 't') {
			thread_num = atoi(optarg);
			if(thread_num < 1) {
				fprintf(stderr, "Error: thread_num should be more than 0\n");
				exit(0);
			} else if (thread_num > MAX_THREAD_NUM) {
				fprintf(stderr, "Error: thread_num should be less than %d\n", MAX_THREAD_NUM);
				exit(0);
			}
		} else if (c == 'n') {
			Usage();
		} else {
			Usage();
		}
	}

	/* extend limit of available file descriptor number */
	const struct rlimit rlp = {MAX_FD_NUM, MAX_FD_NUM};
	struct rlimit rlp_copy;
	setrlimit(RLIMIT_NOFILE, &rlp);
	getrlimit(RLIMIT_NOFILE, &rlp_copy);
	printf("file descriptor limit: %lu : %lu\n", rlp_copy.rlim_cur, rlp_copy.rlim_max);

	/* initialize SSL ctx */
	InitializeSSLContext();

	/* create threads */  
	for(i = 0; i < thread_num; i++) {
		/* set core */
		if((cpusetp[i] = CPU_ALLOC(thread_num)) == NULL) {
			fprintf(stderr, "Error: cpu_set initialize failed\n");
			exit(0);
		}
		cpu_size = CPU_ALLOC_SIZE(thread_num);
		CPU_ZERO_S(cpu_size, cpusetp[i]);
		CPU_SET_S(i, cpu_size, cpusetp[i]);

		/* set thread attribute (core pinning) */
		if(pthread_attr_init(&attr[i]) != 0) {
			fprintf(stderr, "Error: thread attribute initialize failed\n");
			exit(0);
		}
		pthread_attr_setaffinity_np(&attr[i], cpu_size, cpusetp[i]);

		/* create thread */
		tid[i] = i;
		conn_cnt[i] = 0;
		/* if(pthread_create(&p_thread[i], &attr[i], worker, (void *)&tid[i]) < 0) { */
		if(pthread_create(&p_thread[i], NULL, worker, (void *)&tid[i]) < 0) {
			fprintf(stderr, "Error: thread create failed\n");
			exit(0);
		}
		printf("test4\n");
	}

	/* turn on the alarm for monitoring */
	signal(SIGALRM, PrintStatistics);
	alarm(2);
	while(1) {
		sleep(1);
	}

	/* wait threads */
	for(i = 0; i < thread_num; i++) {
		pthread_join(p_thread[i], NULL);
		CPU_FREE(cpusetp[i]);
	}

	for(i = 0; i < thread_num; i++) {
		SSL_CTX_free(g_ctx_arr[i]);         /* release context */
	}
	free(g_ctx_arr);

	return 0;
}
