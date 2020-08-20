#ifndef SERVER_H
#define SERVER_H

#define FAIL             -1
#define SUCCESS          1
#define UNUSED(x) (void)(x)

#define USE_PKA_ENGINE   0

#define MAX_ADDR_LEN 20
#define MAX_THREAD_NUM 16
#define MAX_FD_NUM 1024

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#if USE_PKA_ENGINE
int InitializePkaEngine();
#endif

void InitializeSSLContext();

int OpenListener(char *addr, int port, int thread_idx);

int isRoot();

SSL_CTX* InitServerCTX();

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);

void ShowCerts(SSL* ssl);

int AcceptSSL(SSL* ssl);

int Servlet(SSL* ssl);

#endif	/* SERVER_H */
