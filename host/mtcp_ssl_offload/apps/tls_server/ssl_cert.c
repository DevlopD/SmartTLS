#include <unistd.h>
#include "ssl_cert.h"

option_t option;

static int
load_certificate(const char *infile, const char* password,
                            char* certificate, int max_len)
{
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    X509 *x = NULL;
    BIO *cert;
    char password_[1024];
    strncpy(password_, password, 1024);

    /* Allocate BIO */
    if ((cert=BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(bio_err);
        return -1;
    }

    /* Load certificate to cert */
    if (BIO_read_filename(cert, infile) <= 0) {
        BIO_printf(bio_err, "Error opening %s %s\n",
                   "Certificate", infile);
        ERR_print_errors(bio_err);
        return -1;
    }

    /* Read Certificate in PEM Format */
    x = PEM_read_bio_X509(cert, NULL, NULL, password_);
    if (x == NULL) {
        fprintf(stderr, "Certificate is Null, file: %s, passwd: %s\n",
                        infile, password_);
        exit(EXIT_FAILURE);
    }

    /* Encode the Certificate */
    int len = i2d_X509(x, NULL);
    unsigned char *m = (unsigned char *)OPENSSL_malloc(len);
    unsigned char *d;
    d = (unsigned char *)m;
    if (!d) {
        fprintf(stderr, "Memory allocation for certificate failed\n");
        exit(EXIT_FAILURE);
    }

    len = i2d_X509(x, &d);
    if (len <= 0) {
        fprintf(stderr, "Wrong Certificate\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "certificate len: %d\n", len);
    d = (unsigned char *)m;

    assert(len <= max_len);
    memcpy(certificate, m, len);

    OPENSSL_free(m);
    X509_free(x);
    BIO_free(cert);
    BIO_free(bio_err);

    return len;
}

static void
set_crt(RSA *rsa)
{
    uint8_t crt_available;
#if (OPENSSL_VERSION_NUMBER >= 0x10100010L) 
    crt_available = (
					 RSA_get0_p(rsa) != NULL &&
					 RSA_get0_q(rsa) != NULL &&
					 RSA_get0_dmp1(rsa) != NULL &&
					 RSA_get0_dmq1(rsa) != NULL &&
					 RSA_get0_iqmp(rsa) != NULL
					 );
#elif (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	/* ToDo: conform rsa structure in Openssl 1.1.0 */
	crt_available = 1;
#else
    crt_available = (
					 rsa->p != NULL &&
					 rsa->q != NULL &&
					 rsa->dmp1 != NULL &&
					 rsa->dmq1 != NULL &&
					 rsa->iqmp != NULL
					 );
#endif
    if (!crt_available) {
        fprintf(stderr, "--------------------------------------------\n");
        fprintf(stderr, "Chinese remainder theorem is not applicable!\n");
        fprintf(stderr, "--------------------------------------------\n");
    }
}

static RSA *
rsa_load_key(char *filename, char *passwd)
{
    BIO *key;
    RSA *rsa;
    OpenSSL_add_all_algorithms();
	char cwd[100];

	getcwd(cwd, sizeof(cwd));
	SSL_load_error_strings();
    key = BIO_new(BIO_s_file());
    assert(key != NULL);
    assert(BIO_read_filename(key, filename) == 1);
	fprintf(stderr, "Reading key file %s in %s with password %s.\n", filename, cwd, passwd);
    rsa = PEM_read_bio_RSAPrivateKey(key, NULL, NULL, (void *)passwd);
    ERR_print_errors_fp(stderr);
    BIO_free(key);

    assert(rsa != NULL);
    set_crt(rsa);
    return rsa;
}

int
cert_load_key(mtcp_PUBLIC_CRYPTO_CTX* ctx)
{
    fprintf(stderr, "Loading RSA key\n");
    ctx->rsa = rsa_load_key(option.key_file, option.key_passwd);

    ctx->certificate_length = load_certificate(option.key_file,
                                               option.key_passwd,
                                               (char *)ctx->certificate,
                                               MAX_CERTIFICATE_LENGTH);
    if (ctx->certificate_length <= 0)
        return -1;

    if (!ctx->rsa) {
        fprintf(stderr, "rsa_load_key failed.\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}
