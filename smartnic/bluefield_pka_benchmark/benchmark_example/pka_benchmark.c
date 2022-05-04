#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include <pka.h>
#include <pka_utils.h>
/* #include <pka_vectors.h> */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#include "helper/pka_helper.h"

#define PKA_MAX_RING_CNT 16
#define PKA_MAX_QUEUE_CNT 16
#define PKA_MAX_OBJS 32
#define CMD_QUEUE_SIZE (1 << 14) * PKA_MAX_OBJS
#define RSLT_QUEUE_SIZE (1 << 12) * PKA_MAX_OBJS

#define MAX_THREAD_NUM 15

#define UNUSED(x) (void)(x)
#define DBG_MODE 0

/*---------------------------------------------------------------------------------------*/
// eclipse function parameter for ECC
// All of the following constants are in big-endian format.

//static char P256_p_string[] =
//    "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//    "ffffffff ffffffff";
static uint8_t P256_p_buf[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

//static char P256_a_string[] =
//    "ffffffff 00000001 00000000 00000000 00000000 ffffffff"
//    "ffffffff fffffffc";
static uint8_t P256_a_buf[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

//static char P256_b_string[] =
//    "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6"
//    "3bce3c3e 27d2604b";
static uint8_t P256_b_buf[] = {
	0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
	0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
	0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
	0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

// Base_pt:
//static char P256_xg_string[] =
//    "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0"
//    "f4a13945 d898c296";
static uint8_t P256_xg_buf[] = {
	0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
	0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
	0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
	0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};

//static char P256_yg_string[] =
//    "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece"
//    "cbb64068 37bf51f5";
static uint8_t P256_yg_buf[] = {
	0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
	0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
	0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
	0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

static uint8_t HEX_CHARS[] = "0123456789ABCDEF";
static uint8_t FROM_HEX[256] = {
	['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,
	['5'] = 5,  ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
	['a'] = 10, ['b'] = 11, ['c'] = 12, ['d']  = 13, ['e'] = 14, ['f'] = 15,
	['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15
};

/*---------------------------------------------------------------------------------------*/
/* RSA specific variables
 *
 * p, q: two prime numbers to make a key pair
 * dmp1, dmpq1, iqmp: values for CRT, conducted from p, q
 * n: modulus
 * e: exponent(public key)
 * d: exponent(private key)                                 */
EVP_PKEY *rsa_private_key;
pka_operand_t *p, *q, *d_p, *d_q, *qinv;
pka_operand_t *rsa_encrypt_key, *rsa_decrypt_key, *rsa_modulus, *rsa_ciphertext;
pka_instance_t instance;

/* EC specific variables
 * 
 * a, b, p: parameter of elliptic curve
 * ec_private_key: a big prime number k, less than P
 * x, y: public_key K = (x, y) = k*G, where G is well-known starting point on the graph
 * ec_P256_base_pt: G
 * note: multiply and add operation in ECC are totally different with regular ones */
ecc_curve_t *ec_curve;
pka_operand_t *ec_private_key;
ecc_point_t *ec_public_key;
pka_operand_t *ec_private_key_2; /* the other side of key pair in diffie-hellman */
ecc_point_t *ec_public_key_2;
pka_operand_t *x, *y;
pka_operand_t *x_2, *y_2;
ecc_point_t *ec_P256_base_pt;

/*---------------------------------------------------------------------------------------*/
/* other global variables */
enum {RSA_DECRYPTION = 0, ECDH};
int operation_mode = 0;
int cpu_num = 1;
int thread_num = 1;
int ring_num = 4;
int outstanding_cmd_num = 4;
int cmd_cnt_per_thread = 20000;

int work_done = 0;
#if DBG_MODE
BIO *out;
#endif

size_t cmd_cnt[MAX_THREAD_NUM];

static pka_barrier_t thread_start_barrier;
/* __thread int MAX_CNT = 20000; */
/* __thread int max_cmd_cnt = 20000; */

/*---------------------------------------------------------------------------------------*/
void
usage()
{
	printf("usage: ./pka_benchmark -m [mode] -t [thread_num] -r [ring_num] -o [outstanding_cmd_num] -n [command_num_per_thread]\n");
	printf("mode\n  0: RSA_DECRYPTION\n  1: ECDH\n");
}

/*---------------------------------------------------------------------------------------*/
int
from_hex_string(char *hex_string, pka_operand_t *value)
{
    uint32_t string_len, hexDigitCnt, char_idx, byte_len, hexDigitState;
    uint32_t hex_value, hex_value1 = 0;
    uint8_t *big_num_ptr, ch, big_endian, byte_value;

    // Skip the initial 0x, if present
    string_len = strlen(hex_string);
    if ((3 <= string_len) && (hex_string[0] == '0') &&
        (hex_string[1] == 'x'))
		{
			hex_string += 2;
			string_len -= 2;
		}

	/* fprintf(stderr, "from_hex_string: debug 0\n"); */

    // Next count the number of hexadecimal characters in the string (i.e.
    // ignoring things like spaces and underscores).
    hexDigitCnt = 0;
    for (char_idx = 0;  char_idx < string_len;  char_idx++)	{
		ch = hex_string[char_idx];
		if (isxdigit(ch))
			hexDigitCnt++;
		else if ((! isspace(ch)) && (ch != '_')) {
			return -1;
		}
	}

    byte_len = (hexDigitCnt + 1) / 2;
    if (value->buf_ptr == NULL)	{
		value->buf_ptr = malloc(byte_len);
		value->buf_len = byte_len;
	} else if (value->buf_len < byte_len) {
        return -1;
	}

    value->actual_len   = byte_len;
    value->is_encrypted = 0;
    big_endian          = value->big_endian;
    if (big_endian)
        big_num_ptr = &value->buf_ptr[0];
    else
        big_num_ptr = &value->buf_ptr[byte_len - 1];

    hexDigitState = 0;
    hex_value1    = 0;
    if ((hexDigitCnt & 0x1) != 0)
        hexDigitState = 1;

    for (char_idx = 0;  char_idx < string_len;  char_idx++)	{
		ch = hex_string[char_idx];
		if (isxdigit(ch)) {
			hex_value = FROM_HEX[ch];
			if (hexDigitState == 0)	{
				hex_value1    = hex_value;
				hexDigitState = 1;
			}
			else {
				byte_value    = (hex_value1 << 4) | hex_value;
				hexDigitState = 0;
				if (big_endian)
					*big_num_ptr++ = byte_value;
				else
					*big_num_ptr-- = byte_value;
			}
		}
	}

    return 0;
}

/*---------------------------------------------------------------------------------------*/
int
to_hex_string(pka_operand_t *value,
			  char          *string_buf,
			  uint32_t       buf_len)
{
    uint32_t byte_len, byte_cnt, byte_value;
    uint8_t *byte_ptr;
    char    *char_ptr;

    byte_len = value->actual_len;
    if (buf_len <= byte_len)
        return -1;

    memset(string_buf, 0, buf_len);

    if (value->big_endian) {
		byte_ptr = &value->buf_ptr[0];
		char_ptr = &string_buf[0];
		for (byte_cnt = 0;  byte_cnt < byte_len;  byte_cnt++) {
			byte_value  = *byte_ptr++;
			*char_ptr++ = HEX_CHARS[byte_value >> 4];
			*char_ptr++ = HEX_CHARS[byte_value & 0x0F];
		}
	}
    else {
		byte_ptr = &value->buf_ptr[byte_len - 1];
		char_ptr = &string_buf[0];
		for (byte_cnt = 0;  byte_cnt < byte_len;  byte_cnt++) {
			byte_value  = *byte_ptr--;
			*char_ptr++ = HEX_CHARS[byte_value >> 4];
			*char_ptr++ = HEX_CHARS[byte_value & 0x0F];
		}
	}

    return 0;
}

/*---------------------------------------------------------------------------------------*/
int
GetRSAKeyPair(char *pem_filename)
{
	FILE *fp_pem;
	RSA *rsa;

	if((fp_pem = fopen(pem_filename, "r")) == NULL) {
		perror("fopen");
		exit(0);
	}

	/* debug */
	fprintf(stderr, "check1\n");

	rsa_private_key = PEM_read_PrivateKey(fp_pem, NULL, NULL, NULL);

	/* debug */
	fprintf(stderr, "check2\n");

	if(rsa_private_key == NULL || rsa_private_key->pkey.rsa == NULL) {
		perror("PEM_READ");
		exit(0);
	}

	/* debug */
	fprintf(stderr, "check3\n");

	fclose(fp_pem);

	rsa = rsa_private_key->pkey.rsa;

	if (rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 && rsa->iqmp) {
#if DBG_MODE
		printf("p: ");
		BN_print(out, rsa->p);
		printf("\nq: ");
		BN_print(out, rsa->q);
		printf("\ndmp1: ");
		BN_print(out, rsa->dmp1);
		printf("\ndmq1: ");
		BN_print(out, rsa->dmq1);
		printf("\niqmp: ");
		BN_print(out, rsa->iqmp);
		printf("\n");
#endif
		p = bignum_to_operand((pka_bignum_t *)rsa->p);
		q = bignum_to_operand((pka_bignum_t *)rsa->q);
		d_p = bignum_to_operand((pka_bignum_t *)rsa->dmp1);
		d_q = bignum_to_operand((pka_bignum_t *)rsa->dmq1);
		qinv = bignum_to_operand((pka_bignum_t *)rsa->iqmp);

	} 
	if (rsa->d) {
#if DBG_MODE
		printf("\nd: ");
		BN_print(out, rsa->d);
		printf("\nn: ");
		BN_print(out, rsa->n);
		printf("\ne: ");
		BN_print(out, rsa->e);
		printf("\n");
#endif
		rsa_encrypt_key = bignum_to_operand((pka_bignum_t *)rsa->e);
		rsa_decrypt_key = bignum_to_operand((pka_bignum_t *)rsa->d);
		rsa_modulus = bignum_to_operand((pka_bignum_t *)rsa->n);
	}

#if DBG_MODE
	print_operand("rsa_encrypt_key = ", rsa_encrypt_key, "\n");
	print_operand("rsa_decrypt_key = ", rsa_decrypt_key, "\n");
	print_operand("rsa_modulus = ", rsa_modulus, "\n");
#endif


	return SUCCESS;
}

/*---------------------------------------------------------------------------------------*/
int
GetECCKeyPair()
{
	EC_KEY *ec_key, *ec_key_2;
	EC_GROUP *ec_group;
	const BIGNUM *ec_priv_key, *ec_priv_key_2;
    const EC_POINT *ec_pub_key, *ec_pub_key_2;
	BIGNUM *bn_x, *bn_y, *bn_x_2, *bn_y_2;

	/* generate EC key pair */
	/* note: do NOT use NID_secp256k1, because it is obsolate since TLS 1.3 */
	if((ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) { /* secp256r1 */
		perror("EC_GROUP_new_by_curve_name:");
		exit(0);
	}
	if((ec_key = EC_KEY_new()) == NULL) { /* secp256r1 */
		perror("EC_KEY_new:");
		exit(0);
	}
    EC_KEY_set_group(ec_key, ec_group);
	if(EC_KEY_generate_key(ec_key) != 1) {
		perror("EC_KEY_generate_key:");
		exit(0);
	}
	if((ec_key_2 = EC_KEY_new()) == NULL) { /* secp256r1 */
		perror("EC_KEY_new:");
		exit(0);
	}
    EC_KEY_set_group(ec_key_2, ec_group);
	if(EC_KEY_generate_key(ec_key_2) != 1) {
		perror("EC_KEY_generate_key:");
		exit(0);
	}

	/* extract priv key */
	ec_priv_key = EC_KEY_get0_private_key(ec_key);
	ec_priv_key_2 = EC_KEY_get0_private_key(ec_key_2);

	/* extract pub key */
	bn_x = BN_new();
	bn_y = BN_new();
	ec_pub_key = EC_KEY_get0_public_key(ec_key);
	if((EC_POINT_get_affine_coordinates_GFp(ec_group, ec_pub_key, bn_x, bn_y, NULL)) == 0) {
		perror("EC_POINT_get_affine_coordinates_GFp:");
		exit(0);
	}
	bn_x_2 = BN_new();
	bn_y_2 = BN_new();
	ec_pub_key_2 = EC_KEY_get0_public_key(ec_key_2);
	if((EC_POINT_get_affine_coordinates_GFp(ec_group, ec_pub_key_2, bn_x_2, bn_y_2, NULL)) == 0) {
		perror("EC_POINT_get_affine_coordinates_GFp:");
		exit(0);
	}

#if DBG_MODE
	printf("\nec_priv_key: ");
	BN_print(out, ec_priv_key);
	printf("ec_pub_key: \n");
	printf("X: ");
	BN_print(out, bn_x);
	printf("Y: ");
	BN_print(out, bn_y);
	printf("\n");

	printf("\nec_priv_key_2: ");
	BN_print(out, ec_priv_key_2);
	printf("\nec_pub_key_2: \n");
	printf("X: ");
	BN_print(out, bn_x_2);
	printf("Y: ");
	BN_print(out, bn_y_2);
	printf("\n");
#endif

	ec_private_key = bignum_to_operand((pka_bignum_t *)ec_priv_key);
	x = bignum_to_operand((pka_bignum_t *)bn_x);
	y = bignum_to_operand((pka_bignum_t *)bn_y);
	ec_private_key_2 = bignum_to_operand((pka_bignum_t *)ec_priv_key_2);
	x_2 = bignum_to_operand((pka_bignum_t *)bn_x_2);
	y_2 = bignum_to_operand((pka_bignum_t *)bn_y_2);

	/* allocate ecc point and curve */
	ec_curve = make_ecc_curve(P256_p_buf, sizeof(P256_p_buf),
							  P256_a_buf, sizeof(P256_a_buf),
							  P256_b_buf, sizeof(P256_b_buf),
							  1);
							  /* x->big_endian); */
    ec_P256_base_pt = make_ecc_point(ec_curve,
                                  P256_xg_buf, sizeof(P256_xg_buf),
                                  P256_yg_buf, sizeof(P256_yg_buf),
                                  1);
                                  /* x->big_endian); */
	ec_public_key = malloc_ecc_point(MAX_ECC_BUF, MAX_ECC_BUF, 1/* x->big_endian */);
	set_ecc_point(ec_public_key, x, y);
	ec_public_key_2 = malloc_ecc_point(MAX_ECC_BUF, MAX_ECC_BUF, 1/* x->big_endian */);
	set_ecc_point(ec_public_key_2, x_2, y_2);
#if DBG_MODE
	print_operand("ec_P256_base_pt.x = ", &ec_P256_base_pt->x, "\n");
	print_operand("ec_P256_base_pt.y = ", &ec_P256_base_pt->y, "\n");
	print_operand("ec_private_key = ", ec_private_key, "\n");
	print_operand("ec_public_key.x = ", &ec_public_key->x, "\n");
	print_operand("ec_public_key.y = ", &ec_public_key->y, "\n");
	print_operand("ec_private_key = ", ec_private_key_2, "\n");
	print_operand("ec_public_key_2.x = ", &ec_public_key_2->x, "\n");
	print_operand("ec_public_key_2.y = ", &ec_public_key_2->y, "\n");
#endif


	/* /\* debug *\/ exit(0); */
	/* EC_KEY_FREE(ec_key); */
	return SUCCESS;
}

/*---------------------------------------------------------------------------------------*/
pka_results_t *malloc_results(uint32_t result_cnt, uint32_t buf_len)
{
    pka_results_t *results;
    pka_operand_t *result_ptr;
    uint8_t        result_idx;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

    results = malloc(sizeof(pka_results_t));
    memset(results, 0, sizeof(pka_results_t));

    for (result_idx = 0; result_idx < result_cnt; result_idx++)
		{
			result_ptr             = &results->results[result_idx];
			result_ptr->buf_ptr    = malloc(buf_len);
			memset(result_ptr->buf_ptr, 0, buf_len);
			result_ptr->buf_len    = buf_len;
			result_ptr->actual_len = 0;
		}

    results->result_cnt = result_cnt;

    return results;
}

/*---------------------------------------------------------------------------------------*/
//*TBR*
void free_results_buf(pka_results_t *results)
{
    pka_operand_t *result_ptr;
    uint8_t        result_idx;

    for (result_idx = 0; result_idx < results->result_cnt; result_idx++)
		{
			result_ptr             = &results->results[result_idx];
			free(result_ptr->buf_ptr);
			result_ptr->buf_ptr    = NULL;
			result_ptr->buf_len    = 0;
			result_ptr->actual_len = 0;
		}
}

//*TBR*
void free_results(pka_results_t *results)
{
    if (results == NULL)
		{
			PKA_ERROR(PKA_TESTS,  "free_results called with NULL operand\n");
			return;
		}

    free_results_buf(results);
    free(results);
}


/*---------------------------------------------------------------------------------------*/
void
PrintStatistics(uint64_t interval)
{
    int i;
    /* static size_t prev_total_cmd_cnt = 0; */
	/* static size_t prev_cmd_cnt[MAX_THREAD_NUM] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; */
	static size_t prev_cmd_cnt[MAX_THREAD_NUM];
	size_t total_diff = 0;
	size_t diff;

    printf("\n----------------------------------\n");
    for(i = 0; i < thread_num; i++) {
        /* printf("[THREAD %d]: %lu\n", i + cpu_set_base, cmd_cnt[i] * 1000000 / interval); */
		diff = cmd_cnt[i] - prev_cmd_cnt[i];
        printf("[THREAD %d]: %lu\n", i, diff * 1000000 / interval);
        total_diff += diff;
		prev_cmd_cnt[i] = cmd_cnt[i];
    }
    printf("[TOTAL]: %lu\n", total_diff * 1000000 / interval);
}

/*---------------------------------------------------------------------------------------*/
void *
Printworker(void *arg)
{
	UNUSED(arg);
	uint64_t test_start_time, test_end_time;
	struct timeval g_timeval_start, g_timeval_end, timeval_start, timeval_end;
	int64_t interval;

	gettimeofday(&g_timeval_start, NULL);
	gettimeofday(&timeval_start, NULL);
	test_start_time = pka_cpu_cycles();

	while(!work_done) {
		gettimeofday(&timeval_end, NULL);
		interval = timeval_end.tv_usec - timeval_start.tv_usec
			+ (timeval_end.tv_sec - timeval_start.tv_sec)*1000000;
		if(interval > 1000000) {
			gettimeofday(&timeval_start, NULL);
			PrintStatistics(interval);
		}
	}
	
	/* print total time */
	test_end_time = pka_cpu_cycles();
	gettimeofday(&g_timeval_end, NULL);
	int cpu_frequency = pka_cpu_hz_max();
	printf("total latency: %lu usecs for %d RSA decryption\n"
		   , 1000000 * (test_end_time - test_start_time) / cpu_frequency
		   , cmd_cnt_per_thread * thread_num);
	printf("following to Linux timer, %f secs spent for %d RSA decryption\n"
		   , (float)(g_timeval_end.tv_usec - g_timeval_start.tv_usec)/1000000
    		 + (float)(g_timeval_end.tv_sec - g_timeval_start.tv_sec)
		   , cmd_cnt_per_thread * thread_num);

	return NULL;
}

/*---------------------------------------------------------------------------------------*/
void *
RSAworker(void *arg)
{
	/* UNUSED(arg); */
	char *plaintext = "0x112233445566778899101112131415161718192021222324252627282930313233343536373839404142434445464748"; /* 48 B */

	int worker_id = *(int*)arg;
	int max_cmd_cnt = cmd_cnt_per_thread;
	int cnt = 0;
	int cur_command_cnt = 0;
	pka_handle_t      handle;
	pka_results_t    *results;
	pka_operand_t    msg;
	uint32_t result_len;

#if DBG_MODE
	char result_buf[2][100];
	static __thread int cnt_correct = 0;
	result_buf[0][0] = result_buf[1][0] = '\0';
#endif
	static __thread int user_data[1000];

	/* wait for all worker ready */
	pka_barrier_wait(&thread_start_barrier);

	handle = pka_init_local(instance);  
	results = malloc_results(2, MAX_BYTE_LEN + 8);

	/* encrypt first */
	msg.buf_ptr = NULL;

	if(from_hex_string(plaintext, &msg) < 0) {
		perror("from_hex_string");
		exit(0);
	}

#if DBG_MODE
	printf("\n------------------encrypt----------------------\n");
	print_operand("encrypt_key = ", rsa_encrypt_key, "\n");
	print_operand("modulus = ", rsa_modulus, "\n");
	print_operand("msg = ", &msg, "\n\n");
#endif
	if(pka_modular_exp(handle, NULL, rsa_encrypt_key, rsa_modulus, &msg) < 0) {
		perror("pka_modular_exp");
		exit(0);
	}

	/* get result using polling */
	while (pka_get_result(handle, results) != SUCCESS) {
		pka_wait();
		continue;
	} 

	result_len = results->results[0].actual_len;
	rsa_ciphertext = malloc_operand(result_len);
	copy_operand(&results->results[0], rsa_ciphertext);

	if (rsa_ciphertext == NULL) {
		perror("copy_operand:");
		exit(0);
	}
#if DBG_MODE
	print_operand("encryption result = ", rsa_ciphertext, "\n\n");
#endif

	/* decrypt start */
	int pka_status = SUCCESS;
	

#if DBG_MODE
	printf("\n------------------[%d]decrypt----------------------\n", worker_id);
	print_operand("p = ", p, "\n");
	print_operand("q = ", q, "\n");
	print_operand("d_p = ", d_p, "\n");
	print_operand("d_q = ", d_q, "\n");
	print_operand("qinv = ", qinv, "\n\n");
#endif
	while(cnt < max_cmd_cnt || cur_command_cnt > 0) {
		while(cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
			/* send decryption request to PKA HW */
			user_data[cnt%outstanding_cmd_num] = cnt;
			if(p) {
				if(pka_modular_exp_crt(handle, &user_data[cnt%outstanding_cmd_num], rsa_ciphertext, p, q, d_p, d_q, qinv) < 0){
					perror("pka_modular_exp_crt");
					exit(0);
				}
			} else if(rsa_decrypt_key) {
				if((pka_status = pka_modular_exp(handle, &user_data[cnt%outstanding_cmd_num], rsa_decrypt_key, rsa_modulus, rsa_ciphertext)) < 0) {
					perror("pka_modular_exp");
					exit(0);
				}
			} else {
				fprintf(stderr, "Error: key pair does not exist\n");
				exit(0);
			}
			cnt++;
			cur_command_cnt++;
			/* printf("sent request to PKA HW!\n"); */
		}

		if(pka_status == FAILURE) {
			fprintf(stderr, "pka cmd submittion failed\n");
			pka_status = SUCCESS;
		}

		/* get result using polling */
		if(pka_get_result(handle, results) != SUCCESS) {
			pka_wait();
			continue;
		} else {
			cur_command_cnt--;
			cmd_cnt[worker_id]++;


#if DBG_MODE
			static __thread int i = -1;
			if(i == -1) {
				i = 0;
				if(to_hex_string(&results->results[0], result_buf[1], 100) < 0) {
					perror("to_hex_string");
					exit(0);
				}
			}

			print_operand("decryption result = ", &results->results[0], "\n\n");
			/* printf("cnt_correct = %d\n", cnt_correct++); */

			if(to_hex_string(&results->results[0], result_buf[i], 100) < 0) {
				perror("to_hex_string");
				exit(0);
			}
			if(i == 0) i = 1;
			else i = 0;
			if(strcmp(result_buf[0], result_buf[1]) != 0) {
				fprintf(stderr, "Error: decrypt result is different to original text!\n");
				printf("decryption result0 = %s\n", result_buf[0]);
				printf("decryption result1 = %s\n", result_buf[1]);
				exit(0);
			} else {
				printf("cnt_correct, user_data = %d %d\n", cnt_correct, *(int *)(results->user_data));
				cnt_correct++;
			}
#endif
		}
	}

	free_results(results);
	pka_term_local(handle);
	return NULL;
}

/*---------------------------------------------------------------------------------------*/
void *
ECDHworker(void *arg)
{
	/* UNUSED(arg); */
	pka_operand_t ec_p, *operand_for_ecdh[100];
	pka_handle_t      handle;
	pka_results_t    *results;
	/* uint32_t result_len; */

	int worker_id = *(int*)arg;
	int max_cmd_cnt = cmd_cnt_per_thread;
	int cnt = 0;
	int cur_command_cnt = 0;

	int i;

	/* wait for all worker ready */
	pka_barrier_wait(&thread_start_barrier);

	handle = pka_init_local(instance);  
	results = malloc_results(MAX_RESULT_CNT, MAX_BYTE_LEN + 8);

	/* generate random number operand_for_ecdh */
	char *ec_prime = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"; /* secp256r1 */
	ec_p.buf_ptr = NULL;
	if(from_hex_string(ec_prime, &ec_p) < 0) {
		perror("from_hex_string");
		exit(0);
	}

	for(i = 0; i < 100; i++) {
		operand_for_ecdh[i] = rand_non_zero_integer(handle, &ec_p);
	}

#if DBG_MODE
	printf("\n\n------------------multiply----------------------\n");
	print_operand("curve.p = ", &ec_curve->p, "\n");
	print_operand("curve.a = ", &ec_curve->a, "\n");
	print_operand("curve.b = ", &ec_curve->b, "\n");
	print_operand("K2.x = ", &ec_public_key_2->x, "\n");
	print_operand("K2.y = ", &ec_public_key_2->y, "\n");
	print_operand("k1 = ", ec_private_key, "\n");
	print_operand("operand_for_ecdh = ", operand_for_ecdh[cnt%100], "\n\n");
#endif
	while(cnt < max_cmd_cnt || cur_command_cnt > 0) {
		while(cnt < max_cmd_cnt && cur_command_cnt < outstanding_cmd_num) {
			/* send decryption request to PKA HW */
			int *flag_reloaded = (int *)calloc(1, sizeof(int));

			/* if(pka_ecc_pt_mult(handle, NULL, ec_curve, ec_public_key_2, ec_private_key) < 0){ */
			if(pka_ecc_pt_mult(handle, flag_reloaded, ec_curve, ec_P256_base_pt, operand_for_ecdh[rand()%100]) < 0){
				perror("pka_ecc_pt_mult: ");
				exit(0);
			}
			cnt++;
			cur_command_cnt++;
			/* printf("sent request to PKA HW!\n"); */
		}

		/* get result using polling */
		if(pka_get_result(handle, results) != SUCCESS) {
			pka_wait();
			continue;
		} else {
			/* ECDH need two EC point multiplication */
			if(*(int *)(results->user_data) == 0) {
				*(int *)(results->user_data) = 1;
				if(pka_ecc_pt_mult(handle, results->user_data, ec_curve, ec_P256_base_pt, operand_for_ecdh[rand()%100]) < 0){
					perror("pka_ecc_pt_mult: ");
					exit(0);
				}
			} else {
				/* finished one ECDH operation */
				free(results->user_data);
				cur_command_cnt--;
				cmd_cnt[worker_id]++;
			}

#if DBG_MODE
			print_operand("result 1 = ", &results->results[0], "\n\n");
			print_operand("result 2 = ", &results->results[1], "\n\n");
#endif
		}
	}

	for(i = 0; i < 100; i++) {
		free_operand(operand_for_ecdh[i]);
	}
	free_results(results);
	pka_term_local(handle);
	return NULL;
}


/*---------------------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
	pthread_t p_thread[MAX_THREAD_NUM];
	pthread_attr_t attr[MAX_THREAD_NUM]; 
	int tid[MAX_THREAD_NUM];  
	cpu_set_t *cpusetp[MAX_THREAD_NUM]; 
	int cpu_size, i;

#if DBG_MODE
	out = BIO_new_fp(stdout, BIO_CLOSE);
#endif

	srand(time(NULL));

	/* parse options of commandline */
	while((i = getopt(argc, argv, "m:t:r:o:n:")) >= 0) {
		switch(i) {
		case 'm':
			operation_mode = atoi(optarg);
			if (operation_mode < RSA_DECRYPTION || operation_mode > ECDH) {
				usage();
				exit(1);
			}
			break;
		case 't':
			thread_num = atoi(optarg);
			if(thread_num <= 0 || thread_num > PKA_MAX_QUEUE_CNT) {
				fprintf(stderr, "Error: 0 < thread_num <= 16\n");
				exit(1);
			}
			break;
		case 'r':
			ring_num = atoi(optarg);
			if(ring_num <= 0 || ring_num > PKA_MAX_RING_CNT) {
				fprintf(stderr, "Error: 0 < ring_num <= 16\n");
				exit(1);
			}
			break;
		case 'o':
			outstanding_cmd_num = atoi(optarg);
			if(outstanding_cmd_num <= 0) {
				fprintf(stderr, "Error: 0 < max_outstanding\n");
				exit(1);
			}
			break;
		case 'n':
			cmd_cnt_per_thread = atoi(optarg);
			if(cmd_cnt_per_thread <= 0) {
				fprintf(stderr, "Error: 0 < command_num_per_thread\n");
				exit(1);
			}
			break;
		case '?':
			usage();
			exit(1);
		}
	}



	/* extract argument from cmd */
	/* if(argc > 1) */
	/* 	operation_mode = atoi(argv[1]); */
	/* if(argc > 2) */
	/* 	cpu_set_base = atoi(argv[2]); */
	/* if(argc > 3) */
	/* 	CONCURRENT_LIMIT = atoi(argv[3]); */

	/* extract private/public key pair from certificate */
	GetRSAKeyPair("digital_certificates/cert_rsa.pem");
	GetECCKeyPair();

	// Global PKA initialization. This function must be called once per instance
	// before calling any other PKA API functions. 
	instance = pka_init_global("pka_benchmark_app", PKA_F_PROCESS_MODE_SINGLE |
							   PKA_F_SYNC_MODE_ENABLE,
							   /* PKA_F_SYNC_MODE_DISABLE, */
							   ring_num, thread_num,
							   CMD_QUEUE_SIZE, RSLT_QUEUE_SIZE);
 
	if(instance == PKA_INSTANCE_INVALID) {
		perror("pka_init_global");
		exit(0);
	}

	/* /\* debug *\/exit(0); */

	/* -------------------------------------------------------------------- */
    /* create threads */
	pka_barrier_init(&thread_start_barrier, thread_num);
    for(i = 0; i < thread_num + 1; i++) {
        /* set core */
        /* if((cpusetp[i] = CPU_ALLOC(thread_num)) == NULL) { */
        if((cpusetp[i] = CPU_ALLOC(1)) == NULL) {
            fprintf(stderr, "Error: cpu_set initialize failed\n");
            exit(0);
        }
        cpu_size = CPU_ALLOC_SIZE(1);
        CPU_ZERO_S(cpu_size, cpusetp[i]);
        /* CPU_SET_S(i + cpu_set_base, cpu_size, cpusetp[i]); */
        CPU_SET_S(i, cpu_size, cpusetp[i]);

        /* set thread attribute (core pinning) */
        if(pthread_attr_init(&attr[i]) != 0) {
            fprintf(stderr, "Error: thread attribute initialize failed\n");
            exit(0);
        }
        pthread_attr_setaffinity_np(&attr[i], cpu_size, cpusetp[i]);

        /* create thread */
        tid[i] = i;
        cmd_cnt[i] = 0;
		if(i == thread_num) {			/* thread for printing statistics */
			if(pthread_create(&p_thread[i], &attr[i], Printworker, (void *)&tid[i]) < 0) {
				fprintf(stderr, "Error: thread create failed\n");
				exit(0);
			}
		} else if(operation_mode == RSA_DECRYPTION) {
			/* if(pthread_create(&p_thread[i], NULL, worker, (void *)&tid[i]) < 0) { */
			if(pthread_create(&p_thread[i], &attr[i], RSAworker, (void *)&tid[i]) < 0) {
				fprintf(stderr, "Error: thread create failed\n");
				exit(0);
			}
		} else if(operation_mode == ECDH) {
			if(pthread_create(&p_thread[i], &attr[i], ECDHworker, (void *)&tid[i]) < 0) {
				fprintf(stderr, "Error: thread create failed\n");
				exit(0);
			}
		} else {
			fprintf(stderr, "Error: invalid operation mode\n");
			exit(0);
		}
    }

    /* wait threads */
    for(i = 0; i < thread_num; i++) {
        pthread_join(p_thread[i], NULL);
        CPU_FREE(cpusetp[i]);
    }

	/* finish Printworker */
	work_done = 1;

	/* free all operands */
	if(p) {
		free_operand(p);
		free_operand(q);
		free_operand(d_p);
		free_operand(d_q);
		free_operand(qinv);
	}
	if(rsa_encrypt_key) {
		free_operand(rsa_encrypt_key);
		free_operand(rsa_decrypt_key);
		free_operand(rsa_modulus);
	}

	free_operand(rsa_ciphertext);

	// Release the given handle and PK instance. Note that these calls will free
	// rings related to the PK instance and will mark them as available again  
	pka_term_global(instance); 
 
	return 0;
}
