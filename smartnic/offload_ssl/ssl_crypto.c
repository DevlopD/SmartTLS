#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ssl_crypto.h"

#define MAX_PHASH_INPUT (MAX_HASH_SIZE * 3)
static inline int
P_HASH(const EVP_MD* hash, const int secret_len, const uint8_t *secret,
       const int seed_len, const uint8_t *seed,
       const int out_len,  uint8_t *out)
{
    int out_len_actual = 0;
    uint8_t buf[MAX_PHASH_INPUT];
    uint8_t *hmac_out = buf;
    int hmac_out_len = 0;

    HMAC(hash, secret, secret_len,
         seed, seed_len,
         hmac_out, (unsigned int*)&hmac_out_len);
    assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

    memcpy(hmac_out + hmac_out_len, seed, seed_len);

    HMAC(hash, secret, secret_len,
         hmac_out, hmac_out_len + seed_len,
         out + out_len_actual, (unsigned int*)&hmac_out_len);
    assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

    out_len_actual += hmac_out_len;

    while (out_len_actual < out_len) {
        HMAC(hash, secret, secret_len,
             hmac_out, hmac_out_len,
             hmac_out, (unsigned int *)&hmac_out_len);
        assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);

        HMAC(hash, secret, secret_len,
             hmac_out, hmac_out_len + seed_len,
             out + out_len_actual, (unsigned int *)&hmac_out_len);
        assert(MAX_HASH_SIZE > hmac_out_len && hmac_out_len > 0);
        out_len_actual += hmac_out_len;
    }

    return out_len_actual;
}
#undef MAX_PHASH_INPUT

#define MAX_PRF_INPUT 16384
inline int
PRF(const EVP_MD* (*hash_func)(void), const int secret_len, const uint8_t *secret,
    const int label_len,  const uint8_t *label,
    const int seed_len,   const uint8_t *seed,
    const int out_len,    uint8_t *out)
{
    uint8_t buf[MAX_PRF_INPUT];
    uint8_t *p_sha256 = buf;
    int real_seed_len = label_len + seed_len;
    uint8_t *real_seed = p_sha256 + out_len + 20;

    assert(out_len + 20 + real_seed_len < MAX_PRF_INPUT);

    memcpy(real_seed, label, label_len);
    memcpy(real_seed + label_len, seed, seed_len);

    P_HASH(hash_func(), secret_len, secret,
           real_seed_len, real_seed,
           out_len, p_sha256);

    memcpy(out, p_sha256, out_len);

    return out_len;
}
#undef MAX_PRF_INPUT

static inline void
handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

static inline int
encrypt_aes_cbc(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    /* EVP_CIPHER_CTX *ctx; */

    int len;

    /* /\* Create and initialise the context *\/ */
    /* if(unlikely(!(ctx = EVP_CIPHER_CTX_new()))) */
    /*     handleErrors(); */

    /* Initialise the decryption operation */
    if(unlikely(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)))
        handleErrors();

    len = EVP_Cipher(ctx, plaintext, ciphertext, ciphertext_len);

    /* /\* Clean up *\/ */
    /* EVP_CIPHER_CTX_free(ctx); */

    return len;
}

static inline int
decrypt_aes_cbc(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    /* EVP_CIPHER_CTX *ctx; */

    int len;

    /* /\* Create and initialise the context *\/ */
    /* if(unlikely(!(ctx = EVP_CIPHER_CTX_new()))) */
    /*     handleErrors(); */

    /* Initialise the decryption operation */
    if(unlikely(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)))
        handleErrors();

    len = EVP_Cipher(ctx, plaintext, ciphertext, ciphertext_len);

    /* /\* Clean up *\/ */
    /* EVP_CIPHER_CTX_free(ctx); */

    return len;
}

static inline int
encrypt_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *aad, int aad_len,
                unsigned char *tag, unsigned char *ciphertext)
{
    int len;
    int ciphertext_len;

#if CRYPTO_GETTIME_FLAG
    struct timespec tv_start, tv_end;
    int64_t elapsed_time;
    clock_gettime(CLOCK_MONOTONIC, &tv_start);
#endif

    /* Initialise the encryption operation. */
#if MODIFY_FLAG
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
#endif

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

#if CRYPTO_GETTIME_FLAG
    clock_gettime(CLOCK_MONOTONIC, &tv_end);
    elapsed_time = (tv_end.tv_nsec - tv_start.tv_nsec) + (tv_end.tv_sec - tv_start.tv_sec)*100000000;
    if (elapsed_time > 1000)
        fprintf(stderr, "[encrypt aes gcm] EVP_EncryptUpdate (plaintext) takes %ld nano sec\n",
				(tv_end.tv_nsec - tv_start.tv_nsec) + (tv_end.tv_sec - tv_start.tv_sec)*100000000);
#endif

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

#if VERBOSE_GCM
    int z;
    fprintf(stderr, "\n\n[encrypt aes gcm] iv_len: 0x%x, iv (nonce): \n", iv_len);
    for (z = 0; z < iv_len; z++)
        fprintf(stderr, "%02X%c", iv[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nkey: \n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\naad_len: 0x%x, aad: \n", aad_len);
    for (z = 0; z < aad_len; z++)
        fprintf(stderr, "%02X%c", aad[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n[encrypt aes gcm] plaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nciphertext_len: 0x%x, ciphertext: \n", ciphertext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", ciphertext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\ntag: \n");
    for (z = 0; z < 16; z++)
        fprintf(stderr, "%02X%c", tag[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
#endif

#if MODIFY_FLAG
    EVP_CIPHER_CTX_free(ctx);
#endif

    return ciphertext_len;
}

static inline int
decrypt_aes_gcm(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                unsigned char *iv, unsigned short iv_len, unsigned char *aad, unsigned short aad_len,
                unsigned char *tag, unsigned char *plaintext)
{
    /* EVP_CIPHER_CTX *ctx; */
    int len;
    int plaintext_len;
    int ret;

#if VERBOSE_GCM
    int z;
    fprintf(stderr, "\n[decrypt aes gcm] iv_len: 0x%x, iv (nonce): \n", iv_len);
    for (z = 0; z < iv_len; z++)
        fprintf(stderr, "%02X%c", iv[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nkey: \n");
    for (z = 0; z < 32; z++)
        fprintf(stderr, "%02X%c", key[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\naad_len: 0x%x, aad: \n", aad_len);
    for (z = 0; z < aad_len; z++)
        fprintf(stderr, "%02X%c", aad[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nciphertext_len: 0x%x, ciphertext: \n", ciphertext_len);
    for (z = 0; z < ciphertext_len; z++)
        fprintf(stderr, "%02X%c", ciphertext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\ntag: \n");
    for (z = 0; z < GCM_TAG_SIZE; z++)
        fprintf(stderr, "%02X%c", tag[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
#endif

    /* Initialise the decryption operation. */
#if MODIFY_FLAG
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
#endif

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

	/*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    len = 0;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

#if VERBOSE_GCM
    fprintf(stderr, "plaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\nanother nplaintext_len: 0x%x, plaintext: \n", plaintext_len);
    for (z = 0; z < plaintext_len; z++)
        fprintf(stderr, "%02X%c", plaintext[z+len],
                ((z + 1) % 16)? ' ' : '\n');
    fprintf(stderr, "\n");
#endif

#if MODIFY_FLAG
    EVP_CIPHER_CTX_free(ctx);
#endif

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

inline int
execute_rsa_crypto(ssl_crypto_op_t* op) 
{
	if(!op)
		return -1;
    assert(op->opcode.s.function == TLS_RSA);

    if (op->opcode.s.op == PRIVATE_DECRYPT) {
#if VERBOSE_KEY
		fprintf(stderr, "\nTLS_RSA: PRIVATE_DECRYPT\n");
#endif /* VERBOSE_KEY */

		pka_t* pka = (pka_t *)op->key;
		struct ssl_session *sess =
			(struct ssl_session *)((record_t *)op->data)->sess;
		assert(pka != NULL);

		if (unlikely(pka_modular_exp_crt(handle[sess->coreid],
										 (void *)op, op->pka_in,
										 pka->p,
										 pka->q,
										 pka->d_p,
										 pka->d_q,
										 pka->qinv) < 0)) {
			fprintf(stderr, "\nPKA RSA DECRYPTION ERROR\n");
			assert(0);
		}

#if VERBOSE_SSL
		fprintf(stderr, "Crypto Request at handle %d\n", sess->coreid);
#endif
		ctx_array[sess->coreid]->cur_crypto_cnt++;
    }
    else
		assert(0);
    return 0;

}

inline int
execute_aes_crypto(EVP_CIPHER_CTX *ctx, ssl_crypto_op_t* op) 
{
	if(!op)
		return -1;

	if (op->opcode.s.function == TLS_AES_CBC) {
		if (op->opcode.s.op == ENCRYPT) {
			int ret = encrypt_aes_cbc(ctx, op->in,
								  op->in_len,
								  op->key,
								  op->iv,
								  op->out);
			if (unlikely(ret <= 0)) {
				fprintf(stderr, "AES encryption error\n");
				return -1;
			}
#if VERBOSE_AES
			fprintf(stderr, "\nTLS_AES_CBC %d: ENCRYPT\n",
					op->opcode.s.bit);
			fprintf(stderr, "Encrypted len: %d\n", ret);
#endif /* VERBOSE_AES */
		}
		else if (op->opcode.s.op == DECRYPT) {
			int ret = decrypt_aes_cbc(ctx, op->in,
								  op->in_len,
								  op->key,
								  op->iv,
								  op->out);
			if (unlikely(ret <= 0)) {
				fprintf(stderr, "AES decryption error\n");
				return -1;
			}
#if VERBOSE_AES
			fprintf(stderr, "\nTLS_AES_CBC %d: DECRYPT\n",
					op->opcode.s.bit);
			fprintf(stderr, "decrypted len: %d\n", ret);
#endif /* VERBOSE_AES */
		}
		else
			assert(0);

	} else if(op->opcode.s.function == TLS_AES_GCM) {
        if (op->opcode.s.op == ENCRYPT) {
            int ret = encrypt_aes_gcm(ctx,
                                      op->in,
                                      op->in_len,
                                      op->key,
                                      op->iv,
                                      op->iv_len,
                                      op->aad,
                                      op->aad_len,
                                      op->out + op->in_len,
                                      op->out);
            if (ret <= 0) {
                fprintf(stderr, "AES encryption gcm error\n");
                return -1;
            }
#if VERBOSE_AES
            fprintf(stderr, "\nTLS_AES_GCM %d: ENCRYPT\n",
                    op->opcode.s.bit);
            fprintf(stderr, "Encrypted len: %d\n", ret);
#endif /* VERBOSE_AES */
        } else if (op->opcode.s.op == DECRYPT) {
            int ret = decrypt_aes_gcm(ctx,
                                      op->in,
                                      op->in_len,
                                      op->key,
                                      op->iv,
                                      op->iv_len,
                                      op->aad,
                                      op->aad_len,
                                      op->in + op->in_len,
                                      op->out);

            if (ret <= 0) {
                fprintf(stderr, "AES decryption gcm error\n");
                return -1;
            }
#if VERBOSE_AES
            fprintf(stderr, "\nTLS_AES_GCM %d: DECRYPT\n",
                    op->opcode.s.bit);
            fprintf(stderr, "decrypted len: %d\n", ret);
#endif /* VERBOSE_AES */
        }
        else
            assert(0);
    }

	return 0;
}

inline int
execute_mac_crypto(ssl_crypto_op_t* op) 
{
    assert(op != NULL);
    assert(op->opcode.s.function == TLS_HMAC_SHA1);

	unsigned len;

	HMAC(EVP_sha1(),
		 op->key,
		 op->key_len,
		 op->in,
		 op->in_len,
		 op->out,
		 &len);
	assert(len == op->out_len);

    return 0;
}
