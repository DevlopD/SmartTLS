#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <mtcp.h>
#include "ssloff.h"
#include "ssl_crypto.h"

#define RAND_MAX_LOCAL (1073741823lu*4lu + 3lu)
#define MIN(a, b) ((a)<(b)?(a):(b))

/*---------------------------------------------------------------------------*/
/* FUNCTION PROTOTYPE */
static inline void
set_u32(uint24_t* a, const uint32_t* b);

static inline uint32_t
get_u32(uint24_t a);

static inline uint8_t *
get_mac_out(record_t *record);

static inline cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t* cipher_suites);

static inline void
init_record(record_t* record,
            const sequence_num_t seq, const int is_received_);

static inline record_t *
new_recv_record(struct ssl_session* sess);

static inline record_t *
new_send_record(struct ssl_session* sess);

static inline int
store_handshake(struct ssl_session* sess, record_t *record);

static inline void
delete_record(struct ssl_session* sess, record_t* record);

static inline void
delete_op(ssl_crypto_op_t *op);

static inline int
handle_after_private_decrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op);

static inline int
handle_after_aes_cbc_encrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op);

static inline int
handle_after_aes_cbc_decrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op);

static inline int
handle_after_aes_gcm_encrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op);

static inline int
handle_after_aes_gcm_decrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op);

static inline int
handle_mac(struct ssl_session* sess,
                record_t* record, ssl_crypto_op_t *op);

static inline int
handle_after_rsa_crypto(struct ssl_session* sess,
                    ssl_crypto_op_t *op);

static inline int
handle_after_aes_crypto(struct ssl_session* sess,
                    ssl_crypto_op_t *op);

static inline int
handle_after_mac_crypto(struct ssl_session* sess,
                    ssl_crypto_op_t *op);

static inline int
rsa_decrypt_record(struct ssl_session* sess, record_t* record);

static inline int
decrypt_record(struct ssl_session* sess, record_t* record, char *buf, uint16_t buf_len);

static inline int
encrypt_record(struct ssl_session* sess, record_t* record);

static inline int
unpack_record(record_t* record);

static inline int
pack_record(record_t* record);

static inline int
unpack_change_cipher_spec(void);

static inline int
unpack_alert(record_t* record);

static inline int
unpack_application_data(record_t* record);

static inline int
unpack_handshake(record_t* record);

static inline int
pack_handshake(record_t* record, int offset);

static inline int
handle_alert(struct ssl_session* sess, record_t *record);

static inline int
handle_data(struct ssl_session* sess, record_t *record);

static inline int
handle_read_record(struct ssl_session* sess, record_t* record);

inline int
send_record(struct ssl_session* sess, record_t* record,
            uint8_t c_type, int length);

static inline int
handle_change_cipher_spec(struct ssl_session* sess, record_t* record);

static inline int
handle_handshake(struct ssl_session* sess, record_t* record);

static inline int
send_handshake(struct ssl_session* sess, record_t* record,
               uint8_t msg_type, int length);

static inline int
verify_mac(struct ssl_session* sess, record_t* record);

static inline int
attach_mac(struct ssl_session* sess, record_t* record);

static inline int
unpack_header(record_t* record);

static inline int
process_read_record(struct ssl_session* sess, record_t* record,
                    char* buf, uint16_t buf_len);

static inline int
process_new_record(struct ssl_session* sess, uint8_t *payload, size_t payload_len,
                   char *buf, size_t buf_len);

#if VERBOSE_STATE
/*---------------------------------------------------------------------------*/

static const char state_str_null_state[20] = "NULL_STATE";
static const char state_str_to_pack_header[20] = "TO_PACK_HEADER";
static const char state_str_to_pack_content[20] = "TO_PACK_CONTENT";
static const char state_str_to_append_mac[20] = "TO_APPEND_MAC";
static const char state_str_to_encrypt[20] = "TO_ENCRYPT";
static const char state_str_write_ready[20] = "WRITE_READY";
static const char state_str_to_unpack_header[20] = "TO_UNPACK_HEADER";
static const char state_str_to_unpack_content[20] = "TO_UNPACK_CONTENT";
static const char state_str_to_verify_mac[20] = "TO_VERIFY_MAC";
static const char state_str_to_decrypt[20] = "TO_DECRYPT";
static const char state_str_read_ready[20] = "READ_READY";
static const char state_str_error[20] = "INVALID_STATE";

static const char *
state_to_string(int state)
{
    switch(state) {
        case NULL_STATE:
            return state_str_null_state;

        case TO_PACK_HEADER:
            return state_str_to_pack_header;

        case TO_PACK_CONTENT:
            return state_str_to_pack_content;

        case TO_APPEND_MAC:
            return state_str_to_append_mac;

        case TO_ENCRYPT:
            return state_str_to_encrypt;

        case WRITE_READY:
            return state_str_write_ready;

        case TO_UNPACK_HEADER:
            return state_str_to_unpack_header;

        case TO_UNPACK_CONTENT:
            return state_str_to_unpack_content;

        case TO_VERIFY_MAC:
            return state_str_to_verify_mac;

        case TO_DECRYPT:
            return state_str_to_decrypt;

        case READ_READY:
            return state_str_read_ready;

        default:
            return state_str_error;
    }

    return state_str_error;
}
#endif /* VERBOSE_STATE */

inline void
set_u32(uint24_t* a, const uint32_t* b)
{
    const uint8_t* y = (const uint8_t *)b;
    a->u8[0] = y[2];
    a->u8[1] = y[1];
    a->u8[2] = y[0];
}

inline uint32_t
get_u32(uint24_t a)
{
    uint32_t x;
    x = a.u8[0];
    x = x << 8;
    x |= a.u8[1];
    x = x << 8;
    x |= a.u8[2];

    return x;
}

inline uint8_t *
get_mac_out(record_t *record)
{
	return (record->decrypted + record->plain_text.length + 5);
}

inline void
init_random(struct ssl_session* sess, uint8_t *random, unsigned size)
{
    unsigned *ra = (unsigned *) random;
    unsigned i, j;
    uint64_t rand_seed = sess->rand_seed;

    rand_seed = rand_seed * 1103515245 + 12345;
    for (i = 0; i < size/sizeof(int); i++) {
        rand_seed = rand_seed * 1103515245lu + 12345lu;
        ra[i] = (unsigned)((rand_seed/(RAND_MAX_LOCAL * 21u)) % RAND_MAX_LOCAL);
    }
    for (j = 0; j + i * sizeof(int) < size; j++) {
        rand_seed = rand_seed * 1103515245lu + 12345lu;
        random[i * sizeof(int) + j] = (uint8_t)rand_seed;
    }
}

static inline cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t* cipher_suites)
{
    unsigned i;
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;

    for (i = 0; i < length / sizeof(cipher_suite_t); i++) {
		/* /\* debug *\/ */
		/* if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_CBC_SHA)) { */
        /*     return TLS_RSA_WITH_AES_256_CBC_SHA; */
        /* } */
		if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_GCM_SHA384)) {
            return TLS_RSA_WITH_AES_256_GCM_SHA384;
        } else if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_256_CBC_SHA)) {
            return TLS_RSA_WITH_AES_256_CBC_SHA;
        }
    }
    return cipher;
}

static inline void
init_record(record_t* record,
            const sequence_num_t seq, const int is_received_)
{
	/* really needed to set in advance? */
    record->data = record->buf + sizeof(uint64_t) + MAX_IV_SIZE;

	record->mac_in = record->buf_unencrypted + MAX_IV_SIZE;
	record->decrypted = record->mac_in + sizeof(sequence_num_t);
    record->next_iv = NULL;
    record->current_len = 0;
    record->length = 0;
    record->seq_num = seq;
    record->is_encrypted = 0;

    memset(&record->plain_text, 0, sizeof(plain_text_t));
    memset(&record->cipher_text, 0, sizeof(cipher_text_t));
    memset(&record->fragment, 0, sizeof(record->fragment));

    record->is_reset = FALSE;
    record->is_received = is_received_;
    if (record->is_received)
        record->state = TO_UNPACK_HEADER;
    else
        record->state = TO_PACK_HEADER;

#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(NULL_STATE),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */
}

static inline record_t*
new_recv_record(struct ssl_session* sess)
{
    record_t *record = NULL;
    struct ssl_thread_context *ctx = sess->ctx;

    sess->num_current_records++;

    record = TAILQ_FIRST(&ctx->record_pool);
    if (!record) {
        fprintf(stderr, "Not enough record, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    if(!ctx)
	assert(0);
    TAILQ_REMOVE(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt--;
    ctx->using_record_cnt++;

    record->sess = sess;
    init_record(record, 0, TRUE);

    record->id = sess->next_record_id;
    sess->next_record_id++;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nnew_recv_record: %d\n",
                    record->id);
#endif /* VERBOSE_SSL */

    return record;
}

static inline record_t*
new_send_record(struct ssl_session* sess)
{
    record_t *record = NULL;
    struct ssl_thread_context *ctx = sess->ctx;

    sess->num_current_records++;

    record = TAILQ_FIRST(&ctx->record_pool);
    if (!record) {
        fprintf(stderr, "Not enough record, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt--;
    ctx->using_record_cnt++;

    record->sess = sess;

    init_record(record, sess->send_seq_num_, FALSE);

    record->id = sess->next_record_id;
    sess->next_record_id++;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nnew_send_record: %d\n",
                    record->id);
#endif /* VERBOSE_SSL */

	record->payload_to_send = 0;
#if SEG_RECORD_BUF
	record->total_payload_to_send = 0;
#endif
	record->total_to_send = 0;
	record->where_to_send = NULL;
	record->already_sent = 0;

	sess->current_send_record = record;

    return record;
}

static ssl_crypto_op_t*
new_ssl_crypto_op(struct ssl_session* sess)
{
    ssl_crypto_op_t *target;
    struct ssl_thread_context *ctx = sess->ctx;

    target = TAILQ_FIRST(&ctx->op_pool);
    if (!target) {
        fprintf(stderr, "Not enough op, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->op_pool, target, op_pool_link);
    ctx->free_op_cnt--;
    ctx->using_op_cnt++;

    return target;
}

static inline int
store_handshake(struct ssl_session* sess, record_t *record)
{
    if (record->fragment.handshake.msg_type 
                        <= sess->handshake_state)
        return -1;

    if (record->plain_text.version.major == 0x03)
        memcpy(sess->handshake_msgs + sess->handshake_msgs_len,
               record->plain_text.fragment,
               record->plain_text.length);
    else
        assert(0);

    sess->handshake_msgs_len += record->plain_text.length;

#if VERBOSE_CHUNK
    fprintf(stderr, "\nSTORE HANDSHAKE! new: %u, total : %u, type : %d\n",
                    record->plain_text.length,
                    sess->handshake_msgs_len,
                    record->fragment.handshake.msg_type);

    fprintf(stderr, "\nfragment:\n\n");
    {
		unsigned z;
        for (z = 0; z < record->plain_text.length; z++)
            fprintf(stderr, "%02X%c",
                    *((uint8_t *)(record->plain_text.fragment) + z),
                    ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_CHUNK */

    assert(sess->handshake_msgs_len < MAX_HANDSHAKE_LENGTH);
    return sess->handshake_msgs_len;
}

static inline void
delete_record(struct ssl_session* sess, record_t* record)
{
    struct ssl_thread_context *ctx = record->ctx;

    record->ctx = ctx;
    TAILQ_INSERT_TAIL(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt++;
    ctx->using_record_cnt--;

    sess->num_current_records--;
#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nDelete Record: %d\n",
                    record->id);
#endif /* VERBOSE_SSL */
}

static inline void
delete_op(ssl_crypto_op_t *op)
{
    struct ssl_thread_context *ctx = op->ctx;

    op->ctx = ctx;
    TAILQ_INSERT_TAIL(&ctx->op_pool, op, op_pool_link);
    ctx->free_op_cnt++;
    ctx->using_op_cnt--;
}

static inline int
handle_after_aes_cbc_encrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op)
{
    assert(record->state == TO_ENCRYPT);
    record->state = WRITE_READY;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_ENCRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    memcpy(sess->server_write_IV,
           op->out + op->out_len - sess->write_sp.fixed_iv_length,
           sess->write_sp.fixed_iv_length);
    sess->server_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

static inline int
handle_after_aes_cbc_decrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op)
{
    assert(record->state == TO_DECRYPT);
    record->state = TO_VERIFY_MAC;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_DECRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_AES
    unsigned z = 0;
    fprintf(stderr, "\noriginal data:\n\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->in) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\ndecrypted data:\n\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->out) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#else /* VERBOSE_AES */
    UNUSED(op);
#endif /* !VERBOSE_AES */

    sess->client_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

/* need to implement */
static inline int
handle_after_aes_gcm_encrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op)
{
    assert(record->state == TO_ENCRYPT);
    record->state = WRITE_READY;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_ENCRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    sess->server_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

/* need to implement */
static inline int
handle_after_aes_gcm_decrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op)
{
    assert(record->state == TO_DECRYPT);
    record->state = TO_VERIFY_MAC;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_DECRYPT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_AES
    unsigned z = 0;
    fprintf(stderr, "\noriginal data:\n\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->in) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\ndecrypted data:\n\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->out) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#else /* VERBOSE_AES */
    UNUSED(op);
#endif /* !VERBOSE_AES */

    sess->client_write_IV_seq_num = record->seq_num + 1;

	return 0;
}

static inline int
handle_after_private_decrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op)
{
    assert(op->out_len == 48);
    premaster_secret_t *ps =
                &record->fragment.handshake.body.client_key_exchange.ps;

    memcpy(ps, op->out, MIN(op->out_len, 48u));

	return 0;
}

static inline int
handle_mac(struct ssl_session* sess,
                record_t* record, ssl_crypto_op_t *op)
{
    int wrong = 0;
    unsigned z = 0;
    generic_block_cipher_t *block_cipher =
                                &record->cipher_text.fragment.block_cipher;
    security_params_t *read_sp = &sess->read_sp;

    assert(record->state == TO_APPEND_MAC ||
           record->state == TO_VERIFY_MAC);

	/* verify if received mac is same */
    if (record->is_received) {
        uint8_t* recv_mac = block_cipher->mac;
#if VERBOSE_SSL
        fprintf(stderr, "\nHandle MAC (VERIFY MAC)\n");
#endif /* VERBOSE_SSL */
#if VERBOSE_MAC
        fprintf(stderr, "\nmac received:\n");
        {
            for (z = 0; z < read_sp->mac_key_size; z++)
                fprintf(stderr, "%02X%c",
                                recv_mac[z],
                                ((z + 1) % 16) ? ' ' : '\n');
        }

#endif /* VERBOSE_MAC */
        for (z = 0; z < read_sp->mac_key_size; z++) {
            if (op->out[z] != recv_mac[z]) {
                wrong = 1;
                break;
            }
        }
        if (wrong) {
#if VERBOSE_MAC
			fprintf(stderr, "\nWrong MAC! record->data:\n");
            for (z = 0; z < record->length; z++)
                fprintf(stderr, "%02X%c",
                                record->data[z],
                                ((z + 1) % 16) ? ' ' : '\n');
	    fprintf(stderr, "\n");
#endif
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_MAC;
            close_session(sess);
            return -1;
		}
#if VERBOSE_MAC
        else
            fprintf(stderr, "\nCorrect MAC!!\n");
#endif /* VERBOSE_MAC */

		return 0;
    }
	else {
#if VERBOSE_SSL
        fprintf(stderr, "\nAPPEND MAC\n");
#endif /* VERBOSE_SSL */
        block_cipher->mac =
            record->decrypted + record->plain_text.length + RECORD_HEADER_SIZE;
        memcpy(block_cipher->mac, op->out, op->out_len);
        record->cipher_text.length += op->out_len;
        record->length += op->out_len;
        *(uint16_t*)(record->decrypted + 3) = htons(record->cipher_text.length);

#if VERBOSE_STATE
        fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                        sess->parent->session_id,
                        record->id,
                        state_to_string(TO_APPEND_MAC),
                        state_to_string(record->state));
#endif /* VERBOSE_STATE */

        return 0;
    }

	/* cannot reach here */
	return -1;
}

static int
handle_after_rsa_crypto(struct ssl_session* sess,
                    ssl_crypto_op_t *op)
{
	int ret = -1;
    record_t *record = (record_t *)op->data;
    int crypto_type = op->opcode.s.op;
	if (!record) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
		return -1;
	}
	assert(op->opcode.s.function == TLS_RSA);

#if VERBOSE_SSL
    fprintf(stderr, "Handle after RSA Crypto\n");
#endif /* VERBOSE_SSL */

	if (crypto_type == PRIVATE_DECRYPT) {
		ret = handle_after_private_decrypt(sess, record, op);
	} else
		assert(0);

	delete_op(op);
	return ret;
}

static int
handle_after_aes_crypto(struct ssl_session* sess,
                    ssl_crypto_op_t *op)
{
	int ret = -1;
    record_t *record = (record_t *)op->data;
    int crypto_type = op->opcode.s.op;
    int function = op->opcode.s.function;
	if (!record) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
		return -1;
	}

#if VERBOSE_SSL
    fprintf(stderr, "Handle after AES Crypto\n");
#endif /* VERBOSE_SSL */

	if (crypto_type == ENCRYPT) {
		sess->send_seq_num_++;
		if (function == TLS_AES_CBC)
			ret = handle_after_aes_cbc_encrypt(sess, record, op);
		else if (function == TLS_AES_GCM)
			ret = handle_after_aes_gcm_encrypt(sess, record, op);
		else
			assert(0);
	} else if (crypto_type == DECRYPT) {
		if (function == TLS_AES_CBC)
			ret = handle_after_aes_cbc_decrypt(sess, record, op);
		else if (function == TLS_AES_GCM)
			ret = handle_after_aes_gcm_decrypt(sess, record, op);
		else
			assert(0);
	} else {
		fprintf(stderr, "[handle after aes crypto] undefined crypto_type: %d\n",
				crypto_type);
		delete_op(op);
		return -1;
	}

	delete_op(op);
	return ret;
}

static int
handle_after_mac_crypto(struct ssl_session* sess,
                    ssl_crypto_op_t *op)
{
	int ret = -1;
    record_t *record = (record_t *)op->data;
	if (!record) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
		return -1;
	}
	assert(op->opcode.s.function == TLS_HMAC_SHA1);

#if VERBOSE_SSL
    fprintf(stderr, "Handle after MAC Crypto\n");
#endif /* VERBOSE_SSL */

	ret = handle_mac(sess, record, op);

    delete_op(op);
	return ret;
}

static inline int
rsa_decrypt_record(struct ssl_session* sess, record_t* record)
{
    assert(record != NULL);
#if VERBOSE_SSL
    fprintf(stderr, "RSA Decrypt RECORD\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
	if (!op) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
		return -1;
	}
    client_key_exchange_t* ckpt =
                    &record->fragment.handshake.body.client_key_exchange;
    uint8_t *secret = ckpt->key.rsa.encrypted_premaster_secret;

    op->in = ((uint8_t *)secret) + 2;
    op->out = sess->ctx->rsa_result;
    op->in_len = ntohs(*(uint16_t *)secret);
    op->out_len = op->in_len;
	op->key = (uint8_t *)(sess->ctx->public_crypto_ctx.rsa);

    assert(op->key != NULL);
#if VERBOSE_KEY
    fprintf(stderr, "RSA %d\n", op->in_len * 8);
#endif /* VERBOSE_KEY */
    if (op->in_len == 128) {
        op->opcode.u32 = TLS_OPCODE_RSA_1024_PRIVATE_DECRYPT;
    } else if (op->in_len == 256) {
        op->opcode.u32 = TLS_OPCODE_RSA_2048_PRIVATE_DECRYPT;
    } else if (op->in_len == 512) {
        op->opcode.u32 = TLS_OPCODE_RSA_4096_PRIVATE_DECRYPT;
    } else
        assert(0);

    op->sess = sess;
    op->data = (void *)record;

    sess->waiting_crypto = TRUE;

    if (0 > execute_rsa_crypto(op)) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
		delete_op(op);
		return -1;
	}
 
    return handle_after_rsa_crypto(sess, op);
}

static inline int
decrypt_record(struct ssl_session* sess, record_t* record, char *buf, uint16_t buf_len)
{
    security_params_t *read_sp = &sess->read_sp;

    assert(record->state == TO_DECRYPT);
#if VERBOSE_SSL
    fprintf(stderr, "Decrypting Record\n");
#endif /* VERBOSE_SSL */

    record->seq_num = sess->recv_seq_num_;
    sess->recv_seq_num_++;

    record->is_encrypted = 1;
#if VERBOSE_SSL
    fprintf(stderr, "Need to decrypt Cipher\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);
	if (!op) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
		return -1;
	}

	if (read_sp->cipher_type == BLOCK) {
		generic_block_cipher_t *block_cipher =
			&record->cipher_text.fragment.block_cipher;
		block_cipher->IV = record->data + RECORD_HEADER_SIZE;
		record->cipher_text.length -= read_sp->fixed_iv_length;

		op->in = block_cipher->IV + read_sp->fixed_iv_length;
		op->out = record->decrypted + RECORD_HEADER_SIZE;

		memcpy(record->decrypted, record->data,
			   RECORD_HEADER_SIZE);

		op->in_len = record->cipher_text.length;
		op->out_len = record->cipher_text.length;
		op->iv = block_cipher->IV;
		op->key = sess->client_write_key;
		op->key_len = read_sp->enc_key_size;
		op->iv_len = read_sp->fixed_iv_length;
		op->opcode.u32 = TLS_OPCODE_AES_CBC_256_DECRYPT;

		op->data = (void *)record;

		if (0 > execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op)) {
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
			delete_op(op);
			return -1;
		}

		*((uint16_t *)(record->decrypted + 3)) = htons(record->cipher_text.length);
#if VERBOSE_AES
		fprintf(stderr, "\n[decrypt_record] Decrypted Data:\n");
		{
			int z;
			for (z = 0; z < record->cipher_text.length + RECORD_HEADER_SIZE; z++)
				fprintf(stderr, "%02X%c", record->decrypted[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */

	} else if (read_sp->cipher_type == AEAD) {
		uint8_t nonce[read_sp->fixed_iv_length + read_sp->record_iv_length];
		uint8_t additional_data[sizeof(sequence_num_t) + RECORD_HEADER_SIZE];
		generic_aead_cipher_t *aead_cipher = 
			&record->cipher_text.fragment.aead_cipher;
		sequence_num_t seqnum;

		aead_cipher->nonce_explicit = record->data + RECORD_HEADER_SIZE;
		record->cipher_text.length -= read_sp->record_iv_length + GCM_TAG_SIZE;

#if VERBOSE_AES
		fprintf(stderr, "[decrypt record] decrypt with gcm !!!!!!!!!!!!!!!!!!!!!!!\n");
		fprintf(stderr, "RECORD DATA:\n");
		int z;
		for (z = 0; z < record->length; z++)
			fprintf(stderr, "%02X%c", record->data[z],
					((z + 1) % 16)? ' ' : '\n');

		fprintf(stderr, "\nImplicit part iv (client_write_iv):\n");
		for (z = 0; z < read_sp->fixed_iv_length; z++) 
			fprintf(stderr, "%02X%c", sess->client_write_IV[z],
					((z + 1) % 16)? ' ' : '\n');
		fprintf(stderr, "\n");

		fprintf(stderr, "Explicit part iv: \n");
		for (z = 0; z < read_sp->record_iv_length; z++)
			fprintf(stderr, "%02X%c", aead_cipher->nonce_explicit[z],
					((z + 1) % 16)? ' ' : '\n');
		fprintf(stderr, "\n");
#endif /* VERBOSE_AES */

		memcpy(nonce, sess->client_write_IV,
			   read_sp->fixed_iv_length);
		memcpy(nonce + read_sp->fixed_iv_length, aead_cipher->nonce_explicit,
			   read_sp->record_iv_length);

		seqnum = bswap_64(record->seq_num);
		memcpy(additional_data, &seqnum,
			   sizeof(seqnum));
		memcpy(additional_data + sizeof(sequence_num_t), record->data,
			   RECORD_HEADER_SIZE);
		additional_data[sizeof(additional_data) - 1] -= sizeof(sequence_num_t) + GCM_TAG_SIZE;

		op->in = aead_cipher->nonce_explicit + read_sp->record_iv_length;
		op->out = record->decrypted + RECORD_HEADER_SIZE;

		memcpy(record->decrypted, record->data,
			   RECORD_HEADER_SIZE);

		op->in_len = record->cipher_text.length;
		op->iv = nonce;
		op->iv_len = read_sp->fixed_iv_length + read_sp->record_iv_length;
		op->aad = additional_data;
		op->aad_len = sizeof(sequence_num_t) + RECORD_HEADER_SIZE;
		op->key = sess->client_write_key;
		op->key_len = read_sp->enc_key_size;
		op->opcode.u32 = TLS_OPCODE_AES_GCM_256_DECRYPT;
		op->data = (void *)record;

		if (0 > execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op)) {
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
			delete_op(op);
			return -1;
		}

		*((uint16_t *)(record->decrypted + 3)) = htons(record->cipher_text.length);

#if VERBOSE_AES
		fprintf(stderr, "\n[decrypt_record] Decrypted Data:\n");
		{
			/* int z; */
			for (z = 0; z < record->cipher_text.length + RECORD_HEADER_SIZE; z++)
				fprintf(stderr, "%02X%c", record->decrypted[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */

	} else {
		fprintf(stderr, "[decrypt record] can't support cipher type\n");
		exit(EXIT_FAILURE);
	}

    return handle_after_aes_crypto(sess, op);
}

static inline int
encrypt_record (struct ssl_session* sess, record_t* record)
{
    security_params_t *write_sp = &sess->write_sp;

#if VERBOSE_SSL
    fprintf(stderr, "Encrypt Record!\n");
#endif /* VERBOSE_SSL */
    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);
	if (!op) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
		return -1;
	}

	if (write_sp->cipher_type == BLOCK) {
		generic_block_cipher_t *block_cipher =
			&record->cipher_text.fragment.block_cipher;
		int pad_len = (record->cipher_text.length % 16) ?
			(16 - record->cipher_text.length % 16) : 0;

		block_cipher->padding = block_cipher->mac + MAC_SIZE;
		block_cipher->padding_length = pad_len;
		memset(block_cipher->padding, pad_len - 1, pad_len);

#if VERBOSE_AES
		fprintf(stderr, "\n[encrypt_record] decrypted:\n");
		{
			unsigned z;
			for (z = 0; z < 64; z++)
				fprintf(stderr, "%02X%c", record->decrypted[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */

		record->cipher_text.length += pad_len;

		record->decrypted -= write_sp->fixed_iv_length;
		block_cipher->IV = record->decrypted + RECORD_HEADER_SIZE;

		memcpy(record->decrypted,
			   record->decrypted + write_sp->fixed_iv_length,
			   RECORD_HEADER_SIZE);

#if VERBOSE_AES
		fprintf(stderr, "\n[encrypt_record] fixed_iv_length: %d, cipher_text.length: %d",
				write_sp->fixed_iv_length, record->cipher_text.length);
		fprintf(stderr, "\n[encrypt_record] IV: %p,\n content: %p,\n mac: %p,\n padding: %p\n",
				block_cipher->IV,
				block_cipher->content,
				block_cipher->mac,
				block_cipher->padding);
#endif /* VERBOSE_AES */

		/* Set initial iv as all 0 */
		/* Need to support normal packets */
		/* ToDo: generate IV with random function */
#if 0
/* #if MODIFY_FLAG */
		int i;
		int copy_byte;
		long int rand_tmp;
		for(i = 0; i < write_sp->fixed_iv_length; i += copy_byte) {
			rand_tmp = random();
			copy_byte = MIN(write_sp->fixed_iv_length - i, sizeof(long int));
			memcpy((unsigned char*)(block_cipher->IV) + i, &rand_tmp, copy_byte);
		}
#else
		memset(block_cipher->IV, 0, write_sp->fixed_iv_length);
#endif
		record->cipher_text.length += write_sp->fixed_iv_length;

		*(uint16_t *)(record->decrypted + 3) = htons(record->cipher_text.length);
		op->in = block_cipher->IV;
		op->out = record->data + RECORD_HEADER_SIZE;
		memcpy(record->data,
			   record->decrypted,
			   RECORD_HEADER_SIZE);

#if VERBOSE_AES
		unsigned z;
		fprintf(stderr, "\n[encrypt_record] Revised decrypted:\n");
		{
			for (z = 0; z < 80; z++)
				fprintf(stderr, "%02X%c", record->decrypted[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */

		op->iv = sess->server_write_IV;
		op->key = sess->server_write_key;
		op->in_len = record->cipher_text.length;
		op->key_len = write_sp->enc_key_size;
		op->iv_len = write_sp->fixed_iv_length;
		op->out_len = record->cipher_text.length;
		record->length = record->cipher_text.length + RECORD_HEADER_SIZE;

		op->opcode.u32 = TLS_OPCODE_AES_CBC_256_ENCRYPT;

		op->data = (void *)record;

		if (0 > execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op)) {
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
			delete_op(op);
			return -1;
		}

#if VERBOSE_AES
		fprintf(stderr, "\n[encrypt_record] Encrypted Data with Total Length %lu\n", record->length);
		{
			for (z = 0; z < 80; z++)
				fprintf(stderr, "%02X%c", record->data[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */
	} else if (write_sp->cipher_type == AEAD) {
		uint8_t nonce[write_sp->fixed_iv_length + write_sp->record_iv_length];
		uint8_t additional_data[sizeof(sequence_num_t) + RECORD_HEADER_SIZE];
		generic_aead_cipher_t *aead_cipher =
			&record->cipher_text.fragment.aead_cipher;
		sequence_num_t seqnum;

#if VERBOSE_AES
		fprintf(stderr, "[encrypt record] encrypt with gcm !!!!!!!!!!!!!!!!!!!!!!!\n");
		{
			int z;
			fprintf(stderr, "Implicit part iv (client_write_iv):\n");
			for (z = 0; z < write_sp->fixed_iv_length; z++) 
				fprintf(stderr, "%02X%c", sess->server_write_IV[z],
						((z + 1) % 16)? ' ' : '\n');
			fprintf(stderr, "\n");
		}
#endif /* VERBOSE_AES */

		record->cipher_text.length = record->plain_text.length;

#if SEG_RECORD_BUF
		record->data = record->buf + record->total_to_send;
#else
		record->data -= write_sp->record_iv_length;
#endif
		aead_cipher->nonce_explicit = record->data + RECORD_HEADER_SIZE;

		memcpy(nonce, sess->server_write_IV,
			   write_sp->fixed_iv_length);
		/* Set initial explicit iv as all 0 */
		/* ToDo: generate IV with random function */
#if 0
/* #if MODIFY_FLAG */
		int i;
		int copy_byte;
		long int rand_tmp;
		for(i = 0; i < write_sp->record_iv_length; i += copy_byte) {
			rand_tmp = random();
			copy_byte = MIN(write_sp->fixed_iv_length - i, sizeof(long int));
			memcpy((unsigned char*)(aead_cipher->nonce_explicit) + i, &rand_tmp, copy_byte);
		}
#else
		memset(aead_cipher->nonce_explicit, 0,
			   write_sp->record_iv_length);
#endif
		memcpy(nonce + write_sp->fixed_iv_length, aead_cipher->nonce_explicit,
			   write_sp->record_iv_length);
		record->cipher_text.length += write_sp->record_iv_length;

		record->cipher_text.length += GCM_TAG_SIZE;

		/* please refer pack_application_data() */
		/* handshake data is in "->decrypted", but app data is in "->fragment.application_data" only  */
		/* ToDo: need to reconsider data structure; remove "->decrypted"? or leave? */
		if (record->decrypted[0] == APPLICATION_DATA)
#if SEG_RECORD_BUF
			aead_cipher->content = record->fragment.application_data.data + record->total_payload_to_send;
#else
			aead_cipher->content = record->fragment.application_data.data;
#endif
		else
			aead_cipher->content = record->decrypted + RECORD_HEADER_SIZE;

		*(uint16_t *)(record->decrypted + 3) = htons(record->cipher_text.length);
		op->in = aead_cipher->content;
		op->out = record->data + RECORD_HEADER_SIZE + write_sp->record_iv_length;
		memcpy(record->data,
			   record->decrypted,
			   RECORD_HEADER_SIZE);
		seqnum = bswap_64(sess->send_seq_num_);

		/* make aad */
		memcpy(additional_data, &seqnum,
			   sizeof(seqnum));
		memcpy(additional_data + sizeof(sequence_num_t), record->data,
			   RECORD_HEADER_SIZE);
		if(additional_data[sizeof(additional_data) - 1] < sizeof(sequence_num_t) + GCM_TAG_SIZE) {
			additional_data[sizeof(additional_data) - 2] -= 1;
		}
		additional_data[sizeof(additional_data) - 1] -= sizeof(sequence_num_t) + GCM_TAG_SIZE;

#if VERBOSE_AES
		fprintf(stderr, "\n[encrypt_record] total_payload_to_send: %d, aead->content:\n",
			record->total_payload_to_send);
		{
			int z;
			for (z = 0; z < 50; z++)
				fprintf(stderr, "%02X%c", aead_cipher->content[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */

		op->in_len = record->plain_text.length;
		op->out_len = record->cipher_text.length;
		op->iv = nonce;
		op->iv_len = write_sp->fixed_iv_length + write_sp->record_iv_length;
		op->aad = additional_data;
		op->aad_len = sizeof(sequence_num_t) + RECORD_HEADER_SIZE;
		op->key = sess->server_write_key;
		op->key_len = write_sp->enc_key_size;

		op->opcode.u32 = TLS_OPCODE_AES_GCM_256_ENCRYPT;
		op->data = (void *)record;

		record->length = record->cipher_text.length + RECORD_HEADER_SIZE;

		if (0 > execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op)) {
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
			delete_op(op);
			return -1;
		}

#if VERBOSE_AES
		fprintf(stderr, "\n[encrypt_record] Encrypted Data with Total Length %lu\n", record->length);
		{
			int z;
			for (z = 0; z < record->length; z++)
				fprintf(stderr, "%02X%c", record->data[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
		fprintf(stderr, "\n[encrypt_record] total_to_send (before, after): %d, %ld, buf:\n",
			record->total_to_send, record->total_to_send + record->length);
		{
			int z;
			for (z = 0; z < record->total_to_send; z++)
				fprintf(stderr, "%02X%c", record->buf[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */
	}

    return handle_after_aes_crypto(sess, op);
}

static inline int
unpack_change_cipher_spec(void)
{
#if VERBOSE_SSL
    fprintf(stderr, "Unpack Change Cipher Spec\n");
#endif /* VERBOSE_SSL */

    return 0;
}

static inline int
unpack_alert(record_t* record)
{
#if VERBOSE_SSL
    fprintf(stderr, "Unpack Alert\n");
#endif /* VERBOSE_SSL */

    if (!record)
        return -1;
    record->fragment.alert.level =
                            *(record->decrypted + RECORD_HEADER_SIZE);
    record->fragment.alert.description =
                            *(record->decrypted + RECORD_HEADER_SIZE + 1);
    return 0;
}

static inline int
unpack_application_data(record_t* record)
{
#if VERBOSE_SSL
    fprintf(stderr, "Unpack Application Data\n");
#endif /* VERBOSE_SSL */

    if (!record)
        return -1;
    record->fragment.application_data.data =
                            record->decrypted + RECORD_HEADER_SIZE;
    return 0;
}

static inline int
unpack_record(record_t* record)
{
    uint8_t *decrypted = record->decrypted;
    uint8_t *data = record->data;
    plain_text_t *plain_text = &record->plain_text;
    uint8_t c_type;

    assert(record != NULL);
    assert(record->state == TO_UNPACK_CONTENT);
#if VERBOSE_SSL
    fprintf(stderr, "Unpack Record\n");
#endif /* VERBOSE_SSL */

    record->state = READ_READY;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_UNPACK_CONTENT),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    if (decrypted != data && plain_text->version.major == 0x03) {
        plain_text->c_type = decrypted[0];
        plain_text->version.major = decrypted[1];
        plain_text->version.minor = decrypted[2];
        if (record->is_encrypted) {
			plain_text->length = record->cipher_text.length;

		}
        else {
            plain_text->length = ntohs(*(uint16_t *)(decrypted +3));
        }
    }
    if (plain_text->version.major == 0x03)
        plain_text->fragment = decrypted + RECORD_HEADER_SIZE;
    else
        assert(0);

    c_type = plain_text->c_type;

    int ret = -1;
    switch(c_type) {
        case HANDSHAKE:
            ret = unpack_handshake(record);
            break;
        case CHANGE_CIPHER_SPEC:
            ret = unpack_change_cipher_spec();
            break;
        case ALERT:
            /* fprintf(stderr, "Not supported yet: ALERT\n"); */
			ret = unpack_alert(record);
            break;
        case APPLICATION_DATA:
            ret = unpack_application_data(record);
            break;
        default:
            assert(0);
    }

    return ret;
}

static inline int
pack_change_cipher_spec(record_t* record, int offset)
{
#if VERBOSE_SSL
    fprintf(stderr, "Pack Change Cipher Spec\n");
#endif /* VERBOSE_SSL */

    memcpy(record->decrypted + offset,
           &record->fragment,
           sizeof(change_cipher_spec_t));
    offset += sizeof(change_cipher_spec_t);
    return 0;
}

static inline int
pack_application_data(record_t* record, int offset)
{
#if VERBOSE_SSL
	fprintf(stderr, "Pack Application Data\n");
#endif /* VERBOSE_SSL */

	security_params_t *write_sp = &record->sess->write_sp;

	if(write_sp->bulk_cipher_algorithm == NO_CIPHER) {
		fprintf(stderr, "[pack application data] no cipher for app data?\n");
		return -1;
	}
	else {
		/* CBC mode use unnecessary memcpy() */
		if (write_sp->cipher_type == BLOCK) {
			memcpy(record->decrypted + offset,
				   record->fragment.application_data.data,
				   record->length - RECORD_HEADER_SIZE);
		} else if (write_sp->cipher_type == AEAD) {
			record->plain_text.fragment =
				record->fragment.application_data.data;
		}
	}

	return 0;
}

static inline int
pack_alert(record_t* record, int offset)
{
#if VERBOSE_SSL
    fprintf(stderr, "Pack Alert\n");
#endif /* VERBOSE_SSL */

    memcpy(record->decrypted + offset,
           &record->fragment,
           sizeof(alert_t));
    offset += sizeof(alert_t);
    return 0;
}

static inline int
pack_record(record_t* record)
{
    uint8_t* decrypted;
    plain_text_t* plain_text = &record->plain_text;

    assert(record->state == TO_PACK_HEADER);
    record->state = TO_APPEND_MAC;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_PACK_HEADER),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

#if VERBOSE_SSL
    fprintf(stderr, "PACK RECORD\n");
#endif /* VERBOSE_SSL */
    record->decrypted = record->mac_in + sizeof(sequence_num_t);
    decrypted = record->decrypted;

    int offset = 0;

    decrypted[0] = plain_text->c_type;
    offset += sizeof(plain_text->c_type);

    memcpy(decrypted + offset, &plain_text->version,
           sizeof(plain_text->version));
    offset += sizeof(plain_text->version);

    *(uint16_t *)(decrypted + offset) = htons(plain_text->length);
    offset += sizeof(uint16_t);

    int ret = -1;
    switch (plain_text->c_type) {
        case HANDSHAKE:
            ret = pack_handshake(record, offset);
            break;
        case CHANGE_CIPHER_SPEC:
			ret = pack_change_cipher_spec(record, offset);
			break;
        case ALERT:
			ret = pack_alert(record, offset);
			break;
        case APPLICATION_DATA:
			ret = pack_application_data(record, offset);
			break;
    }

    return ret;
}

static inline int
unpack_handshake(record_t* record)
{
    plain_text_t* plain_text = &record->plain_text;
    uint8_t *pf = plain_text->fragment;
    uint8_t *hl = record->fragment.handshake.length.u8;
    int off = 4;
    int end = plain_text->length;
    client_hello_t* pch = &record->fragment.handshake.body.client_hello;
    client_key_exchange_t *pcke =
                    &record->fragment.handshake.body.client_key_exchange;
    finished_t* pcf = &record->fragment.handshake.body.client_finished;

#if VERBOSE_SSL
    fprintf(stderr, "Unpack Handshake\n");
#endif /* VERBOSE_SSL */

    record->fragment.handshake.msg_type = pf[0];
    hl[0] = pf[1];
    hl[1] = pf[2];
    hl[2] = pf[3];

    switch(record->fragment.handshake.msg_type) {
        case CLIENT_HELLO:
#if VERBOSE_SSL
            fprintf(stderr, "Client Hello!\n");
#endif /* VERBOSE_SSL */
            if (plain_text->version.major == 0x03 &&
                plain_text->version.minor == 0x01) {

                pch->version = *(protocol_version_t *)(pf + off);
                off += sizeof(protocol_version_t);

                memcpy(&pch->random, pf + off, sizeof(pch->random));
                off += sizeof(pch->random);

                pch->session_id_length = pf[off];
                off += sizeof(uint8_t);

                if (pch->session_id_length > 0) {
                    memcpy(&pch->session_id, pf + off, pch->session_id_length);
                    off += pch->session_id_length;
                }

                pch->cipher_suite_length = htons(*(uint16_t *)(pf +off));
                off += sizeof(uint16_t);

                assert(pch->cipher_suites == NULL);
                if (pch->cipher_suite_length > 0) {
                    pch->cipher_suites = (cipher_suite_t *)(pf + off);
                    off += pch->cipher_suite_length;
                }
                pch->compression_method_length = pf[off];
                off += sizeof(uint8_t);

                assert(pch->compression_methods == NULL);
                if (pch->compression_method_length > 0) {
                    pch->compression_methods =
                                    (compression_method_t *)(pf + off);
                    off += pch->compression_method_length *
                                    sizeof(compression_method_t);
                }

                if (off < end) {
                    pch->extension_length = ntohs(*(uint16_t *)(pf + off));
                    off += sizeof(uint16_t);

                    assert(pch->extension == NULL);
                    if (pch->extension_length > 0) {
                        pch->extension = pf + off;
                        off += pch->extension_length;
                    }
                }
            }
			else {
                fprintf(stderr, "This version does not supported\n");
            }

#if VERBOSE_SSL
            fprintf(stderr, "Client Version: %u.%u,\n", 
                            pch->version.major, pch->version.minor);
            fprintf(stderr, "Session ID Length: %u,\n",
                            pch->session_id_length);
            fprintf(stderr, "Cipher Length: %x,\n",
                            pch->cipher_suite_length);
            fprintf(stderr, "Compression Length: %x,\n",
                            pch->compression_method_length);
            fprintf(stderr, "off: %u, off_value: %u\n\n",
                            off, *(pf + off));
#endif /* VERBOSE_SSL */
            break;

        case CLIENT_KEY_EXCHANGE:
#if VERBOSE_SSL
            fprintf(stderr, "Client Key Exchange!\n");
#endif /* VERBOSE_SSL */

            /* Assume RSA */
            assert(pcke->key.rsa.encrypted_premaster_secret == NULL);
            if (end > off) {
                pcke->key.rsa.encrypted_premaster_secret = pf + off;
                off += (end - off);
            }
            break;
        case CLIENT_FINISHED:
#if VERBOSE_SSL
            fprintf(stderr, "\nClient FINISHED!\n");
#endif /* VERBOSE_SSL */

            memcpy(&pcf->verify_data, pf + off, sizeof(pcf->verify_data));
            off += sizeof(pcf->verify_data);

            break;

        case HELLO_REQUEST:
        case CERTIFICATE:
        case SERVER_HELLO:
        case SERVER_KEY_EXCHANGE:
        case CERTIFICATE_REQUEST:
        case SERVER_HELLO_DONE:
        case CERTIFICATE_VERIFY:
            fprintf(stderr, "Not Supported Handshake Message\n");
            break;

        default:
            fprintf(stderr, "No matching Type of Handshake: %X\n",
                                    record->fragment.handshake.msg_type);
            break;

        assert(off == end);

        return 0;
    }

    return 0;
}

static inline int
pack_handshake(record_t* record, int offset)
{
    uint8_t* decrypted = record->decrypted;
    handshake_t *phs = &record->fragment.handshake;
    record->plain_text.fragment = decrypted + offset;

#if VERBOSE_SSL
    fprintf(stderr, "PACK HANDSHAKE\n");
#endif /* VERBOSE_SSL */
    decrypted[offset++] = phs->msg_type;
    memcpy(decrypted + offset, &phs->length, sizeof(phs->length));
    offset += sizeof(phs->length);

    switch (phs->msg_type) {
        case HELLO_REQUEST:
        case CLIENT_HELLO:
            assert(0);
            break;
        case SERVER_HELLO: {
            server_hello_t* psh = &phs->body.server_hello;

            memcpy(decrypted + offset,
                   &psh->version,
                   sizeof(psh->version));
            offset += sizeof(psh->version);

            memcpy(decrypted + offset,
                   &psh->random,
                   sizeof(psh->random));
            offset += sizeof(psh->random);

            *(uint8_t *)(decrypted + offset) = 
                    psh->session_id_length;
            offset += sizeof(uint8_t);

            memcpy(decrypted + offset,
                   &psh->session_id,
                   sizeof(psh->session_id));
            offset += sizeof(psh->session_id);

            *(cipher_suite_t *)(decrypted + offset) = 
                    psh->cipher_suite;
            offset += sizeof(psh->cipher_suite);

            *(compression_method_t *)(decrypted + offset) =
                    psh->compression_method;
            offset += sizeof(psh->compression_method);

            break;
        }
        case CERTIFICATE: {
            certificate_list_t *pc = &phs->body.certificate;

            memcpy(decrypted + offset,
                   &pc->certificate_length,
                   sizeof(pc->certificate_length));
            offset += sizeof(pc->certificate_length);

            int remain_cert_len = get_u32(pc->certificate_length);

            certificate_t *cert;
            cert = pc->certificates;
            while (remain_cert_len > 0) {
                memcpy(decrypted + offset,
                       &cert->length,
                       sizeof(cert->length));
                offset += sizeof(cert->length);
                remain_cert_len -= sizeof(cert->length);

                memcpy(decrypted + offset,
                       cert->certificate,
                       get_u32(cert->length));
                offset += get_u32(cert->length);
                remain_cert_len -= get_u32(cert->length);

                cert = (certificate_t *)(((uint8_t *)pc->certificates) +
                                         get_u32(cert->length) +
                                         sizeof(cert->length));
            }
            break;
        }
        case SERVER_HELLO_DONE: {
            break;
        }
        case CLIENT_FINISHED:
        case SERVER_FINISHED: {
            finished_t *pf = &phs->body.server_finished;
            memcpy(decrypted + offset,
                   pf->verify_data, sizeof(pf->verify_data));
            offset += sizeof(pf->verify_data);
            break;
        }
        case SERVER_KEY_EXCHANGE:
        case CERTIFICATE_REQUEST:
        case CERTIFICATE_VERIFY:
        case CLIENT_KEY_EXCHANGE:
            fprintf(stderr, "Unsupported Handshake.\n");
            assert(0);
            break;
        default:
            fprintf(stderr, "Unmatched Handshake.\n");
            assert(0);
            break;
    }

    return offset;
}

/* Clear all parameter except SSL_CTX related parameters. e.g.) mctx, coreid */
inline void
clear_session(struct ssl_session *ssl)
{
	int i;

	ssl->sockid = 0;

	ssl->state = STATE_INIT;
	ssl->handshake_state = HELLO_REQUEST;

	if (ssl->current_read_record) {
		delete_record(ssl, ssl->current_read_record);
		ssl->current_read_record = NULL;
	}

	if (ssl->current_send_record) {
		delete_record(ssl, ssl->current_send_record);
		ssl->current_send_record = NULL;
	}

	ssl->version.major = 0;
	ssl->version.minor = 0;

	ssl->recv_seq_num_ = 0;
	ssl->send_seq_num_ = 0;

	ssl->handshake_msgs_len = 0;

	ssl->client_write_IV_seq_num = 0;
	ssl->server_write_IV_seq_num = 0;

	ssl->rand_seed = rand();

	memset(&ssl->read_sp, 0, sizeof(ssl->read_sp));
	memset(&ssl->write_sp, 0, sizeof(ssl->write_sp));
	memset(&ssl->pending_sp, 0, sizeof(ssl->pending_sp));

	ssl->read_sp.entity = SERVER;
	ssl->write_sp.entity = SERVER;

	record_t *cur, *next;
	cur = TAILQ_FIRST(&ssl->recv_q);
	while(cur != NULL) {
		next = TAILQ_NEXT(cur, recv_q_link);

		TAILQ_REMOVE(&ssl->recv_q, cur, recv_q_link);

		memset(cur, 0, sizeof(record_t));
		cur->ctx = ssl->ctx;

		TAILQ_INSERT_TAIL(&ssl->ctx->record_pool, cur, record_pool_link);
		ssl->ctx->free_record_cnt++;
		ssl->ctx->using_record_cnt--;

		cur = next;
	}

	ssl->num_current_records = 0;
	ssl->recv_q_cnt = 0;

	for (i = 0; i < sizeof(mtcp_SSL_RET); i++)
		ssl->msg_num[i] = -1;

	ssl->read_buf_offset = 0;

	init_random(ssl, ssl->id_.id, sizeof(ssl->id_.id));
}

int
close_session(struct ssl_session* sess)
{
	/* Make ALERT */
	record_t *alert = new_send_record(sess);
	int	length = 0;
	int ret;

#if VERBOSE_SSL
		fprintf(stderr, "CLOSE SESSION\n\n");
#endif /* VERBOSE_SSL */

    alert->fragment.alert.level = WARNING;
    length += sizeof(alert->fragment.alert.level);
	if (sess->state == STATE_HANDSHAKE)
	    alert->fragment.alert.description = HANDSHAKE_FAILURE;
	else
	    alert->fragment.alert.description = CLOSE_NOTIFY;
    length += sizeof(alert->fragment.alert.description);

    ret = send_record(sess, alert, ALERT, length);
	if(ret < 0) {
		fprintf(stderr, "send_record for alert failed.\n");
		assert(0);
	}

	if (sess->state == STATE_CLOSE_RECEIVED) {
		sess->state = STATE_CLOSED;
		ret = 1;
	} else if ((sess->state == STATE_ACTIVE) ||
				(sess->state == STATE_CLOSE_SENT)) {
		sess->state = STATE_CLOSE_SENT;
		ret = 0;
	} else if ((sess->state == STATE_HANDSHAKE)) {
		sess->state = STATE_CLOSED;
		ret = 1;
	} else {
		/* only TCP connection is accepted and no TLS handshake, but goint to shutdown TLS */
	}

	return ret;
}

static inline int
handle_close_notify(struct ssl_session *sess)
{
	if (sess->state == STATE_CLOSE_SENT) {
		sess->state = STATE_CLOSED;
	} else if ((sess->state == STATE_ACTIVE) ||
				(sess->state == STATE_CLOSE_RECEIVED)) {
		sess->state = STATE_CLOSE_RECEIVED;
	}

	return 0;
}

static inline int
handle_fatal_error(struct ssl_session *sess)
{
	int ret = 0;

	ret = close_session(sess);
	sess->state = STATE_CLOSED;

	return ret;
}

static inline int
handle_alert(struct ssl_session* sess, record_t *record)
{
	unsigned char level = record->fragment.alert.level;
	unsigned char description = record->fragment.alert.description;
	int ret = 0;
#if VERBOSE_SSL
    fprintf(stderr, "Handle Alert, level = %u, description = %u\n",
			level, description);
#endif /* VERBOSE_SSL */

	switch(description) {
	    case CLOSE_NOTIFY:
			ret = handle_close_notify(sess);
    	case UNEXPECTED_MESSAGE:
    	case BAD_RECORD_MAC:
    	case RECORD_OVERFLOW:
    	case DECOMPRESSION_FAILURE:
    	case HANDSHAKE_FAILURE:
    	case ILLEGAL_PARAMETER:
    	case UNKNOWN_CA:
    	case ACCESS_DENIED:
    	case DECODE_ERROR:
    	case DECRYPT_ERROR:
    	case PROTOCOL_VERSION:
    	case INSUFFICIENT_SECURITY:
    	case INTERNEL_ERROR:
    	case UNSUPPORTED_EXTENSION:
			ret = handle_fatal_error(sess);
			break;
    	case NO_RENEGOTIATION:
			/* now server do not renegotiate, so ignore */
			break;
    	default:
			if(level != WARNING) {
				ret = handle_fatal_error(sess);
			}
			break;
	}

    delete_record(sess, record);
    return ret;
}

static inline int
handle_data(struct ssl_session* sess, record_t *record)
{
    unsigned char *data = record->fragment.application_data.data;
    unsigned data_len = record->plain_text.length;

#if VERBOSE_SSL
	fprintf(stderr, "handle_data: %d\n"
					"offset %d -> %d\n",
					data_len,
					sess->read_buf_offset,
					sess->read_buf_offset + data_len);
#endif /* VERBOSE_SSL */

	if (RECORD_SIZE_LIMIT - sess->read_buf_offset < data_len) {
		return -1;
	}
	memcpy(sess->read_buf + sess->read_buf_offset, data, data_len);
	sess->read_buf_offset += data_len;

#if VERBOSE_DATA
    unsigned z;
    fprintf(stderr, "\nAPP DATA LEN: %u\n", data_len);
    for (z = 0; z < data_len; z++)
        fprintf(stderr, "%c", data[z]);
#endif /* VERBOSE_DATA */

    delete_record(sess, record);
    /* abort_session(sess); */

    return 0;
}

static inline int
handle_read_record(struct ssl_session* sess, record_t* record)
{
    int ret = -1;

    assert(record != NULL);
#if VERBOSE_SSL
    fprintf(stderr, "Handle Read Record\n");
#endif /* VERBOSE_SSL */

    assert(record->state == READ_READY);

    switch(record->plain_text.c_type) {
        case HANDSHAKE:
            ret = handle_handshake(sess, record);
            break;

        case CHANGE_CIPHER_SPEC:
            ret = handle_change_cipher_spec(sess, record);
            break;

        case ALERT:
			ret = handle_alert(sess, record);
			break;
        case APPLICATION_DATA:
            ret = handle_data(sess, record);
            break;

        default:
            fprintf(stderr, "Unmatched Record Type\n");
            break;
    }

    return ret;
}


#if SEG_RECORD_BUF
inline int
fill_application_record(struct ssl_session* sess, record_t* record,
            uint8_t c_type, int length)
{
    /* int ret = -1; */
    assert(record != NULL);
	assert(length <= MAX_PLAIN_DATA_LEN);

#if VERBOSE_SSL
    fprintf(stderr, "FILL APPLICATION RECORD\n");
#endif /* VERBOSE_SSL */

    record->plain_text.length = length;
    record->plain_text.c_type = c_type;
    record->plain_text.version = sess->version;
    record->length = length + RECORD_HEADER_SIZE;

    if (0 > pack_record(record))
        assert(0);

    if (record->plain_text.c_type == HANDSHAKE) {
		fprintf(stderr, "weird2..\n");
		exit(EXIT_FAILURE);
    }

	if(sess->write_sp.bulk_cipher_algorithm == NO_CIPHER) {
		fprintf(stderr, "weird3..\n");
		exit(EXIT_FAILURE);
	}

	/* it is not supported in cbc now.. */
	if (sess->pending_sp.cipher_type != AEAD) {
		fprintf(stderr, "weird4..\n");
		exit(EXIT_FAILURE);
	}

	record->state = TO_ENCRYPT;
	if(encrypt_record(sess, record) < 0) {
		return -1;
	}

#if VERBOSE_CHUNK
    fprintf(stderr, "\nSending Payload\n");
    {
		unsigned z;
        for (z = 0; z < record->length; z++)
        fprintf(stderr, "%02X%c", *((uint8_t *)record->data + z),
                        ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_CHUNK */

	return record->length;
}
#endif	/* SEG_RECORD_BUF */

inline int
send_record(struct ssl_session* sess, record_t* record,
            uint8_t c_type, int length)
{
    int ret = -1;
    assert(record != NULL);
	assert(length <= MAX_PLAIN_DATA_LEN);

	if (record->total_to_send) {
		/* Delivery ongoing record */
		goto tcp_send;
	}
#if VERBOSE_SSL
    fprintf(stderr, "SEND RECORD\n");
#endif /* VERBOSE_SSL */

    record->plain_text.length = length;
    record->plain_text.c_type = c_type;
    record->plain_text.version = sess->version;
    record->length = length + RECORD_HEADER_SIZE;

    if (0 > pack_record(record))
        assert(0);

    if (record->plain_text.c_type == HANDSHAKE) {
        if (0 > store_handshake(sess, record)) {
#if VERBOSE_SSL
            fprintf(stderr, "handshake retransmission\n");
#endif /* VERBOSE_SSL */
        }
    }

	if(sess->write_sp.bulk_cipher_algorithm != NO_CIPHER) {
		if(sess->write_sp.mac_algorithm == NO_MAC) {
			fprintf(stderr, "[send record] Error: the packet has no need to attach MAC!\n");
			exit(EXIT_FAILURE);
		}
		if (sess->pending_sp.cipher_type != AEAD) {
			ret = attach_mac(sess, record);
			if (ret < 0)
				return -1;
		}
		if(encrypt_record(sess, record) < 0) {
			return -1;
		}
	} else {
		record->data = record->decrypted;
		record->state = WRITE_READY;
	}

#if VERBOSE_CHUNK
    fprintf(stderr, "\nSending Payload\n");
    {
		unsigned z;
        for (z = 0; z < record->length; z++)
        fprintf(stderr, "%02X%c", *((uint8_t *)record->data + z),
                        ((z + 1) % 16) ? ' ' : '\n');
    }
    fprintf(stderr, "\n");
#endif /* VERBOSE_CHUNK */

	record->total_to_send = record->length;

tcp_send:
	ret = -1;
    ret = mtcp_write(sess->mctx,
                     sess->sockid,
					(char *)record->data + record->already_sent,
					record->total_to_send - record->already_sent);

	if (ret < 0) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE;
		return FAIL;
	}

#if VERBOSE_SSL
	fprintf(stderr, "Socket %d sent %d bytes among %d bytes\n",
					sess->sockid, ret, record->total_to_send - record->already_sent);
#endif /* VERBOSE_SSL */

	record->already_sent += ret;

	if (record->already_sent > record->total_to_send) {
		fprintf(stderr, "Weird State!!\n");
		exit(EXIT_FAILURE);
	} else if (record->already_sent == record->total_to_send) {
		/* Sent a whole record */
	    delete_record(sess, record);
		sess->current_send_record = NULL;
		return length;
	} else {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_WANT_WRITE;
		return FAIL;
	}

    return FAIL;
}

static inline int
handle_change_cipher_spec(struct ssl_session* sess, record_t* record)
{
#if VERBOSE_SSL
    fprintf(stderr, "Handle CHANGE_CIPHER_SPEC\n\n");
#endif /* VERBOSE_SSL */
    if (sess->state >= CLIENT_CIPHER_SPEC)
        goto cipher_spec_record_finish;


    sess->handshake_state = CLIENT_CIPHER_SPEC;
    sess->recv_seq_num_ = 0;
    sess->client_write_IV_seq_num = 0;
    memcpy(&sess->read_sp, &sess->pending_sp, sizeof(sess->read_sp));
cipher_spec_record_finish:
    delete_record(sess, record);
    record = NULL;
    return 0;
}

static inline int
handle_handshake(struct ssl_session* sess, record_t* record)
{
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;
    client_hello_t* client_hello;
    premaster_secret_t *ps;
    security_params_t *pending_sp = &sess->pending_sp;
    security_params_t *write_sp = &sess->write_sp;
    uint8_t *vd;
    uint8_t *my_vd;

    int length = 0;
    int random_size = sizeof(pending_sp->client_random) +
                      sizeof(pending_sp->server_random);
    uint8_t randoms[random_size];
	const EVP_MD* (*hash_func)(void);
    unsigned z;

#if VERBOSE_SSL
    fprintf(stderr, "Handle Handshake, type: %d, len: %d\n",
                        record->fragment.handshake.msg_type,
                        record->plain_text.length);
#endif /* VERBOSE_SSL */

    if (0 > store_handshake(sess, record)) {
#if VERBOSE_SSL
        fprintf(stderr, "handshake retransmission\n");
#endif /* VERBOSE_SSL */
    }
    switch(record->fragment.handshake.msg_type) {
        case CLIENT_HELLO: {
            if (sess->state >= CLIENT_HELLO)
                goto handshake_record_finish;
            sess->state = STATE_HANDSHAKE;
            sess->handshake_state = CLIENT_HELLO;
            if (record->plain_text.version.major == 0x03) {
                client_hello = &(record->fragment.handshake.body.client_hello);
                cipher = select_cipher(client_hello->cipher_suite_length,
                                       client_hello->cipher_suites);
				pending_sp->cipher = cipher;

                if (COMPARE_CIPHER(cipher, TLS_RSA_WITH_AES_256_CBC_SHA)) {
                    pending_sp->entity = SERVER;
                    pending_sp->prf_algorithm = PRF_SHA256;
                    pending_sp->bulk_cipher_algorithm = AES;
                    pending_sp->cipher_type = BLOCK;
                    pending_sp->enc_key_size = 32;
                    pending_sp->block_length = 16; /* Actually, not used */
                    pending_sp->fixed_iv_length = 16;
                    pending_sp->record_iv_length = 16; /* Actually, not used */
                    pending_sp->mac_length = 20; /* Actually, not used */
                    pending_sp->mac_key_size = 20;
                    pending_sp->mac_algorithm = MAC_SHA1;
                    pending_sp->compression_algorithm = NO_COMP;

                    memcpy(pending_sp->client_random,
                           &(client_hello->random),
                           sizeof(pending_sp->client_random));

                    uint32_t now = time(NULL);
                    memcpy(pending_sp->server_random, &now, sizeof(uint32_t));
                    init_random(sess, (pending_sp->server_random) + sizeof(uint32_t),
                                sizeof(pending_sp->server_random) - sizeof(uint32_t));
                } else if (COMPARE_CIPHER(cipher, TLS_RSA_WITH_AES_256_GCM_SHA384)) {
                    pending_sp->entity = SERVER;
                    pending_sp->prf_algorithm = PRF_SHA384;
                    pending_sp->bulk_cipher_algorithm = AES;
                    pending_sp->cipher_type = AEAD;
                    pending_sp->enc_key_size = 32;
                    pending_sp->block_length = 16; /* Actually, not used */
                    pending_sp->fixed_iv_length = 4; /* length of implicit part of nonce */
                    pending_sp->record_iv_length = 8; /* length of explicit part of nonce */
                    pending_sp->mac_length = 48; /* not used? */
                    pending_sp->mac_key_size = 48;
                    pending_sp->mac_algorithm = MAC_SHA384;
                    pending_sp->compression_algorithm = NO_COMP;

                    memcpy(pending_sp->client_random,
                           &(client_hello->random),
                           sizeof(pending_sp->client_random));

                    uint32_t now = time(NULL);
                    memcpy(pending_sp->server_random, &now, sizeof(uint32_t));
                    init_random(sess, (pending_sp->server_random) + sizeof(uint32_t),
                                sizeof(pending_sp->server_random) - sizeof(uint32_t));
				} else {
					sess->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_CIPHER;
					return -1;
                }
                sess->version = client_hello->version;
            } else if (record->plain_text.version.major == 0x02) {
                fprintf(stderr, "Not supported version\n");
            } else
                assert(0);

#if VERBOSE_SSL
            fprintf(stderr, "CLIENT HELLO RECEIVED\n\n");
            fprintf(stderr, "Prepare SERVER HELLO\n");
#endif /* VERBOSE_SSL */

            // send server hello
            record_t* server_hello = new_send_record(sess);
			if (!server_hello) {
				sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
				return -1;
			}
            int length = 0;
            server_hello_t *psh =
                    &server_hello->fragment.handshake.body.server_hello;

            memcpy(&psh->random, pending_sp->server_random,
                   sizeof(pending_sp->server_random));
            length += sizeof(psh->random);

            psh->session_id_length = sizeof(session_id_t);
            length += sizeof(psh->session_id_length);

            psh->session_id = sess->id_;
            length += sizeof(psh->session_id);

            psh->cipher_suite = cipher;
            length += sizeof(psh->cipher_suite);

            psh->compression_method.cm = NO_COMP;
            length += sizeof(psh->compression_method);

            psh->version = sess->version;
            length += sizeof(psh->version);

            if (0 > send_handshake(sess, server_hello, SERVER_HELLO, length)) {
                fprintf(stderr, "send_handshake for server_hello failed\n");
                exit(EXIT_FAILURE);
            }
            sess->handshake_state = SERVER_HELLO;
#if VERBOSE_SSL
            fprintf(stderr, "SERVER HELLO SENT\n\n");
            fprintf(stderr, "Prepare CERTIFICATE\n");
#endif /* VERBOSE_SSL */

            //send certificate
            record_t* certificates = new_send_record(sess);
            length = 0;
            certificate_list_t *pcert =
                &certificates->fragment.handshake.body.certificate;
            certificate_t temp_certificate;

            pcert->certificates = &temp_certificate;
            pcert->certificates->certificate = sess->ctx->public_crypto_ctx.certificate;
            length += sess->ctx->public_crypto_ctx.certificate_length;

            set_u32(&pcert->certificates->length, (uint32_t *)&length);
            length += sizeof(pcert->certificates[0].length);

            set_u32(&pcert->certificate_length, (uint32_t *)&length);
            length += sizeof(pcert->certificate_length);

            if (0 > send_handshake(sess, certificates, CERTIFICATE, length)) {
                fprintf(stderr, "send_handshake for certificate failed\n");
                exit(EXIT_FAILURE);
            }
            sess->handshake_state = CERTIFICATE;
#if VERBOSE_SSL
            fprintf(stderr, "CERTIFICATE SENT\n\n");
            fprintf(stderr, "Prepare SERVER HELLO DONE\n");
#endif /* VERBOSE_SSL */

            //send server hello done
            record_t *server_hello_done = new_send_record(sess);
            length = 0;
            if (0 > send_handshake(sess,
                                   server_hello_done,
                                   SERVER_HELLO_DONE,
                                   length)) {
                fprintf(stderr,
                        "send_handshake for server_hello_done failed\n");
                exit(EXIT_FAILURE);
            }
            sess->handshake_state = SERVER_HELLO_DONE;
#if VERBOSE_SSL
            fprintf(stderr, "SERVER HELLO DONE SENT\n\n");
#endif /* VERBOSE_SSL */

            break;
        }
        case CLIENT_KEY_EXCHANGE:
            if (sess->state >= CLIENT_KEY_EXCHANGE)
                goto handshake_record_finish;

            sess->handshake_state = CLIENT_KEY_EXCHANGE;
            ps = &record->fragment.handshake.body.client_key_exchange.ps;
            memcpy(randoms,
                   pending_sp->client_random,
                   sizeof(pending_sp->client_random));
            memcpy(randoms + sizeof(pending_sp->client_random),
                   pending_sp->server_random,
                   sizeof(pending_sp->server_random));

			if (pending_sp->prf_algorithm == PRF_SHA256) {
				hash_func = EVP_sha256;
			} else if  (pending_sp->prf_algorithm == PRF_SHA384) {
				hash_func = EVP_sha384;
			} else {
				fprintf(stderr, "during client_key_exchange, not supported prf algorithm\n");
				exit(EXIT_FAILURE);
			} 

            PRF(hash_func, 48, (const uint8_t *)ps,
                13, (const uint8_t *)"master secret",
                64, randoms,
                48, pending_sp->master_secret);

            memcpy(randoms,
                   pending_sp->server_random,
                   sizeof(pending_sp->server_random));
            memcpy(randoms + sizeof(pending_sp->server_random),
                   pending_sp->client_random,
                   sizeof(pending_sp->client_random));

            int key_block_len = (pending_sp->mac_key_size * 2) +
                                (pending_sp->enc_key_size * 2) +
                                (pending_sp->fixed_iv_length * 2);
            uint8_t key_block[MAX_KEY_BLOCK_LEN];
            PRF(hash_func, 48, pending_sp->master_secret,
                13, (const uint8_t *)"key expansion",
                64, randoms,
                key_block_len, key_block);

#if VERBOSE_KEY
            fprintf(stderr, "\npre-master\n");
            {
                for (z = 0; z < 48; z++)
                    fprintf(stderr, "%02X%c", *((uint8_t *)ps + z),
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nclient random\n");
            {
                for (z = 0; z < 32; z++)
                    fprintf(stderr, "%02X%c", pending_sp->client_random[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nserver random\n");
            {
                for (z = 0; z < 32; z++)
                    fprintf(stderr, "%02X%c", pending_sp->server_random[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nmaster\n");
            {
                for (z = 0; z < 48; z++)
                    fprintf(stderr, "%02X%c", pending_sp->master_secret[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\nkey block\n");
            {
                for (z = 0; z < (unsigned)key_block_len; z++)
                    fprintf(stderr, "%02X%c", key_block[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_KEY */

            int offset = 0;
			if (pending_sp->cipher_type != AEAD) {
				memcpy(&sess->client_write_MAC_secret,
					   key_block + offset,
					   pending_sp->mac_key_size);
				offset += pending_sp->mac_key_size;

				memcpy(&sess->server_write_MAC_secret,
					   key_block + offset,
					   pending_sp->mac_key_size);
				offset += pending_sp->mac_key_size;
			} 
            memcpy(&sess->client_write_key,
                   key_block + offset,
                   pending_sp->enc_key_size);
            offset += pending_sp->enc_key_size;

            memcpy(&sess->server_write_key,
                   key_block + offset,
                   pending_sp->enc_key_size);
            offset += pending_sp->enc_key_size;

            memcpy(&sess->client_write_IV,
                   key_block + offset,
                   pending_sp->fixed_iv_length);
            offset += pending_sp->fixed_iv_length;

            memcpy(&sess->server_write_IV,
                   key_block + offset,
                   pending_sp->fixed_iv_length);
            offset += pending_sp->fixed_iv_length;

#if VERBOSE_KEY
			if (pending_sp->cipher_type != AEAD) {
				fprintf(stderr, "\n\nclient_MAC_secret\n");
				{
					for (z = 0; z < pending_sp->mac_key_size; z++)
						fprintf(stderr, "%02X%c", sess->client_write_MAC_secret[z],
								((z + 1) % 16) ? ' ' : '\n');
				}

				fprintf(stderr, "\n\nserver_MAC_secret\n");
				{
					for (z = 0; z < pending_sp->mac_key_size; z++)
						fprintf(stderr, "%02X%c", sess->server_write_MAC_secret[z],
								((z + 1) % 16) ? ' ' : '\n');
				}
			}

            fprintf(stderr, "\n\nclient_key\n");
            {
                for (z = 0; z < pending_sp->enc_key_size; z++)
                    fprintf(stderr, "%02X%c", sess->client_write_key[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\n\nserver key\n");
            {
                for (z = 0; z < pending_sp->enc_key_size; z++)
                    fprintf(stderr, "%02X%c", sess->server_write_key[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\n\nclient IV\n");
            {
                for (z = 0; z < pending_sp->fixed_iv_length; z++)
                    fprintf(stderr, "%02X%c", sess->client_write_IV[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }

            fprintf(stderr, "\n\nserver IV\n");
            {
                for (z = 0; z < pending_sp->fixed_iv_length; z++)
                    fprintf(stderr, "%02X%c", sess->server_write_IV[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_KEY */
#if VERBOSE_SSL
            fprintf(stderr, "\nCLIENT KEY EXCHANGE RECEIVED\n\n");
#endif /* VERBOSE_SSL */

            break;
        case CLIENT_FINISHED:
            if (sess->state >= CLIENT_FINISHED)
                goto handshake_record_finish;

            vd = record->fragment.handshake.body.client_finished.verify_data;
            sess->handshake_state = CLIENT_FINISHED;
#if VERBOSE_SSL
            fprintf(stderr, "CLIENT FINISHED!!\n");
#endif /* VERBOSE_SSL */

            /* Verify Handshake */
            uint8_t verify_handshake[12];
			uint8_t handshake_hash[MAX_HASH_SIZE];
			int hash_size;

			if (pending_sp->prf_algorithm == PRF_SHA256) {
				hash_size = 32;
                hash_func = EVP_sha256;
				SHA256(sess->handshake_msgs,
					   sess->handshake_msgs_len - record->plain_text.length,
					   handshake_hash);
            } else if  (pending_sp->prf_algorithm == PRF_SHA384) {
				hash_size = 48;
                hash_func = EVP_sha384;
				SHA384(sess->handshake_msgs,
					   sess->handshake_msgs_len - record->plain_text.length,
					   handshake_hash);
            } else {
                fprintf(stderr, "during client_finished, not supported prf algorithm\n");
                exit(EXIT_FAILURE);
            }

            PRF(hash_func, sizeof(sess->read_sp.master_secret),
                sess->read_sp.master_secret,
                15, (const uint8_t *)"client finished",
                hash_size, handshake_hash,
                sizeof(verify_handshake), verify_handshake);

#if VERBOSE_CHUNK
            fprintf(stderr, "\nHandshake Chunk\n");
            {
				int z;
                for (z = 0; z < sess->handshake_msgs_len -
                                    record->plain_text.length; z++)
                    fprintf(stderr, "%02X%c", sess->handshake_msgs[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_CHUNK */

#if VERBOSE_SSL
            fprintf(stderr, "\nClient Handshake Verify\n");
            {
                for (z = 0; z < sizeof(verify_handshake); z++)
                    fprintf(stderr, "%02X%c", verify_handshake[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }


            fprintf(stderr, "\nMy Handshake Verify\n");
            {
                for (z = 0; z < sizeof(verify_handshake); z++)
                    fprintf(stderr, "%02X%c", vd[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
            fprintf(stderr, "\n");
#endif /* VERBOSE_SSL */

            for (z = 0; z < sizeof(verify_handshake); z++)
                if (vd[z] != verify_handshake[z])
                    break;

            if (z != sizeof(verify_handshake)) {
				sess->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_HANDSHAKE_HASH;
				return -1;
			}
#if VERBOSE_SSL
            else
                fprintf(stderr, "Handshake Verified!!\n");
#endif /* VERBOSE_SSL */

            /* Send CHANGE_CIPHER_SPEC */
            record_t* change_cipher_spec = new_send_record(sess);

            change_cipher_spec->fragment.change_cipher_spec.type = 1;
            length +=
                sizeof(change_cipher_spec->fragment.change_cipher_spec.type);

            if (0 > send_record(sess,
                                change_cipher_spec,
                                CHANGE_CIPHER_SPEC,
                                length)) {
                fprintf(stderr, "send_record for change_cipher_spec failed.\n");
                exit(EXIT_FAILURE);
            }
            sess->handshake_state = SERVER_CIPHER_SPEC;

#if VERBOSE_CHUNK
            fprintf(stderr, "\nFinal Handshake Chunk\n");
            {
				int z;
                for (z = 0; z < sess->handshake_msgs_len; z++)
                    fprintf(stderr, "%02X%c", sess->handshake_msgs[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_CHUNK */

            /* Change write-side cipher specification */
            memcpy(write_sp, pending_sp, sizeof(*pending_sp));
            sess->send_seq_num_ = 0;
            sess->server_write_IV_seq_num = 0;

            /* Make Server Finish */
            record_t *server_finished = new_send_record(sess);
            my_vd = server_finished-> \
                    fragment.handshake.body.server_finished.verify_data;
            length = 0;

			if (pending_sp->prf_algorithm == PRF_SHA256) {
				SHA256(sess->handshake_msgs,
					   sess->handshake_msgs_len,
					   handshake_hash);
            } else if  (pending_sp->prf_algorithm == PRF_SHA384) {
				SHA384(sess->handshake_msgs,
					   sess->handshake_msgs_len,
					   handshake_hash);
            } else {
                fprintf(stderr, "during server_finished, not supported prf algorithm\n");
                exit(EXIT_FAILURE);
            }

            PRF(hash_func, sizeof(write_sp->master_secret), write_sp->master_secret,
                15, (const uint8_t *)"server finished",
                hash_size, handshake_hash,
                sizeof(verify_handshake), my_vd);

            length += sizeof(verify_handshake);

            /* Send Server Finish */
            /* There is only FINISHED (20), actually */
            if (0 > send_handshake(sess,
                                            server_finished,
                                            CLIENT_FINISHED,
                                            length)) {
                fprintf(stderr, "send_handshake for server_finished failed.\n");
                exit(EXIT_FAILURE);
            }
            sess->handshake_state = SERVER_FINISHED;
#if VERBOSE_SSL
            fprintf(stderr, "SERVER FINISHED SENT\n\n");
#endif /* VERBOSE_SSL */

            sess->state = STATE_ACTIVE;

#if VERBOSE_SSL
			fprintf(stderr, "next_record_id: %d\n"
							"send_seq_num_: %lu\n"
							"recv_seq_num_: %lu\n",
							sess->next_record_id,
							sess->send_seq_num_,
							sess->recv_seq_num_);
#endif /* VERBOSE_SSL */
            break;
        default:
            fprintf(stderr, "Unmatched handshake\n");
            assert(0);
            break;
    }

handshake_record_finish:
    delete_record(sess, record);
    record = NULL;

    return 0;
}

static inline int
send_handshake(struct ssl_session* sess, record_t* record,
               uint8_t msg_type, int length)
{
#if VERBOSE_SSL
    fprintf(stderr, "SEND HANDSHAKE\n");
#endif /* VERBOSE_SSL */
    set_u32(&record->fragment.handshake.length, (uint32_t *)&length);
    length += sizeof(record->fragment.handshake.length);
    record->fragment.handshake.msg_type = msg_type;
    length += sizeof(record->fragment.handshake.msg_type);

    return send_record(sess, record, HANDSHAKE, length);
}

#if SEG_RECORD_BUF
inline int
send_data(struct ssl_session *sess, void *buf, int num)
{
	int ret;
	record_t *record;
#if VERBOSE_SSL
	fprintf(stderr, "SEND DATA\n");
#endif /* VERBOSE_SSL */


	if (sess->current_send_record) {
		record = sess->current_send_record;
		if (sess->pending_sp.cipher_type == AEAD) {
 			goto tcp_send;
		} else {
			ret = send_record(sess, record, APPLICATION_DATA, num);
			return ret;
		}
	} else {
		record = new_send_record(sess);

		if (!record) {
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
			return -1;
		}
		record->where_to_send = buf;
		record->payload_to_send = num;
		record->fragment.application_data.data = (uint8_t *)buf;
	}

	/* only AEAD support packet aggregation now.. */
	if (sess->pending_sp.cipher_type != AEAD) {
		ret = send_record(sess, record, APPLICATION_DATA, num);
		return ret;
	}

    int remaining = num;
	int to_send;
    while (remaining > 0) {
		to_send = MIN(remaining, MAX_PLAIN_DATA_LEN);
		if(record->total_to_send + to_send > TCP_EXTENDED_MSS) {
			fprintf(stderr, "[send data] exit the loop, total_to_send: %d, to_send: %d\n",
					record->total_to_send, to_send);
			break;
		}

		ret = fill_application_record(sess, record,
											APPLICATION_DATA, to_send);

        if (ret <= 0) {
			if (ret < 0) {
				sess->msg_num[FAIL] = mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE;
			}
            if (remaining == num) {
				return FAIL;
			} else {
				break;
			}
        }
        remaining -= to_send;
		record->total_payload_to_send += to_send;
		record->total_to_send += ret;
    }

 tcp_send:
	ret = -1;
    ret = mtcp_write(sess->mctx,
                     sess->sockid,
					(char *)record->buf + record->already_sent,
					record->total_to_send - record->already_sent);

#if VERBOSE_SSL
	fprintf(stderr, "Socket %d sent %d bytes among %d bytes\n",
					sess->sockid, ret, record->total_to_send - record->already_sent);
#endif /* VERBOSE_SSL */

	if(ret > 0)
		record->already_sent += ret;

	if (record->already_sent > record->total_to_send) {
		fprintf(stderr, "Weird State!!\n");
		exit(EXIT_FAILURE);
	} else if (record->already_sent == record->total_to_send) {
		/* Sent a whole record */
        ret = record->total_payload_to_send;
	    delete_record(sess, record);
		sess->current_send_record = NULL;
		return ret;
	} else {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_WANT_WRITE;
		return FAIL;
	}

	return FAIL;
}
#else	/* SEG_RECORD_BUF */
inline int
send_data(struct ssl_session *sess, void *buf, int num)
{
	int ret;
	record_t *sending_data;
#if VERBOSE_SSL
	fprintf(stderr, "SEND DATA\n");
#endif /* VERBOSE_SSL */

	if (sess->current_send_record) {
		sending_data = sess->current_send_record;
	} else {
		sending_data = new_send_record(sess);

		if (!sending_data) {
			sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
			return -1;
		}
		sending_data->where_to_send = buf;
		sending_data->payload_to_send = num;
		sending_data->fragment.application_data.data = (uint8_t *)buf;
	}

	ret = send_record(sess, sending_data, APPLICATION_DATA, num);

	return ret;
}
#endif	/* !SEG_RECORD_BUF */

static inline int
verify_mac(struct ssl_session* sess, record_t* record)
{
    unsigned pad_len;
    security_params_t *read_sp = &sess->read_sp;
    generic_block_cipher_t *block_cipher =
                            &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "VERIFY MAC\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
	if (!op) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
		return -1;
	}
    op->in = record->mac_in;
    sequence_num_t seqnum = bswap_64(record->seq_num);
    op->opcode.u32 = TLS_OPCODE_HMAC_SHA1_HASH;
#if VERBOSE_MAC
    fprintf(stderr, "\nDecrypt MAC\n");
#endif /* VERBOSE_MAC */

    if (likely(record->is_received)) {
        op->key = sess->client_write_MAC_secret;
        op->key_len = read_sp->mac_key_size;
        op->out_len = read_sp->mac_key_size;

        uint8_t *end = record->decrypted + RECORD_HEADER_SIZE +
                                            record->cipher_text.length - 1;

        pad_len = *end;
		if (pad_len != *(end - 1) || pad_len > record->cipher_text.length) {
			pad_len = 0;
		}
 
        op->in_len = record->cipher_text.length +
                     sizeof(record->seq_num) +
                     RECORD_HEADER_SIZE -
                     read_sp->mac_key_size -
                     pad_len - 1;

        block_cipher->padding_length = pad_len;
        block_cipher->padding = end - pad_len;
        block_cipher->mac = block_cipher->padding - read_sp->mac_key_size;
        block_cipher->content = record->decrypted + RECORD_HEADER_SIZE;

        record->cipher_text.length -= (read_sp->mac_key_size + pad_len + 1);
        *((uint16_t *)(record->decrypted + 3)) =
                                            htons(record->cipher_text.length);

    } else {
		/* debug */
		fprintf(stderr, "[verify mac] ???\n");
		exit(EXIT_FAILURE);
    }

    memcpy(op->in, &seqnum, sizeof(seqnum));
    op->out = record->mac_buf;
    op->data = (void *)record;

    if (0 > execute_mac_crypto(op)) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
		delete_op(op);
		return -1;
	}

#if VERBOSE_MAC
	unsigned z;
    fprintf(stderr, "\nmac key:\n");
    {
        for (z = 0; z < op->key_len; z++)
            fprintf(stderr, "%02X%c", op->key[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }


    fprintf(stderr, "\nmac_out:\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", op->out[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_MAC */

    return handle_after_mac_crypto(sess, op);
}

static inline int
attach_mac(struct ssl_session* sess, record_t* record)
{
    security_params_t *write_sp = &sess->write_sp;
    generic_block_cipher_t *block_cipher =
                            &record->cipher_text.fragment.block_cipher;
	/* int ret = 0; */

#if VERBOSE_SSL
    fprintf(stderr, "ATTACH MAC\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
	if (!op) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE;
		return -1;
	}
    op->in = record->mac_in;
    sequence_num_t seqnum = bswap_64(record->seq_num);
    op->opcode.u32 = TLS_OPCODE_HMAC_SHA1_HASH;
#if VERBOSE_MAC
    fprintf(stderr, "\nDecrypt MAC\n");
#endif /* VERBOSE_MAC */

    if (unlikely(record->is_received)) {
		fprintf(stderr, "[attach_mac]???\n");
		exit(EXIT_FAILURE);
    } else {
        op->key = sess->server_write_MAC_secret;
        op->key_len = write_sp->mac_key_size;
        op->out_len = write_sp->mac_key_size;
        op->in_len = record->plain_text.length +
                     sizeof(sess->recv_seq_num_) +
                     RECORD_HEADER_SIZE;
        block_cipher->content = record->decrypted + RECORD_HEADER_SIZE;
        record->cipher_text.length = record->plain_text.length;
    }

    memcpy(op->in, &seqnum, sizeof(seqnum));
    op->out = record->mac_buf;
    op->data = (void *)record;

    if (0 > execute_mac_crypto(op)) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;
		delete_op(op);
		return -1;
	}

#if VERBOSE_MAC
	unsigned z;
    fprintf(stderr, "\nmac key:\n");
    {
        for (z = 0; z < op->key_len; z++)
            fprintf(stderr, "%02X%c", op->key[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }


    fprintf(stderr, "\nmac_out:\n");
    {
        for (z = 0; z < op->out_len; z++)
            fprintf(stderr, "%02X%c", op->out[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_MAC */

    return handle_after_mac_crypto(sess, op);
}

static int
unpack_header(record_t* record)
{
    uint8_t* data = record->data;
    plain_text_t* plain_text = &record->plain_text;
    cipher_text_t* cipher_text = &record->cipher_text;

    assert(record->state = TO_UNPACK_HEADER);
#if VERBOSE_SSL
    fprintf(stderr, "\nUnpacking Header\n");
#endif /* VERBOSE_SSL */

    record->state = TO_DECRYPT;
#if VERBOSE_STATE
    fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
                    ((struct ssl_session *)record->sess)->parent->session_id,
                    record->id,
                    state_to_string(TO_UNPACK_HEADER),
                    state_to_string(record->state));
#endif /* VERBOSE_STATE */

    if (data[0] == CHANGE_CIPHER_SPEC ||
        data[0] == ALERT ||
        data[0] == HANDSHAKE ||
        data[0] == APPLICATION_DATA) {

        cipher_text->c_type = data[0];
        cipher_text->version.major = data[1];
        cipher_text->version.minor = data[2];
        cipher_text->length = ntohs(*(uint16_t *)(data + 3));

        plain_text->c_type = data[0];
        plain_text->version.major = data[1];
        plain_text->version.minor = data[2];
        plain_text->length = ntohs(*(uint16_t *)(data + 3));
    } else {
		return -1;
    }

    return 0;
}



static inline int
process_read_record(struct ssl_session* sess, record_t* record,
                    char *buf, uint16_t buf_len)
{
    assert(record != NULL);

#if VERBOSE_CHUNK
	unsigned z;
    fprintf(stderr,"\nNew READ RECORD\n");
    {
        for (z = 0; z < record->length; z++)
            fprintf(stderr, "%02X%c", record->data[z],
                                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_SSL */

    if (0 < unpack_header(record)) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_RECORD;
		return -1;
    }

	if(sess->read_sp.bulk_cipher_algorithm != NO_CIPHER) {
		if(sess->read_sp.mac_algorithm == NO_MAC) {
			fprintf(stderr, "[process_read_record] Error: the encrypted packet has no MAC!\n");
			exit(EXIT_FAILURE);
		}
		
		/* if(decrypt_record(sess, record, buf, buf_len) < 0) { */
		/* 	return -1 */
		/* } */
		decrypt_record(sess, record, buf, buf_len);
		if (sess->pending_sp.cipher_type != AEAD)
			verify_mac(sess, record);
	} else {
		record->decrypted = record->data;
	}

	record->state = TO_UNPACK_CONTENT;
#if VERBOSE_STATE
	fprintf(stderr, "\n(Session %d, Record %d) State CHANGE %s -> %s\n",
			sess->parent->session_id,
			record->id,
			state_to_string(TO_VERIFY_MAC),
			state_to_string(record->state));
#endif /* VERBOSE_STATE */
	
	if (0 > unpack_record(record)) {
		sess->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_RECORD;
		return -1;
	}

	/* ToDo: move below code to where handshake is handled*/
	/* do RSA decryption if needed */
	if (record->plain_text.c_type == HANDSHAKE &&
		record->fragment.handshake.msg_type == CLIENT_KEY_EXCHANGE) {
#if VERBOSE_SSL
		fprintf(stderr, "RSA Decrypt Needed!\n");
#endif /* VERBOSE_SSL */
		if (rsa_decrypt_record(sess, record) < 0)
			return -1;
	}
	
	return handle_read_record(sess, record);
}

static inline int
process_new_record(struct ssl_session* sess, uint8_t *payload, size_t payload_len,
                   char *buf, size_t buf_len)
{
    size_t processed_len = 0;
    size_t copy_len = 0;
    record_t* crr;
    uint16_t record_len = 0;
	int ret;

#if VERBOSE_SSL
    unsigned z;
    fprintf(stderr, "process_new_record\n");
#endif /* VERBOSE_SSL */
    crr = sess->current_read_record;

    while (processed_len < payload_len) {
        if (crr == NULL) {
            uint8_t* ph;

            if (payload_len - processed_len < RECORD_HEADER_SIZE)
                break;

            crr = sess->current_read_record = new_recv_record(sess);
            if (crr == NULL)
                return processed_len;

            ph = payload + processed_len;

            record_len = ntohs(*(uint16_t *)(ph + 3));
#if VERBOSE_SSL
            fprintf(stderr, "\nNew RECORD "
                            "%d, processed: %lu, record_len: %u\n",
                            crr->id,
                            processed_len, ntohs(*(uint16_t *)(ph + 3)));
            {
                for (z = 0; z < 64; z++)
                    fprintf(stderr, "%02X%c", ph[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_SSL */
            assert(record_len < 16384 +2048);
            crr->length = record_len + RECORD_HEADER_SIZE;
        }

        copy_len = MIN(crr->length - crr->current_len, payload_len - processed_len);
#if VERBOSE_SSL
        fprintf(stderr, "crr->length: %lu, crr->current_len: %lu, "
                        "payload_len: %lu, processed_len: %lu\n",
                        crr->length, crr->current_len, payload_len, processed_len);
#endif /* VERBOSE_SSL */

        memcpy(crr->data + crr->current_len, payload + processed_len, copy_len);
        crr->current_len += copy_len;
        processed_len += copy_len;

        if (crr->current_len == crr->length) {
            ret = process_read_record(sess, crr, buf, buf_len);
            sess->current_read_record = NULL;
            crr = NULL;
			if (ret < 0)
				return ret;
        }
    }

    /* We need next packet */
    if (crr != NULL) {
       return -1; 
    }

    return processed_len;
}

int
process_ssl_packet(struct ssl_session* ssl_sess,
                   uint8_t *payload, uint16_t payloadlen,
                   char *buf, uint16_t buf_len)
{
    if (!ssl_sess || !payload || payloadlen <= 0 || !buf || buf_len <= 0) {
        fprintf(stderr, "Wrong Arguments, payloadlen: %d\n", payloadlen);
        return -1;
    }

#if VERBOSE_SSL
    fprintf(stderr, "< SSL Packet >\n");
#endif /* VERBOSE_SSL */

    return process_new_record(ssl_sess, payload, payloadlen, buf, buf_len);
}
