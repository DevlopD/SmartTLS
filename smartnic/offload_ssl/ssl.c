#include "ssloff.h"
#include "ssl_crypto.h"

#define RAND_MAX_LOCAL (1073741823lu*4lu + 3lu)

/*---------------------------------------------------------------------------*/
/* FUNCTION PROTOTYPE */

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
decrypt_record(struct ssl_session* sess, record_t* record);

static inline int
encrypt_record(struct ssl_session* sess, record_t* record);

static inline int
unpack_record(record_t* record);

static inline int
pack_record(record_t* record);

static inline int
unpack_change_cipher_spec(void);

static inline int
unpack_application_data(record_t* record);

static inline int
unpack_handshake(record_t* record);

static inline int
pack_handshake(record_t* record, int offset);

static inline int
handle_data(struct ssl_session* sess, record_t *record);

static inline int
handle_read_record(struct ssl_session* sess, record_t* record);

static inline int
send_record(struct ssl_session* sess, record_t* record,
            uint8_t c_type, int length, int send_type);

static inline int
handle_change_cipher_spec(struct ssl_session* sess, record_t* record);

static inline int
handle_handshake(struct ssl_session* sess, record_t* record);

static inline int
send_handshake(struct ssl_session* sess, record_t* record,
               uint8_t msg_type, int length, int last);

static inline int
verify_mac(struct ssl_session* sess, record_t* record);

static inline int
attach_mac(struct ssl_session* sess, record_t* record);

static inline int
unpack_header(record_t* record);

static inline int
process_read_record(struct ssl_session* sess, record_t* record);

static inline int
process_new_record(struct ssl_session* sess, uint8_t *buf, size_t len);

static inline void
push_read_record(struct ssl_session* sess, record_t* record);

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

static inline void
set_u32(uint24_t* a, const uint32_t* b)
{
    const uint8_t* y = (const uint8_t *)b;
    a->u8[0] = y[2];
    a->u8[1] = y[1];
    a->u8[2] = y[0];
}

static inline uint32_t
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

/*
 * This function changes string to operand.
 * 
 * @str     The string to convert to operand for RSA
 * @op      The operand which will contain the result
 * @len     The length of string
 * @endian  The endian to be used in conversion
 *          0: Little Endian
 *          1: Big Endian
 */
static void
string_to_operand(uint8_t *str, pka_operand_t *op, uint16_t len, int endian)
{
    uint8_t *big_num_ptr;
    int i;

#if VERBOSE_KEY
    unsigned z = 0;
    fprintf(stderr, "\nPKA request data:\n\n");
    {
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(str) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    assert(op != NULL);
    assert(op->buf_ptr != NULL);

    memset(op->buf_ptr, 0, op->buf_len);

    op->actual_len = len;
    op->is_encrypted = 0;
    op->big_endian = endian;

    if (endian)
        big_num_ptr = &op->buf_ptr[0];
    else
        big_num_ptr = &op->buf_ptr[len - 1];

    for (i = 0; i < len; i++) {
        if (endian)
            *big_num_ptr++ = str[i];
        else
            *big_num_ptr-- = str[i];
    }
}

/*
 * This function changes to operand to string at most max_len.
 *
 * @op      The operand which will be converted to string
 * @str     The pointer which will contain the result
 * @max_len The maximum length of result string
 */
static void
operand_to_string(pka_operand_t *op, uint8_t *str, uint16_t max_len)
{
    uint32_t len = MIN(max_len, op->actual_len);
    uint32_t i;
    uint8_t *byte_ptr;

#if VERBOSE_KEY
    unsigned z = 0;
    fprintf(stderr, "\nPKA return data:\n\n");
    {
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->buf_ptr) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_KEY */

    //memset(str, 0, max_len);

    if (op->big_endian) {
        byte_ptr = &op->buf_ptr[0];
        for (i = 0; i < len; i++) {
            str[i] = *byte_ptr++;
        }
    }
    else {
        byte_ptr = &op->buf_ptr[len - 1];
        for (i = 0; i < len; i++) {
            str[i] = *byte_ptr--;
        }
    }
}

inline pka_results_t *
malloc_results(uint32_t result_cnt, uint32_t buf_len)
{
    pka_results_t   *results;
    pka_operand_t   *result_ptr;
    uint8_t         result_idx, i;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);

    results = malloc(sizeof(pka_results_t));
    if (results == NULL) {
        fprintf(stderr, "Error: malloc for results failed\n");
        return NULL;
    }
    memset(results, 0, sizeof(pka_results_t));

    for (result_idx = 0; result_idx < result_cnt; result_idx++) {
        result_ptr = &results->results[result_idx];
        if ((result_ptr->buf_ptr = malloc(buf_len)) == NULL) {
            fprintf(stderr, "Error: malloc for buf_ptr failed\n");
            for (i = 0; i < result_idx; i++)
                free(results->results[result_idx].buf_ptr);
            return NULL;
        }
        memset(result_ptr->buf_ptr, 0, buf_len);
        result_ptr->buf_len = buf_len;
        result_ptr->actual_len = 0;
    }

    return results;
}

static void free_results_buf(pka_results_t *results)
{
    pka_operand_t   *result_ptr;
    uint8_t         result_idx;

    for (result_idx = 0; result_idx < 2; result_idx++) {
        result_ptr = &results->results[result_idx];
        if (result_ptr->buf_ptr)
            free(result_ptr->buf_ptr);
        result_ptr->buf_ptr = NULL;
        result_ptr->buf_len = 0;
        result_ptr->actual_len = 0;
    }
}

inline void free_results(pka_results_t *results)
{
    assert(results != NULL);
    free_results_buf(results);
    free(results);
}

inline void clear_results(pka_results_t *results)
{
    pka_operand_t   *result_ptr;
    uint8_t         result_idx;

    assert(results);

    for (result_idx = 0; result_idx < 2; result_idx++) {
        result_ptr = &results->results[result_idx];
        if (result_ptr->buf_ptr) {
            memset(result_ptr->buf_ptr, 0, result_ptr->buf_len);
            result_ptr->actual_len = 0;
        }
    }

    results->user_data = NULL;
    results->opcode = 0;
    results->result_cnt = 0;
    results->status = 0;
    results->compare_result = 0;
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

inline void
remove_pending_rsa_op(struct ssl_session* sess)
{
    ssl_crypto_op_t *op = sess->pending_rsa_op;
    if(unlikely(op != NULL)) {
#if VERBOSE_SSL
        fprintf(stderr, "[Remove Pending RSA OP] hit, remove pending RSA op before clearing session\n");
#endif
		op->pka_flag = 0;
        delete_record(sess, (record_t *)(op->data));
        delete_op(op);
		sess->pending_rsa_op = NULL;
		sess->ctx->cur_crypto_cnt--;
    }
}

static inline cipher_suite_t
select_cipher(uint16_t length, cipher_suite_t* cipher_suites)
{
    cipher_suite_t cipher = TLS_NULL_WITH_NULL_NULL;
	uint32_t i;

    for (i = 0; i< length / sizeof(cipher_suite_t); i++) {
		/* /\* debug *\/ */
        /* if (COMPARE_CIPHER(cipher_suites[i], TLS_RSA_WITH_AES_128_GCM_SHA256)) { */
        /*     return TLS_RSA_WITH_AES_128_GCM_SHA256; */
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
    record->data = record->buf + sizeof(uint64_t);
    record->decrypted = record->mac_in + sizeof(uint64_t);
    record->next_iv = NULL;
    record->current_len = 0;
    record->length = 0;
    record->seq_num = seq;
    record->is_encrypted = 0;

    memset(&record->plain_text, 0, sizeof(plain_text_t));
    memset(&record->cipher_text, 0, sizeof(cipher_text_t));
    memset(&record->fragment, 0, sizeof(record->fragment));

    record->is_reset = false;
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
    struct thread_context *ctx = sess->ctx;

    sess->num_current_records++;

    record = TAILQ_FIRST(&ctx->record_pool);
    if (unlikely(!record)) {
        fprintf(stderr, "Not enough record, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt--;
    ctx->using_record_cnt++;

    record->sess = sess;

    init_record(record, 0, true);

    record->id = sess->next_record_id;
    sess->next_record_id++;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nnew_recv_record: Session %d: %d\n",
                    sess->parent->session_id,
                    record->id);
#endif /* VERBOSE_SSL */

    return record;
}

static inline record_t*
new_send_record(struct ssl_session* sess)
{
    record_t *record = NULL;
    struct thread_context *ctx = sess->ctx;

    sess->num_current_records++;

    record = TAILQ_FIRST(&ctx->record_pool);
    if (unlikely(!record)) {
        fprintf(stderr, "Not enough record, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt--;
    ctx->using_record_cnt++;

    record->sess = sess;

    init_record(record, sess->send_seq_num_, false);

    record->id = sess->next_record_id;
    sess->next_record_id++;

#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nnew_send_record: Session %d: %d\n",
                    sess->parent->session_id,
                    record->id);
#endif /* VERBOSE_SSL */

    return record;
}

static ssl_crypto_op_t*
new_ssl_crypto_op(struct ssl_session* sess)
{
    ssl_crypto_op_t *target;
    struct thread_context *ctx = sess->ctx;

    target = TAILQ_FIRST(&ctx->op_pool);
    if (unlikely(!target)) {
        fprintf(stderr, "[new_ssl_crypto_op] Not enough op, and this must not happen.\n");
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
    if (unlikely(record->fragment.handshake.msg_type 
                        <= sess->handshake_state))
        return -1;

    if (likely(record->plain_text.version.major == 0x03))
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
    fprintf(stderr, "fragment:\n");
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
    struct thread_context *ctx = record->ctx;

    memset(record, 0, sizeof(record_t));
    record->ctx = ctx;
    TAILQ_INSERT_TAIL(&ctx->record_pool, record, record_pool_link);
    ctx->free_record_cnt++;
    ctx->using_record_cnt--;

    sess->num_current_records--;
#if VERBOSE_SSL || VERBOSE_STATE
    fprintf(stderr, "\nDelete Session %d, Record: %d\n",
                    sess->parent->session_id,
                    record->id);
#endif /* VERBOSE_SSL */
}

static inline void
delete_op(ssl_crypto_op_t *op)
{
    struct thread_context *ctx = op->ctx;

    memset(op, 0, sizeof(ssl_crypto_op_t));
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
    fprintf(stderr, "\n[handle after aes cbc decrypt] op->in (original data):\n\n");
    {
        for (z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", *((uint8_t *)(op->in) + z),
                ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\n[handle after aes cbc decrypt] op->out (decrypted data):\n\n");
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
handle_after_aes_gcm_encrypt(struct ssl_session* sess,
                             record_t* record, ssl_crypto_op_t *op)
{
	UNUSED(op);

	if(record->state != TO_ENCRYPT) {
		fprintf(stderr, "[handle after aes gcm encrypt] wrong record->state: %d!\n",
				record->state);
		return -1;
	}

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
	UNUSED(sess);

    premaster_secret_t *ps =
                &record->fragment.handshake.body.client_key_exchange.ps;
    assert(op->pka_out->result_cnt == 1);
    operand_to_string(&op->pka_out->results[0],
                     (uint8_t *)ps,
                     48u);

#if VERBOSE_KEY
	fprintf(stderr, "\n[handle after private decrypt] pre-master:\n");
	{
		int z;
		for (z = 0; z < 48; z++)
			fprintf(stderr, "%02X%c", *((uint8_t *)ps + z),
					((z + 1) % 16) ? ' ' : '\n');
	}
#endif
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

    if (record->is_received) {
        uint8_t* recv_mac = block_cipher->mac;
#if VERBOSE_SSL
        fprintf(stderr, "\n[HANDLE MAC] VERIFY MAC\n");
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
            if (unlikely(op->out[z] != recv_mac[z])) {
                wrong = 1;
                break;
            }
        }
        if (unlikely(wrong)) {
			fprintf(stderr, "[HANDLE MAC] mac verify failed!\n");
			delete_record(sess, record);
			abort_session(sess);
			return -1;
		}
        else {
#if VERBOSE_MAC
            fprintf(stderr, "\nCorrect MAC!!\n");
#endif /* VERBOSE_MAC */
			return 0;
		}

    }
    else {
#if VERBOSE_SSL
        fprintf(stderr, "\n[HANDLE MAC] APPEND MAC\n");
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

	/* can't reach here */
	return -1;
}

inline int
process_crypto(struct thread_context* ctx)
{
    int ret, processed;
    ssl_crypto_op_t *op;
    record_t *record;
    struct ssl_session *sess;

    processed = 0;
    while(ctx->cur_crypto_cnt > 0) {
        //clear_results(ctx->rsa_result);
        ret = pka_get_result(*(ctx->handle), ctx->rsa_result);

        /* Get out from loop when there is no completed rsa */
        if (ret == FAILURE) {
            break;
        }

        op = (ssl_crypto_op_t *)(ctx->rsa_result->user_data);
        record = (record_t *)(op->data);
		if(!record) {
			/* DEBUG_PRINT("[process crypto] record is null..\n"); */
			return -1;
		}
        sess = (struct ssl_session *)(record->sess);

		/* it may be already rotten */
		if(unlikely(op->pka_flag == 0)) {
			continue;
        }

		sess->pending_rsa_op = NULL;

		op->pka_out = ctx->rsa_result;
		if(0 > handle_after_private_decrypt(sess, record, op)) {
			return -1;
		}

		if (0 > handle_read_record(sess, record)) {
			return -1;
		}

        assert(op->pka_in == sess->rsa_operand);
        assert(op->pka_in->buf_ptr != NULL);
        //op->pka_in->buf_ptr = NULL;
        sess->waiting_crypto = FALSE;

		delete_record(sess, record);
        delete_op(op);
        ctx->cur_crypto_cnt--;
        processed++;
    }
    return processed;
}

static int
handle_after_rsa_crypto(struct ssl_session* sess,
						ssl_crypto_op_t *op)
{
	int ret = -1;
    record_t *record = (record_t *)op->data;
    int crypto_type = op->opcode.s.op;
    if (!record) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
        return -1;
    }
    assert(op->opcode.s.function == TLS_RSA);

#if VERBOSE_SSL
    fprintf(stderr, "Handle after RSA Crypto\n");
#endif /* VERBOSE_SSL */

	if (likely(crypto_type == PRIVATE_DECRYPT)) {
		ret = handle_after_private_decrypt(sess, record, op);
	}
	else
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
		/* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL;  */
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
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
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
    fprintf(stderr, "[RSA Decrypt RECORD]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
	if (!op) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE; */
        return -1;
    }
    client_key_exchange_t* ckpt =
                    &record->fragment.handshake.body.client_key_exchange;
    uint8_t *secret = ckpt->key.rsa.encrypted_premaster_secret;
    string_to_operand((((uint8_t *)secret) + 2),
                      sess->rsa_operand,
                      ntohs(*(uint16_t *)secret),
                      0);
    op->pka_in = sess->rsa_operand;
    op->pka_out = sess->ctx->rsa_result;
    op->in_len = ntohs(*(uint16_t *)secret);
    op->out_len = op->in_len;
    op->key = (uint8_t *)(sess->ctx->ssl_context->pka);

    assert(op->key != NULL);
#if VERBOSE_KEY
    fprintf(stderr, "RSA %d\n", op->in_len * 8);
#endif /* VERBOSE_KEY */
    if (op->in_len ==128) {
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
		/* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
		delete_op(op);
		return -1;
	}

    op->pka_flag = 1;
    sess->pending_rsa_op = op;

	return 0;
}

static inline int
decrypt_record(struct ssl_session* sess, record_t* record)
{
    security_params_t *read_sp = &sess->read_sp;

    assert(record->state == TO_DECRYPT);
#if VERBOSE_SSL
    fprintf(stderr, "[Decrypt Record]\n");
#endif /* VERBOSE_SSL */

    record->seq_num = sess->recv_seq_num_;
    sess->recv_seq_num_++;

    record->is_encrypted = 1;


    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);
	if (!op) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE; */
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
			/* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
			delete_op(op);
			return -1;
		}

		*((uint16_t *)(record->decrypted + 3)) = htons(record->cipher_text.length);
#if VERBOSE_AES
		fprintf(stderr, "\nDecrypted Data:\n");
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
        uint16_t z;
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
            /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
            delete_op(op);
            return -1;
        }

        *((uint16_t *)(record->decrypted + 3)) = htons(record->cipher_text.length);

#if VERBOSE_AES
        fprintf(stderr, "\n[decrypt_record] Decrypted Data:\n");
		for (z = 0; z < record->cipher_text.length + RECORD_HEADER_SIZE; z++)
			fprintf(stderr, "%02X%c", record->decrypted[z],
					((z + 1) % 16) ? ' ' : '\n');

#endif /* VERBOSE_AES */

    } else {
        fprintf(stderr, "[decrypt record] can't support cipher type\n");
        exit(EXIT_FAILURE);
    }

	return handle_after_aes_crypto(sess, op);
}

static inline int
encrypt_record(struct ssl_session* sess, record_t* record)
{
    security_params_t *write_sp = &sess->write_sp;
    generic_block_cipher_t *block_cipher =
                                &record->cipher_text.fragment.block_cipher;
#if VERBOSE_SSL
    fprintf(stderr, "[encrypt Record]\n");
#endif /* VERBOSE_SSL */

    if (unlikely(sess->server_write_IV_seq_num != record->seq_num)) {
        fprintf(stderr, "Something wrong with sequence number!\n");
        return -1;
    }

    ssl_crypto_op_t *op = new_ssl_crypto_op(sess);
	if (!op) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE; */
        return -1;
    }

	if (write_sp->cipher_type == BLOCK) {
		int pad_len = (record->cipher_text.length % 16) ?
			(16 - record->cipher_text.length % 16) : 0;

		block_cipher->padding = block_cipher->mac + MAC_SIZE;
		block_cipher->padding_length = pad_len;
		memset(block_cipher->padding, pad_len - 1, pad_len);

#if VERBOSE_AES
		fprintf(stderr, "\ndecrypted:\n");
		{
			unsigned z;
			for (z = 0; z < 64; z++)
				fprintf(stderr, "%02X%c", record->decrypted[z],
						((z + 1) % 16) ? ' ' : '\n');
		}
#endif /* VERBOSE_AES */

		record->cipher_text.length += pad_len;
		block_cipher->IV = record->decrypted + RECORD_HEADER_SIZE;

		memmove(block_cipher->IV + write_sp->fixed_iv_length,
				block_cipher->IV,
				record->cipher_text.length);

		block_cipher->content += write_sp->fixed_iv_length;
		block_cipher->mac += write_sp->fixed_iv_length;
		block_cipher->padding += write_sp->fixed_iv_length;

#if VERBOSE_AES
		fprintf(stderr, "\n IV: %p,\n content: %p,\n mac: %p,\n padding: %p\n",
				block_cipher->IV,
				block_cipher->content,
				block_cipher->mac,
				block_cipher->padding);
#endif /* VERBOSE_AES */
		/* Set initial iv as all 0 */
		/* Need to support normal packets */

		memset(block_cipher->IV, 0, write_sp->fixed_iv_length);
		record->cipher_text.length += write_sp->fixed_iv_length;

		*(uint16_t *)(record->decrypted + 3) = htons(record->cipher_text.length);
		op->in = block_cipher->IV;
		op->out = record->data + RECORD_HEADER_SIZE;
		memcpy(record->data,
			   record->decrypted,
			   RECORD_HEADER_SIZE);

#if VERBOSE_AES
		fprintf(stderr, "\nRevised decrypted:\n");
		{
			unsigned z;
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
			/* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
			delete_op(op);
			return -1;
		}


#if VERBOSE_AES
		fprintf(stderr, "\nEncrypted Data with Total Length %lu\n", record->length);
		{
			unsigned z;
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
        record->data -= write_sp->record_iv_length;

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
			/* debug */
            rand_tmp = random();
            copy_byte = MIN(write_sp->fixed_iv_length - i, (uint8_t)sizeof(long int));
            memcpy((unsigned char*)(aead_cipher->nonce_explicit) + i, &rand_tmp, copy_byte);
        }

		/* debug */
		{
            int z;
			fprintf(stderr, "[encrypt record] explicit iv:\n");
            for (z = 0; z < write_sp->record_iv_length; z++)
                fprintf(stderr, "%02X%c", aead_cipher->nonce_explicit[z],
                        ((z + 1) % 16)? ' ' : '\n');
            fprintf(stderr, "\n");
        }

#else
        memset(aead_cipher->nonce_explicit, 0,
               write_sp->record_iv_length);
#endif
        memcpy(nonce + write_sp->fixed_iv_length, aead_cipher->nonce_explicit,
               write_sp->record_iv_length);
        record->cipher_text.length += write_sp->record_iv_length;

        record->cipher_text.length += GCM_TAG_SIZE;

		/* fill aead_cipher content */
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

#if VERBOSE_AES
        fprintf(stderr, "\n[encrypt record] op->in (aead->content) with length %d:\n",
				op->in_len);
		uint8_t z;
		for (z = 0; z < op->in_len; z++)
			fprintf(stderr, "%02X%c", op->in[z],
					((z + 1) % 16) ? ' ' : '\n');

        fprintf(stderr, "\n[encrypt record] op->iv (nonce) with length %d:\n",
				op->iv_len);
		for (z = 0; z < op->iv_len; z++)
			fprintf(stderr, "%02X%c", op->iv[z],
					((z + 1) % 16) ? ' ' : '\n');

        fprintf(stderr, "\n[encrypt record] op->aad (additional_data) with length %d:\n",
				op->aad_len);
		for (z = 0; z < op->aad_len; z++)
			fprintf(stderr, "%02X%c", op->aad[z],
					((z + 1) % 16) ? ' ' : '\n');

        fprintf(stderr, "\n[encrypt record] op->key (sess->server_write_key) with length %d:\n",
				op->key_len);
		for (z = 0; z < op->key_len; z++)
			fprintf(stderr, "%02X%c", op->key[z],
					((z + 1) % 16) ? ' ' : '\n');
#endif /* VERBOSE_AES */

        if (0 > execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op)) {
            /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
            delete_op(op);
            return -1;
        }

#if VERBOSE_AES
        fprintf(stderr, "\n[encrypt record] Encrypted Data with Total Length %lu\n", record->length);
        {
            int z;
            for (z = 0; z < 160; z++)
                fprintf(stderr, "%02X%c", record->data[z],
                        ((z + 1) % 16) ? ' ' : '\n');
        }
#endif /* VERBOSE_AES */
    }

    return handle_after_aes_crypto(sess, op);
}

static inline int
unpack_change_cipher_spec(void)
{
    return 0;
}

static inline int
unpack_alert(record_t* record)
{
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
    if (unlikely(!record))
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
    fprintf(stderr, "[Unpack Record]\n");
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
        if (record->is_encrypted)
            plain_text->length = record->cipher_text.length;
        else {
            plain_text->length = ntohs(*(uint16_t *)(decrypted +3));
        }
    }

    if (likely(plain_text->version.major == 0x03))
        plain_text->fragment = decrypted + RECORD_HEADER_SIZE;
    else {
        assert(0);
	}

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

static int
pack_change_cipher_spec(record_t* record, int offset)
{
#if VERBOSE_SSL
    fprintf(stderr, "[PACK CHANGE CIPHER SPEC]\n");
#endif /* VERBOSE_SSL */

    memcpy(record->decrypted + offset,
           &record->fragment,
           sizeof(change_cipher_spec_t));
    offset += sizeof(change_cipher_spec_t);
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
    fprintf(stderr, "[PACK RECORD]\n");
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
        case APPLICATION_DATA:
            fprintf(stderr, "Not supported yet\n");
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
    fprintf(stderr, "[Unpack Handshake]\n");
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
            if (likely(plain_text->version.major == 0x03 &&
                plain_text->version.minor == 0x01)) {

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
            fprintf(stderr, "No matching Type of Handshake: %d\n",
                                    record->fragment.handshake.msg_type);
	    abort_session(record->sess);
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
    fprintf(stderr, "[PACK HANDSHAKE]\n");
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
	    abort_session(record->sess);
	    return -1;
        default:
            fprintf(stderr, "Unmatched Handshake.\n");
	    abort_session(record->sess);
	    return -1;
    }

    return offset;
}

static inline int
handle_alert(struct ssl_session* sess, record_t *record)
{
  unsigned char level = record->fragment.alert.level;
  unsigned char description = record->fragment.alert.description;

  const char FATAL = 2;
  const char CLOSE_NOTIFY = 0;

  /* serve simplified respond */
  if(level == FATAL || description == CLOSE_NOTIFY) {
      delete_record(sess, record);
      abort_session(sess);
  } else {
      delete_record(sess, record);
  }

  return 0;
}


static inline int
handle_data(struct ssl_session* sess, record_t *record)
{
#if VERBOSE_DATA
    unsigned char *data = record->fragment.application_data.data;
    unsigned data_len = record->plain_text.length;
    unsigned z;

    fprintf(stderr, "\nAPP DATA LEN: %u\n", data_len);
    for (z = 0; z < data_len; z++)
        fprintf(stderr, "%c", data[z]);
#else /* VERBOSE_DATA */
    UNUSED(record);
#endif /* !VERBOSE_DATA */

#if !ONLOAD
    sess->ctx->stat.completes++;
#endif /* !ONLOAD */

    delete_record(sess, record);
    abort_session(sess);


    return 0;
}

static inline int
handle_read_record(struct ssl_session* sess, record_t* record)
{
    int ret = -1;

    assert(record != NULL);
#if VERBOSE_SSL
    fprintf(stderr, "[Handle Read Record]\n");
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

static inline int
send_record(struct ssl_session* sess, record_t* record,
            uint8_t c_type, int length, int send_type)
{
    int ret = -1;
    int copy_len = 0;
    assert(record != NULL);

#if VERBOSE_SSL
    fprintf(stderr, "[SEND RECORD]\n");
#endif /* VERBOSE_SSL */
    record->plain_text.length = length;
    length += sizeof(record->plain_text.length);
    record->plain_text.c_type = c_type;
    length += sizeof(record->plain_text.c_type);
    record->plain_text.version = sess->version;
    length += sizeof(record->plain_text.version);

    record->length = length;

    if (unlikely(0 > pack_record(record)))
        return -1;

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

#if OFFLOAD_AES_GCM
		/* ToDo: insert information on AES offload into mbuf? */

		/* It only consider handshake packet,
		   so please rethink when processing app data here */
		if (send_type == PKT_TYPE_OFFL_TLS_AES && 
			sess->pending_sp.cipher_type == AEAD) {
			int add_len = sess->write_sp.record_iv_length + GCM_TAG_SIZE;
			record->data = record->decrypted;
			record->data -= sess->write_sp.record_iv_length;
			memcpy(record->data, record->decrypted, RECORD_HEADER_SIZE);
			record->data[4] += add_len;
			memset(record->data + RECORD_HEADER_SIZE, 0,
				   sess->write_sp.record_iv_length);
			record->length += add_len;
			record->state = WRITE_READY;
		} else {
			record->state = TO_ENCRYPT;
			if(encrypt_record(sess, record) < 0) {
				return -1;
			}
		}
#else
		record->state = TO_ENCRYPT;
        if(encrypt_record(sess, record) < 0) {
            return -1;
        }
#endif
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
#endif /* VERBOSE_SSL */

    memcpy(sess->send_buffer + sess->send_buffer_offset, record->data, record->length);
    sess->send_buffer_offset += record->length;
    copy_len = record->length;

    if (send_type) {
		ret = -1;
        while (ret < 0) {
#if OFFLOAD_AES_GCM
			if (send_type == PKT_TYPE_OFFL_TLS_AES) {
				ret = send_tcp_packet(sess->parent, sess->send_buffer,
							  sess->send_buffer_offset, TCP_FLAG_ACK, 
							  TCP_OFFL_TSO | TCP_OFFL_TLS_AES);
			} else {
				ret = send_tcp_packet(sess->parent, sess->send_buffer,
							  sess->send_buffer_offset, TCP_FLAG_ACK, 0);
			}
#else
            ret = send_tcp_packet(sess->parent, sess->send_buffer,
                                  sess->send_buffer_offset, TCP_FLAG_ACK, 0);
#endif

            if (unlikely(ret < 0))
                fprintf(stderr, "\nSending Payload failed, len: %d\n",
                                sess->ctx->dpc->wmbufs[sess->parent->portid].len);
        }
        memset(&sess->send_buffer, 0, sizeof(sess->send_buffer));
        sess->send_buffer_offset = 0;
    }

    delete_record(sess, record);

    return copy_len;
}

static inline int
handle_change_cipher_spec(struct ssl_session* sess, record_t* record)
{
#if VERBOSE_SSL
    fprintf(stderr, "[Handle CHANGE_CIPHER_SPEC]\n\n");
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

int send_server_hello(struct ssl_session* sess)
{
    record_t* server_hello = new_send_record(sess);
    int length = 0;
    server_hello_t *psh =
        &server_hello->fragment.handshake.body.server_hello;
    int ret;

    security_params_t *sp;
    sp = &sess->pending_sp;

#if VERBOSE_SSL
	fprintf(stderr, "[send server hello]\n");
#endif

    memcpy(&psh->random, sp->server_random,
            sizeof(sp->server_random));
    length += sizeof(psh->random);

    psh->session_id_length = sizeof(session_id_t);
    length += sizeof(psh->session_id_length);

    psh->session_id = sess->id_;
    length += sizeof(psh->session_id);

    psh->cipher_suite = sp->cipher;
    length += sizeof(psh->cipher_suite);

    psh->compression_method.cm = NO_COMP;
    length += sizeof(psh->compression_method);

    psh->version = sess->version;
    length += sizeof(psh->version);

    ret = send_handshake(sess, server_hello, SERVER_HELLO, length, 0);
    if (unlikely(0 > ret)) {
        fprintf(stderr, "send_handshake for server_hello failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int send_certificate(struct ssl_session* sess)
{
    record_t* certificates = new_send_record(sess);
    int length = 0;
    certificate_list_t *pcert =
        &certificates->fragment.handshake.body.certificate;
    certificate_t temp_certificate;
    int ret;

#if VERBOSE_SSL
	fprintf(stderr, "[send certificate]\n");
#endif

    pcert->certificates = &temp_certificate;
    pcert->certificates->certificate = sess->ctx->ssl_context->certificate;
    length += sess->ctx->ssl_context->certificate_length;

    set_u32(&pcert->certificates->length, (uint32_t *)&length);
    length += sizeof(pcert->certificates[0].length);

    set_u32(&pcert->certificate_length, (uint32_t *)&length);
    length += sizeof(pcert->certificate_length);

    ret = send_handshake(sess, certificates, CERTIFICATE, length, 0);
    if (unlikely(0 > ret)) {
        fprintf(stderr, "send_handshake for certificate failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int send_server_hello_done(struct ssl_session* sess)
{
    record_t *server_hello_done = new_send_record(sess);
    int length = 0;
    int ret;

#if VERBOSE_SSL
	fprintf(stderr, "[send server hello done]\n");
#endif

    ret =  send_handshake(sess,
                          server_hello_done,
                          SERVER_HELLO_DONE,
                          length,
                          PKT_TYPE_HELLO);
    if (unlikely(0 > ret)) {
        fprintf(stderr,
                "send_handshake for server_hello_done failed\n");
        exit(EXIT_FAILURE);
    }

    return ret;
}

int send_change_cipher_spec(struct ssl_session* sess)
{
    record_t* change_cipher_spec = new_send_record(sess);
    int length = 0;
    int ret;

#if VERBOSE_SSL
	fprintf(stderr, "[send change cipher spec]\n");
#endif

    change_cipher_spec->fragment.change_cipher_spec.type = 1;
    length +=
        sizeof(change_cipher_spec->fragment.change_cipher_spec.type);

#if OFFLOAD_AES_GCM
    ret = send_record(sess,
					  change_cipher_spec,
					  CHANGE_CIPHER_SPEC,
					  length,
					  PKT_TYPE_FINISH);
#else
    ret = send_record(sess,
                      change_cipher_spec,
                      CHANGE_CIPHER_SPEC,
                      length,
                      PKT_TYPE_NONE);
#endif
    if (unlikely(0 > ret)) {
        fprintf(stderr, "send_record for change_cipher_spec failed.\n");
        return -1;
    }

    return ret;
}

int send_server_finish(struct ssl_session *sess, uint8_t *digest)
{
    uint8_t *my_vd;
    record_t *server_finished = new_send_record(sess);
    int length = 0;
    int ret;

#if VERBOSE_AES
	fprintf(stderr, "[send server finish] check0\n");
#endif

    /* Send Server Finish */
    my_vd = server_finished-> \
            fragment.handshake.body.server_finished.verify_data;

    if(!digest) {
        fprintf(stderr, "NULL digest!\n");
        exit(EXIT_FAILURE);
    }
    memcpy(my_vd, digest, FINISH_DIGEST_SIZE);

    length += FINISH_DIGEST_SIZE;

    /* There is only FINISHED (20), actually */
#if OFFLOAD_AES_GCM
	if(sess->is_offl_aead) {
		ret = send_handshake(sess,
							 server_finished,
							 CLIENT_FINISHED,
							 length,
							 PKT_TYPE_OFFL_TLS_AES);
	} else {
		ret = send_handshake(sess,
							 server_finished,
							 CLIENT_FINISHED,
							 length,
							 PKT_TYPE_FINISH);
	}
#else
    ret = send_handshake(sess,
                         server_finished,
                         CLIENT_FINISHED,
                         length,
                         PKT_TYPE_FINISH);
#endif
    if (unlikely(0 > ret)) {
        fprintf(stderr, "send_handshake for server_finished failed.\n");
        exit(EXIT_FAILURE);
    }

    return ret;
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

    int random_size = sizeof(pending_sp->client_random) +
                      sizeof(pending_sp->server_random);
    uint8_t randoms[random_size];
	const EVP_MD* (*hash_func)(void);
    unsigned z;

#if VERBOSE_SSL
    fprintf(stderr, "[Handle Handshake] type: %d, len: %d\n",
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
            if (likely(record->plain_text.version.major == 0x03)) {
                client_hello = &(record->fragment.handshake.body.client_hello);
                cipher = select_cipher(client_hello->cipher_suite_length,
                                       client_hello->cipher_suites);
				pending_sp->cipher = cipher;

				if (COMPARE_CIPHER(cipher, TLS_RSA_WITH_AES_256_GCM_SHA384)) {
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
                } else if (COMPARE_CIPHER(cipher, TLS_RSA_WITH_AES_256_CBC_SHA)) {
                    pending_sp->entity = SERVER;
                    pending_sp->prf_algorithm = PRF_SHA256;
                    pending_sp->bulk_cipher_algorithm = AES;
                    pending_sp->cipher_type = BLOCK;
                    pending_sp->enc_key_size = 32;
                    pending_sp->block_length = 16; /* Actually, not used */
                    pending_sp->fixed_iv_length = 16;
                    pending_sp->record_iv_length = 16; /* Actually, not used */
                    pending_sp->mac_length = 16; /* Actually, not used */
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
                } else {
                    fprintf(stderr, "Unsupported Cipher\n");
                }
                sess->version = client_hello->version;
            }
            else if (record->plain_text.version.major == 0x02) {
                fprintf(stderr, "Not supported version\n");
            }
            else
                assert(0);

#if VERBOSE_SSL
            fprintf(stderr, "CLIENT HELLO RECEIVED\n\n");
            fprintf(stderr, "Prepare SERVER HELLO\n");
#endif /* VERBOSE_SSL */

            // send server hello
            send_server_hello(sess);
            sess->handshake_state = SERVER_HELLO;
#if VERBOSE_SSL
            fprintf(stderr, "SERVER HELLO SENT\n\n");
            fprintf(stderr, "Prepare CERTIFICATE\n");
#endif /* VERBOSE_SSL */

            //send certificate
            send_certificate(sess);
            sess->handshake_state = CERTIFICATE;
#if VERBOSE_SSL
            fprintf(stderr, "CERTIFICATE SENT\n\n");
            fprintf(stderr, "Prepare SERVER HELLO DONE\n");
#endif /* VERBOSE_SSL */

            //send server hello done
            send_server_hello_done(sess);
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

			/* the record should be deleted when get the result, not here */
			return 0;
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

            /* Exclude the last message */
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
                if (unlikely(vd[z] != verify_handshake[z]))
                    break;

            if (unlikely(z != sizeof(verify_handshake))) {
                fprintf(stderr, "Wrong Handshake Data!!\n");
				abort_session(sess);
				goto handshake_record_finish;
			}

#if VERBOSE_SSL
            else
                fprintf(stderr, "Handshake Verified!!\n");
#endif /* VERBOSE_SSL */

            /* Send CHANGE_CIPHER_SPEC */
            int change_cipher_pkt_len;
            change_cipher_pkt_len = send_change_cipher_spec(sess);
			if(change_cipher_pkt_len < 0) {
				return -1;
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

#if OFFLOAD_AES_GCM
			/* Add tls_ctx on established session */
			if (COMPARE_CIPHER(sess->write_sp.cipher, 
							   TLS_RSA_WITH_AES_256_GCM_SHA384)) {
				sess->is_offl_aead = 1;
				sess->tls_ctx.tls_version[0] = 3;
				sess->tls_ctx.tls_version[1] = 3;
				/**< TLS v1.2 */
				sess->tls_ctx.cipher_suite = 0x009d;
				/**< TLS_RSA_WITH_AES_256_GCM_SHA384 */
				sess->tls_ctx.aead_key.key_size = 32;
				sess->tls_ctx.aead_key.key = sess->server_write_key;
				sess->tls_ctx.aead_key.iv_size = 4; /* implicit */
				sess->tls_ctx.aead_key.server_write_iv =
					sess->server_write_IV;
				sess->tls_ctx.next_record_num = 0;
				sess->tls_ctx.next_tcp_seq = sess->parent->next_sent_seq;
				sess->tls_ctx.is_ooo = 1;

				/* create tls dev for this session key */
				if (rte_eth_tls_device_create(
							  sess->parent->portid, &sess->tls_ctx) < 0) {
					DEBUG_PRINT("can't create tls_dev!\n");
					exit(EXIT_FAILURE);
				}

				/* DEBUG_PRINT("[core %u] create tls_dev!\n",  */
				/* 			rte_lcore_id()); */
			}
			/* /\* debug *\/ */
			/* exit(EXIT_FAILURE); */
#endif

            /* Make Server Finish */
            int server_finish_len;
            uint8_t digest[FINISH_DIGEST_SIZE];

            server_finish_len = FINISH_DIGEST_SIZE;

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
                FINISH_DIGEST_SIZE, digest);

#if ONLOAD
            int ret;
            ret = send_connection_state(sess, change_cipher_pkt_len, server_finish_len);
            if (unlikely(ret < 0)) {
                fprintf(stderr, "Sending Connection State Failed!\n");
            }

            /* Change the connection rule */
            ret = change_connection_rule(sess);
            if (unlikely(ret < 0)) {
                fprintf(stderr, "Changing Connection Rule Failed!\n");
            }
#else /* ONLOAD */
            UNUSED(server_finish_len);
            UNUSED(change_cipher_pkt_len);
#endif /* !ONLOAD */

            memcpy(sess->server_finish_digest, digest, FINISH_DIGEST_SIZE);
            send_server_finish(sess, sess->server_finish_digest);
            sess->handshake_state = SERVER_FINISHED;

            sess->state = STATE_ACTIVE;
            break;
        default:
            fprintf(stderr, "Unmatched handshake, %d\n", record->fragment.handshake.msg_type);
			abort_session(record->sess);
            return -1;
			break;
    }

handshake_record_finish:
    delete_record(sess, record);
    record = NULL;

    return 0;
}

static inline int
send_handshake(struct ssl_session* sess, record_t* record,
               uint8_t msg_type, int length, int send_type)
{
#if VERBOSE_SSL
    fprintf(stderr, "[SEND HANDSHAKE]\n");
#endif /* VERBOSE_SSL */
    set_u32(&record->fragment.handshake.length, (uint32_t *)&length);
    length += sizeof(record->fragment.handshake.length);
    record->fragment.handshake.msg_type = msg_type;
    length += sizeof(record->fragment.handshake.msg_type);

    return send_record(sess, record, HANDSHAKE, length, send_type);
}

static inline int
verify_mac(struct ssl_session* sess, record_t* record)
{
    unsigned pad_len;
    security_params_t *read_sp = &sess->read_sp;
    generic_block_cipher_t *block_cipher =
                            &record->cipher_text.fragment.block_cipher;

#if VERBOSE_SSL
    fprintf(stderr, "[verify mac]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
    if (!op) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE; */
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
		if(pad_len != *(end - 1) || pad_len > record->cipher_text.length) {
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

    }
    else {
		fprintf(stderr, "[verify mac] ???\n");
		exit(EXIT_FAILURE);
    }

    memcpy(op->in, &seqnum, sizeof(seqnum));
    op->out = record->mac_buf;
    op->data = (void *)record;

	if (0 > execute_mac_crypto(op)) {
		/* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
		delete_op(op);
		return -1;
	}

#if VERBOSE_MAC
    fprintf(stderr, "\nmac key:\n");
    {
        for (unsigned z = 0; z < op->key_len; z++)
            fprintf(stderr, "%02X%c", op->key[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (unsigned z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }


    fprintf(stderr, "\nmac_out:\n");
    {
        for (unsigned z = 0; z < op->out_len; z++)
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

#if VERBOSE_SSL
    fprintf(stderr, "[attach mac]\n");
#endif /* VERBOSE_SSL */

    ssl_crypto_op_t* op = new_ssl_crypto_op(sess);
    if (!op) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_INSUFFICIENT_RESOURCE; */
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
    }
    else {
        op->key = sess->server_write_MAC_secret;
        op->key_len = write_sp->mac_key_size;
        op->out_len = write_sp->mac_key_size;
        op->in_len = record->plain_text.length +
                     sizeof(record->seq_num) +
                     RECORD_HEADER_SIZE;

        block_cipher->content = record->decrypted + RECORD_HEADER_SIZE;
        record->cipher_text.length = record->plain_text.length;
    }

    memcpy(op->in, &seqnum, sizeof(seqnum));
    op->out = record->mac_buf;
    op->data = (void *)record;

    if (0 > execute_mac_crypto(op)) {
        /* sess->msg_num[FAIL] = mtcp_SSL_ERROR_CRYPTO_FAIL; */
        delete_op(op);
        return -1;
    }

#if VERBOSE_MAC
    fprintf(stderr, "\nmac key:\n");
    {
        for (unsigned z = 0; z < op->key_len; z++)
            fprintf(stderr, "%02X%c", op->key[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }

    fprintf(stderr, "\nmac_in:\n");
    {
        for (unsigned z = 0; z < op->in_len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
    }


    fprintf(stderr, "\nmac_out:\n");
    {
        for (unsigned z = 0; z < op->out_len; z++)
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
    fprintf(stderr, "\n[Unpack Header]\n");
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
    }
    else {
        plain_text->c_type = HANDSHAKE;
        plain_text->version.major = 0x02;
        plain_text->version.minor = 0x00;
        plain_text->length = record->length - 2;
    }

    return 0;
}

static inline void
push_read_record(struct ssl_session* sess, record_t* record)
{
    TAILQ_INSERT_TAIL(&sess->recv_q, record, recv_q_link);
    sess->recv_q_cnt++;
}

inline int
process_session_read(struct ssl_session* sess)
{
    int processed_record = 0;
    record_t *target;

    assert(sess->recv_q_cnt >= 0);

    while(sess->recv_q_cnt > 0 && !sess->waiting_crypto) {
        target = TAILQ_FIRST(&sess->recv_q);

        TAILQ_REMOVE(&sess->recv_q, target, recv_q_link);
        sess->recv_q_cnt--;

        process_read_record(sess, target);
        processed_record++;
    }

    return processed_record;
}

static inline int
process_read_record(struct ssl_session* sess, record_t* record)
{
    assert(record != NULL);

#if VERBOSE_SSL
	fprintf(stderr, "[PROCESS READ RECORD]\n");
#endif
#if VERBOSE_CHUNK
    fprintf(stderr,"\nNew READ RECORD\n");
    {
		unsigned z;
        for (z = 0; z < record->length; z++)
            fprintf(stderr, "%02X%c", record->data[z],
                                ((z + 1) % 16) ? ' ' : '\n');
    }
#endif /* VERBOSE_SSL */

    if (unlikely(0 < unpack_header(record))) {
        fprintf(stderr, "unpack_header failed\n");
        exit(EXIT_FAILURE);
    }

	if(sess->read_sp.bulk_cipher_algorithm != NO_CIPHER) {
		if(sess->read_sp.mac_algorithm == NO_MAC) {  
			fprintf(stderr, "[process_read_record] Error: the encrypted packet has no MAC!\n");
            exit(EXIT_FAILURE);
        }

        /* decrypt_record(sess, record, record->data, record->length); */
        decrypt_record(sess, record);
        if (sess->pending_sp.cipher_type != AEAD)
            if(0 > verify_mac(sess, record)) {
				/* debug */
				fprintf(stderr, "[process read record] verify mac failed\n");
				return -1;
			}
    } else {
        record->decrypted = record->data;
    }

	record->state = TO_UNPACK_CONTENT;
	if (0 > unpack_record(record)) {
		/* sess->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_RECORD; */
		return -1;
	}

    /* ToDo: move below code to where handshake is handled*/
    /* do RSA decryption if needed */
	/* PKA is asynchronous call.. we should not call handle_read_record() here. */
    if (record->plain_text.c_type == HANDSHAKE &&
        record->fragment.handshake.msg_type == CLIENT_KEY_EXCHANGE) {
#if VERBOSE_SSL
        fprintf(stderr, "RSA Decrypt Needed!\n");
#endif /* VERBOSE_SSL */
        if (rsa_decrypt_record(sess, record) < 0)
            return -1;
		else
			return 0;
    }

    return handle_read_record(sess, record);
}

static inline int
process_new_record(struct ssl_session* sess, uint8_t *buf, size_t len)
{
    size_t processed_len = 0;
    size_t copy_len = 0;
    record_t* crr;
    uint16_t record_len = 0;

#if VERBOSE_SSL
    fprintf(stderr, "\n[Process New Record]\n");
#endif /* VERBOSE_SSL */
    crr = sess->current_read_record;

    while (processed_len < len) {
        if (crr == NULL) {
            uint8_t* ph;

            if (len - processed_len < RECORD_HEADER_SIZE)
                break;

            crr = sess->current_read_record = new_recv_record(sess);
            if (crr == NULL)
                return processed_len;

            ph = buf + processed_len;

            record_len = ntohs(*(uint16_t *)(ph + 3));
#if VERBOSE_SSL
			uint8_t record_type;
            record_type = *ph;
            fprintf(stderr, "\nNew RECORD Session %d: "
					"%d, processed: %lu, record type: %u, len: %u\n",
					sess->parent->session_id, crr->id,
					processed_len, record_type, record_len);
            {
				unsigned z;
                for (z = 0; z < 64; z++)
                    fprintf(stderr, "%02X%c", ph[z],
                                    ((z + 1) % 16) ? ' ' : '\n');
            }
#endif /* VERBOSE_SSL */
            assert(record_len < 16384+2048);
            crr->length = record_len + RECORD_HEADER_SIZE;
        }

#if ZERO_COPY_RECV
		/* selectively copy packet between TCP-TLS */
		if (crr->current_len > 0 ||
			crr->length > len - processed_len ||
			sess->waiting_crypto ||
			sess->handshake_state == SERVER_HELLO_DONE) {

			copy_len = MIN(crr->length - crr->current_len,
						   len - processed_len);
			memcpy(crr->data + crr->current_len,
				   buf + processed_len, copy_len);
			crr->current_len += copy_len;
			processed_len += copy_len;
		} else {
			crr->data = buf + processed_len;
			crr->current_len += crr->length;
			processed_len += crr->length;
		}
#else  /* ZERO_COPY_RECV */
		copy_len = MIN(crr->length - crr->current_len,
					   len - processed_len);
		memcpy(crr->data + crr->current_len, buf + processed_len, copy_len);
		crr->current_len += copy_len;
		processed_len += copy_len;
#endif /* !ZERO_COPY_RECV */

#if VERBOSE_SSL
        fprintf(stderr, "crr->length: %lu, crr->current_len: %lu, "
                        "len: %lu, processed_len: %lu\n",
                        crr->length, crr->current_len, len, processed_len);
#endif /* VERBOSE_SSL */

        if (crr->current_len == crr->length) {
#if MODIFY_FLAG
			if (sess->waiting_crypto)
				push_read_record(sess, crr);
			else
				process_read_record(sess, crr);
#else
            push_read_record(sess, crr);
#endif
			
            sess->current_read_record = NULL;
            crr = NULL;
        } 
    }

    /* We need next packet */
    if (crr != NULL) {
       return -1; 
    }

    return processed_len;
}

inline int
process_ssl_packet(struct tcp_session* tcp_sess,
                 uint8_t *payload, uint16_t payloadlen)
{
    struct ssl_session *ssl_sess = tcp_sess->ssl_session;
    if (!ssl_sess || !payload || payloadlen == 0)
        return -1;

#if VERBOSE_SSL
    fprintf(stderr, "\n--------------< SSL Packet >--------------\n");
#endif /* VERBOSE_SSL */

    return process_new_record(ssl_sess, payload, payloadlen);
}
