#include <ssl_api.h>
#include <mtcp.h>
#include <ssloff.h>
 
#define MAX_FLOW_NUM (10000)
#define HTTP_HEADER_LEN 1024
#define MAX_HEADER_LEN (HTTP_HEADER_LEN + MAX_KEY_SIZE)
#define MIN(a, b) ((a)<(b)?(a):(b))

/* Not fully implemented yet */
int mtcp_SSL_library_init(void)
{
    return 1;
}

mtcp_SSL_METHOD *
mtcp_TLSv1_2_server_method(void)
{
	mtcp_SSL_METHOD *ret = (mtcp_SSL_METHOD *)calloc(1, sizeof(int));
	*ret = mtcp_TLSv1_2_server;

	return ret;
}

mtcp_SSL_CTX *
mtcp_SSL_CTX_new(mctx_t mctx, const mtcp_SSL_METHOD *method)
{
	int i;

	if (!mctx) {
		fprintf(stderr, "Wrong mctx\n");
		exit(EXIT_FAILURE);
	}

	if (!method) {
		fprintf(stderr, "Wrong method\n");
		exit(EXIT_FAILURE);
	}

	mtcp_SSL_CTX *ssl_ctx = (mtcp_SSL_CTX *)calloc(1, sizeof(mtcp_SSL_CTX));
	ssl_ctx->method = method;
	ssl_ctx->mctx = mctx;
	ssl_ctx->coreid = mctx->cpu;

	TAILQ_INIT(&ssl_ctx->record_pool);
	TAILQ_INIT(&ssl_ctx->whole_record);
	ssl_ctx->free_record_cnt = 0;
	ssl_ctx->using_record_cnt = 0;

	for (i = 0; i < MAX_FLOW_NUM * 4; i++) {
		record_t *new_record = (record_t *)calloc(1, sizeof(record_t));
		new_record->ctx = ssl_ctx;
		TAILQ_INSERT_TAIL(&ssl_ctx->record_pool, new_record, record_pool_link);
		TAILQ_INSERT_TAIL(&ssl_ctx->whole_record, new_record, record_trace_link);
		ssl_ctx->free_record_cnt++;
	}

	TAILQ_INIT(&ssl_ctx->op_pool);
	TAILQ_INIT(&ssl_ctx->whole_op);
	ssl_ctx->free_op_cnt = 0;
	ssl_ctx->using_op_cnt = 0;

	for (i = 0; i < MAX_FLOW_NUM * 4; i++) {
		ssl_crypto_op_t *new_op =
			(ssl_crypto_op_t *)calloc(1, sizeof(ssl_crypto_op_t));
		new_op->ctx = ssl_ctx;
		TAILQ_INSERT_TAIL(&ssl_ctx->op_pool, new_op, op_pool_link);
		TAILQ_INSERT_TAIL(&ssl_ctx->whole_op, new_op, op_trace_link);
		ssl_ctx->free_op_cnt++;
	}

	return ssl_ctx;
}

int
mtcp_get_free_op(mtcp_SSL_CTX *ssl_ctx)
{
	return ssl_ctx->free_op_cnt;
}

int
mtcp_get_using_op(mtcp_SSL_CTX *ssl_ctx)
{
	return ssl_ctx->using_op_cnt;
}

void
mtcp_SSL_CTX_free(mtcp_SSL_CTX *ssl_ctx)
{
	void *cur, *next;

	if (ssl_ctx->public_crypto_ctx.rsa)
		free(ssl_ctx->public_crypto_ctx.rsa);

    EVP_CIPHER_CTX_free(ssl_ctx->symmetric_crypto_ctx);

	cur = TAILQ_FIRST(&ssl_ctx->op_pool);
	while(cur != NULL) {
		next = (ssl_crypto_op_t *)TAILQ_NEXT((ssl_crypto_op_t *)cur,
												op_pool_link);
		TAILQ_REMOVE(&ssl_ctx->op_pool,
						(ssl_crypto_op_t *)cur,
						op_pool_link);
		cur = next;
	}

	cur = TAILQ_FIRST(&ssl_ctx->record_pool);
	while(cur != NULL) {
		next = (record_t *)TAILQ_NEXT((record_t *)cur,
										record_pool_link);
		TAILQ_REMOVE(&ssl_ctx->record_pool,
						(record_t *)cur,
						record_pool_link);
		cur = next;
	}

	cur = TAILQ_FIRST(&ssl_ctx->whole_op);
	while(cur != NULL) {
		next = (ssl_crypto_op_t *)TAILQ_NEXT((ssl_crypto_op_t *)cur,
												op_trace_link);
		TAILQ_REMOVE(&ssl_ctx->whole_op,
						(ssl_crypto_op_t *)cur,
						op_trace_link);
		free(cur);
		cur = next;
	}

	cur = TAILQ_FIRST(&ssl_ctx->whole_record);
	while(cur != NULL) {
		next = (record_t *)TAILQ_NEXT((record_t *)cur,
										record_trace_link);
		TAILQ_REMOVE(&ssl_ctx->whole_record,
						(record_t *)cur,
						record_trace_link);
		free(cur);
		cur = next;
	}

	free(ssl_ctx);
}

int
mtcp_SSL_CTX_use_CRYPTO_CTX(mtcp_SSL_CTX *ssl_ctx, mtcp_PUBLIC_CRYPTO_CTX *public_crypto_ctx)
{
	if (!ssl_ctx) {
		fprintf(stderr, "Wrong mctx\n");
		return -1;
	}

	if (!public_crypto_ctx) {
		fprintf(stderr, "Wrong public_crypto_ctx\n");
		return -1;
	}
	else {
		if (!public_crypto_ctx->rsa) {
			fprintf(stderr, "Wrong rsa in public_crypto_ctx\n");
			return -1;
		}
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	ssl_ctx->public_crypto_ctx.rsa = RSA_new();
#else
	ssl_ctx->public_crypto_ctx.rsa = (RSA *)calloc(1, sizeof(RSA));
#endif
	if(ssl_ctx->public_crypto_ctx.rsa == NULL) {
		fprintf(stderr, "Can't get rsa\n");
		exit(EXIT_FAILURE);
	}
	memcpy(&ssl_ctx->public_crypto_ctx, public_crypto_ctx, sizeof(mtcp_PUBLIC_CRYPTO_CTX));
	/* memcpy(ssl_ctx->public_crypto_ctx.rsa, public_crypto_ctx->rsa, sizeof(RSA)); */

	/* Create and initialise the OpenSSL AES context */
    if(!(ssl_ctx->symmetric_crypto_ctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "Wrong ssl_aes_ctx\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

mtcp_SSL *
mtcp_SSL_new(mtcp_SSL_CTX *ssl_ctx)
{
	if (!ssl_ctx) {
		fprintf(stderr, "Wrong ssl_rsa_ctx\n");
		exit(EXIT_FAILURE);
	}

#if MODIFY_FLAG
	srandom(time(NULL));
#endif

	mtcp_SSL *ssl = (mtcp_SSL *)calloc(1, sizeof(mtcp_SSL));

	ssl->mctx = ssl_ctx->mctx;
	ssl->coreid = ssl_ctx->mctx->cpu;
	ssl->ctx = ssl_ctx;

	ssl->next_record_id = 0;
	TAILQ_INIT(&ssl->recv_q);
	ssl->recv_q_cnt = 0;

	clear_session(ssl);

	return ssl;
}

void
mtcp_SSL_free(mtcp_SSL *ssl)
{
	void *cur, *next;

	cur = TAILQ_FIRST(&ssl->recv_q);
	while(cur != NULL) {
		next = (record_t *)TAILQ_NEXT((record_t *)cur,
										recv_q_link);
		TAILQ_REMOVE(&ssl->recv_q,
						(record_t *)cur,
						recv_q_link);
		cur = next;
	}
}

int
mtcp_SSL_set_fd(mtcp_SSL *ssl, int fd)
{
	if (!ssl) {
		fprintf(stderr, "Wrong ssl\n");
		return -1;
	}

	if (fd < 0) {
		fprintf(stderr, "Wrong fd\n");
		return -1;
	}

	ssl->sockid = fd;
	return 0;
}

int
mtcp_SSL_get_fd(mtcp_SSL *ssl)
{
	if (!ssl) {
		fprintf(stderr, "Wrong ssl\n");
		return -1;
	}

	return ssl->sockid;
}

void
mtcp_SSL_clear(mtcp_SSL *ssl)
{
	clear_session(ssl);
	return;
}

int
mtcp_SSL_accept(mtcp_SSL *ssl)
{
	int rd;
	uint8_t raw_buf[MAX_HEADER_LEN];
	char buf[MAX_HEADER_LEN];
	mtcp_manager_t mtcp;
	socket_map_t socket;
	tcp_stream *cur_stream;
	int sockid;
	int ret;

	mtcp = GetMTCPManager(ssl->mctx);
	sockid = ssl->sockid;
	if (!mtcp) {
		return -1;
	}

	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
		fprintf(stderr, "Socket id %d out of range.\n", sockid);
		errno = EBADF;
		return -1;
	}

	socket = &mtcp->smap[sockid];
	if (socket->socktype == MTCP_SOCK_UNUSED) {
		fprintf(stderr, "Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}
	
	if (socket->socktype != MTCP_SOCK_STREAM) {
		fprintf(stderr, "Not an end socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	/* stream should be in ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
	cur_stream = socket->stream;
	if (!cur_stream || 
			!(cur_stream->state >= TCP_ST_ESTABLISHED && 
			  cur_stream->state <= TCP_ST_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	if (ssl->current_send_record) {
		/* Have something to send */
		ret = send_record(ssl, ssl->current_send_record,
							HANDSHAKE, ssl->current_send_record->payload_to_send);
		static int case_num = 0;
		if (ret > 0) {
			case_num++;
			fprintf(stderr, "case_num: %d\n", case_num);
			/* Make handshake functions modularize and switch case here */
		}

		return ret;
	}

	if (cur_stream->ssl_onload) {
		ssl_info_t *info = cur_stream->ssl_info;
		security_params_t *sp = &ssl->pending_sp;
		if (!info->active)
			return -1;

		/* Get all ssl related info here */
		ssl->state = STATE_ACTIVE;
		ssl->handshake_state = SERVER_FINISHED;

		ssl->version.major = info->version.major;
		ssl->version.minor = info->version.minor;

		ssl->send_seq_num_ = 1;
		ssl->recv_seq_num_ = 1;

		memcpy(&ssl->client_write_MAC_secret,
				&info->client_write_MAC_secret,
				MAX_KEY_SIZE); 
		memcpy(&ssl->server_write_MAC_secret,
				&info->server_write_MAC_secret,
				MAX_KEY_SIZE); 

		memcpy(&ssl->client_write_key,
				&info->client_write_key,
				MAX_KEY_SIZE); 
		memcpy(&ssl->server_write_key,
				&info->server_write_key,
				MAX_KEY_SIZE);

		memcpy(&ssl->client_write_IV,
				&info->client_write_IV,
				MAX_KEY_SIZE); 
		memcpy(&ssl->server_write_IV,
				&info->server_write_IV,
				MAX_KEY_SIZE); 

		sp->entity = SERVER;
		sp->prf_algorithm = PRF_SHA256;

		sp->bulk_cipher_algorithm = info->bulk_cipher_algorithm;
		sp->cipher_type = info->cipher_type;
		sp->mac_algorithm = info->mac_algorithm;
		sp->enc_key_size = info->enc_key_size;
		sp->fixed_iv_length = info->fixed_iv_length;
		sp->mac_key_size = info->mac_key_size;

		if(sp->cipher_type == AEAD)
			sp->record_iv_length = 8;

		sp->compression_algorithm = NO_COMP;

		memcpy(&ssl->write_sp, sp, sizeof(security_params_t));
		memcpy(&ssl->read_sp, sp, sizeof(security_params_t));

		return mtcp_SSL_SUCCESS_OFFLOAD;
	}

	rd = mtcp_read(ssl->mctx, ssl->sockid, (char *)raw_buf, MAX_HEADER_LEN);
	if (rd <= 0) {
		if (rd == 0)
			ssl->msg_num[FAIL] = mtcp_SSL_ERROR_TCP_RETURN_ZERO;
		else
			ssl->msg_num[FAIL] = mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE;

		return FAIL;
	}

	ret = process_ssl_packet(ssl, raw_buf, rd, buf, MAX_HEADER_LEN);
	if (ret < 0) {
		fprintf(stderr, "process_ssl_packet failed\n");
		return FAIL;
	}

	if (ssl->state == STATE_ACTIVE) {
		assert(ssl->handshake_state == SERVER_FINISHED);
		return mtcp_SSL_SUCCESS_NORMAL;
	}

	if (ssl->state == STATE_HANDSHAKE) {
		/* Set err_num */
		if (ssl->handshake_state == CLIENT_HELLO ||
			ssl->handshake_state == SERVER_HELLO ||
			ssl->handshake_state == CERTIFICATE ||
			ssl->handshake_state == CLIENT_FINISHED ||
			ssl->handshake_state == SERVER_CIPHER_SPEC)
		{
			fprintf(stderr, "Can this really happen??\n");
			ssl->msg_num[FAIL] = mtcp_SSL_ERROR_WANT_WRITE;
		}
		else if (ssl->handshake_state == SERVER_HELLO_DONE ||
					ssl->handshake_state == CLIENT_KEY_EXCHANGE ||
					ssl->handshake_state == CLIENT_CIPHER_SPEC)
		{
			ssl->msg_num[FAIL] = mtcp_SSL_ERROR_WANT_READ;
		}

		return FAIL;
	}

	ssl->msg_num[FAIL] = mtcp_SSL_ERROR_UNKNOWN;
	return FAIL;
}

int
mtcp_SSL_get_error(mtcp_SSL *ssl, int ret_val)
{
	return ssl->msg_num[ret_val];
}

int
mtcp_SSL_shutdown(mtcp_SSL *ssl)
{
	return close_session(ssl);
}

int
mtcp_SSL_read(mtcp_SSL *ssl, void *buf, int num)
{
	/* May be the size of raw buf should be changed */
	uint8_t raw_buf[num];
	int rd;
	int ret;
	int copy_len;

	rd = mtcp_read(ssl->mctx, ssl->sockid, (char *)raw_buf, num);
	if (rd <= 0) {
		if (ssl->read_buf_offset == 0) {
			if (rd == 0)
				ssl->msg_num[FAIL] = mtcp_SSL_ERROR_TCP_RETURN_ZERO;
			else
				ssl->msg_num[FAIL] = mtcp_SSL_ERROR_TCP_RETURN_NEGATIVE;
			return FAIL;
		}
		else {
			goto do_copy;
		}
	}

	ret = process_ssl_packet(ssl, raw_buf, rd, buf, num);
	if (ret < 0)
		return FAIL;

	if (ssl->read_buf_offset == 0) {
		ssl->msg_num[FAIL] = mtcp_SSL_ERROR_WANT_READ;
		return FAIL;
	}

do_copy:
	if (ssl->read_buf_offset <= num) {
		copy_len = ssl->read_buf_offset;
		memcpy(buf, ssl->read_buf, ssl->read_buf_offset);
		ssl->read_buf_offset = 0;
		return copy_len;
	}
	else {
		memcpy(buf, ssl->read_buf, num);
		memcpy(ssl->read_buf, ssl->read_buf + num, ssl->read_buf_offset - num);
		ssl->read_buf_offset -= num;
		return num;
	}

	ssl->msg_num[FAIL] = mtcp_SSL_ERROR_UNKNOWN;
	return FAIL;
}

int
mtcp_SSL_write(mtcp_SSL *ssl, void *buf, int num)
{
	int ret;
	record_t *cur;

	if (ssl->current_send_record) {
		cur = ssl->current_send_record;
		if (cur->payload_to_send != num ||
			cur->where_to_send != buf ||
			cur->already_sent < 0) {
			ssl->msg_num[FAIL] = mtcp_SSL_ERROR_INVALID_ARGUMENT;
			return FAIL;
		}
	}

	ret = send_data(ssl, buf, num);
	return ret;
}
