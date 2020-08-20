#include "host.h"


#if ONLOAD

inline int
change_connection_rule(struct ssl_session* sess)
{
    sess->parent->onload = 1;

    return 0;
}

static inline void
build_connection_meta(struct ssl_session *ssl, conn_meta_t *meta)
{
    struct tcp_session *tcp = ssl->parent;
    security_params_t *sp = &ssl->write_sp;

    meta->session_id = tcp->session_id;

    /* SSL related parameter */
    meta->version = ssl->version;

    meta->bulk_cipher_algorithm = sp->bulk_cipher_algorithm;
    meta->cipher_type = sp->cipher_type;
    meta->mac_algorithm = sp->mac_algorithm;

    meta->mac_key_size = sp->mac_key_size;

    memcpy(&meta->client_write_MAC_secret,
           &ssl->client_write_MAC_secret,
           sp->mac_key_size);

    memcpy(&meta->server_write_MAC_secret,
           &ssl->server_write_MAC_secret,
           sp->mac_key_size);

    meta->enc_key_size = sp->enc_key_size;

    memcpy(&meta->client_write_key,
           &ssl->client_write_key,
           sp->enc_key_size);

    memcpy(&meta->server_write_key,
           &ssl->server_write_key,
           sp->enc_key_size);

    meta->fixed_iv_length = sp->fixed_iv_length;

    memcpy(&meta->client_write_IV,
           &ssl->client_write_IV,
           sp->fixed_iv_length);

    memcpy(&meta->server_write_IV,
           &ssl->server_write_IV,
           sp->fixed_iv_length);

}

static inline void
encrypt_meta(struct ssl_session *sess, uint8_t *meta, uint8_t *encrypted, int len)
{
    ssl_crypto_op_t *op;
    struct thread_context *ctx = sess->ctx;

    op = TAILQ_FIRST(&ctx->op_pool);
    if (unlikely(!op)) {
        fprintf(stderr, "[encrypt_meta] Not enough op, and this must not happen.\n");
        exit(EXIT_FAILURE);
    }

    TAILQ_REMOVE(&ctx->op_pool, op, op_pool_link);
    ctx->free_op_cnt--;
    ctx->using_op_cnt++;

    op->in = meta;
    op->out = encrypted;
    op->key = nic_key;
    op->iv = nic_iv;

    op->in_len = len;
    op->out_len = len;
    op->key_len = nic_key_size;
    op->iv_len = nic_iv_size;

    op->opcode.u32 = TLS_OPCODE_AES_CBC_256_ENCRYPT;
    op->data = NULL;


#if VERBOSE_TCP
    fprintf(stderr, "\nOriginal Data:\n");
    {
        int z;
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", op->in[z],
                            ((z + 1) % 16) ? ' ' : '\n');
        fprintf(stderr, "\n");
    }
#endif /* VERBOSE_TCP */

    execute_aes_crypto(sess->ctx->symmetric_crypto_ctx, op);

#if VERBOSE_TCP
    fprintf(stderr, "\nEncrypted Data:\n");
    {
        int z;
        for (z = 0; z < len; z++)
            fprintf(stderr, "%02X%c", op->out[z],
                            ((z + 1) % 16) ? ' ' : '\n');
        fprintf(stderr, "\n");
    }
#endif /* VERBOSE_TCP */
}

inline int
send_connection_state(struct ssl_session* sess, int change_cipher_pkt_len, int server_finish_len)
{
    assert(sess);
    conn_meta_t meta;
    uint8_t encrypted[sizeof(conn_meta_t)];
    uint32_t next_recv_seq = 0, next_recv_ack = 0, next_pkt_len = 0, pad_len = 0;

    build_connection_meta(sess, &meta);

    /* TCP related parameter */
    next_recv_seq = htonl(sess->parent->last_sent_ack + sess->parent->last_recv_len);

	/* AES-CBC */
	if(sess->write_sp.cipher_type == BLOCK) {
		next_pkt_len = sess->write_sp.fixed_iv_length +
			sizeof(sequence_num_t) + 4 + server_finish_len + MAC_SIZE;
		pad_len = (next_pkt_len % 16) ? (16 - (next_pkt_len % 16)) : 0;
		next_pkt_len += pad_len;
		next_pkt_len += RECORD_HEADER_SIZE;

		next_recv_ack = htonl(sess->parent->last_recv_ack +
							  next_pkt_len + change_cipher_pkt_len);
		/* next_recv_ack = htonl(sess->parent->last_recv_ack + */
		/* 					  next_pkt_len + change_cipher_pkt_len); */
	} 

	/* AES-GCM */
	else if (sess->write_sp.cipher_type == AEAD) {
		next_pkt_len = RECORD_HEADER_SIZE;
		next_pkt_len += sizeof(sequence_num_t) + 4 + server_finish_len + GCM_TAG_SIZE;

		next_recv_ack = htonl(sess->parent->last_recv_ack +
							  next_pkt_len + change_cipher_pkt_len);
	}

#if VERBOSE_TCP
    fprintf(stderr, "Sending Meta!\n\n"
                    "last_sent_ack: %u\n"
                    "last_sent_seq: %u\n"
                    "last_sent_len: %u\n"
                    "last_recv_ack: %u\n"
                    "last_recv_seq: %u\n"
                    "last_recv_len: %u\n\n"
                    "change_cipher_pkt_len: %d\n"
                    "server_finish_len: %d\n"
                    "next_pkt_len: %u\n\n"
                    "next_recv_seq: %u\n"
                    "next_recv_ack: %u\n",
                    sess->parent->last_sent_ack,
                    sess->parent->last_sent_seq,
                    sess->parent->last_sent_len,
                    sess->parent->last_recv_ack,
                    sess->parent->last_recv_seq,
                    sess->parent->last_recv_len,
                    change_cipher_pkt_len,
                    server_finish_len,
                    next_pkt_len,
                    ntohl(next_recv_seq),
                    ntohl(next_recv_ack));
#endif /* VERBOSE_TCP */

#if ENCRYPT_META
    encrypt_meta(sess, (uint8_t *)&meta, encrypted, sizeof(conn_meta_t));

    if (unlikely(0 > send_meta_packet(sess->coreid, sess->parent->portid + 1, sess->parent,
                                      next_recv_seq, next_recv_ack,
                                      (uint8_t *)&encrypted, sizeof(conn_meta_t)))) {
        return -1;
    }
#else /* ENCRYPT_META */
    if (unlikely(0 > send_meta_packet(sess->coreid, sess->parent->portid + 1, sess->parent,
                                      next_recv_seq, next_recv_ack,
                                      (uint8_t *)&meta, sizeof(conn_meta_t)))) {
        return -1;
    }
    UNUSED(encrypted);
#endif /* !ENCRYPT_META */

    sess->ctx->stat.completes++;

    return 0;
}

#endif /* ONLOAD */
