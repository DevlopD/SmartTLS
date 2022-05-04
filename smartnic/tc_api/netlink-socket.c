/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* #include <config.h> */
#include "netlink-socket.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
/* #include "coverage.h" */
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "netlink.h"
#include "netlink-protocol.h"
#include "odp-netlink.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "seq.h"
#include "socket-util.h"
#include "util.h"

/* COVERAGE_DEFINE(netlink_overflow); */
/* COVERAGE_DEFINE(netlink_received); */
/* COVERAGE_DEFINE(netlink_recv_jumbo); */
/* COVERAGE_DEFINE(netlink_sent); */

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* A single (bad) Netlink message can in theory dump out many, many log
 * messages, so the burst size is set quite high here to avoid missing useful
 * information.  Also, at high logging levels we log *all* Netlink messages. */

static uint32_t nl_sock_allocate_seq(struct nl_sock *, unsigned int n);

/* Netlink sockets. */

struct nl_sock {
    int fd;
    uint32_t next_seq;
    uint32_t pid;
    int protocol;
    unsigned int rcvbuf;        /* Receive buffer size (SO_RCVBUF). */
};

/* Compile-time limit on iovecs, so that we can allocate a maximum-size array
 * of iovecs on the stack. */
#define MAX_IOVS 128

/* Maximum number of iovecs that may be passed to sendmsg, capped at a
 * minimum of _XOPEN_IOV_MAX (16) and a maximum of MAX_IOVS.
 *
 * Initialized by nl_sock_create(). */
static int max_iovs;

static int nl_pool_alloc(int protocol, struct nl_sock **sockp);
static void nl_pool_release(struct nl_sock *);

/* Creates a new netlink socket for the given netlink 'protocol'
 * (NETLINK_ROUTE, NETLINK_GENERIC, ...).  Returns 0 and sets '*sockp' to the
 * new socket if successful, otherwise returns a positive errno value. */
int
nl_sock_create(int protocol, struct nl_sock **sockp)
{
    /* static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER; */
    struct nl_sock *sock;
    struct sockaddr_nl local, remote;

    socklen_t local_size;
    int rcvbuf;
    int retval = 0;

    /* fprintf(stderr, "[nl_sock_create] check0\n"); */

    /* if (ovsthread_once_start(&once)) { */
    /*     int save_errno = errno; */
    /*     errno = 0; */

    /*     max_iovs = sysconf(_SC_UIO_MAXIOV); */
    /*     if (max_iovs < _XOPEN_IOV_MAX) { */
    /*         if (max_iovs == -1 && errno) { */
    /* 	      ; */
    /*         } */
    /*         max_iovs = _XOPEN_IOV_MAX; */
    /*     } else if (max_iovs > MAX_IOVS) { */
    /*         max_iovs = MAX_IOVS; */
    /*     } */

    /*     errno = save_errno; */
    /*     ovsthread_once_done(&once); */
    /* } */

    *sockp = NULL;
    sock = malloc(sizeof *sock);

    sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
    if (sock->fd < 0) {
        goto error;
    }

    sock->protocol = protocol;
    sock->next_seq = 1;

    rcvbuf = 1024 * 1024;

    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &rcvbuf, sizeof rcvbuf)) {
        /* Only root can use SO_RCVBUFFORCE.  Everyone else gets EPERM.
         * Warn only if the failure is therefore unexpected. */
        if (errno != EPERM) {
	  ;
        }
    }

    /* fprintf(stderr, "[nl_sock_create] check1, sock->fd = %d\n", sock->fd); */

    int error;
    int len = sizeof(retval);
    error = getsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &retval, &len);
    /* error = getsockopt_int(sock->fd, SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF", &rcvbuf); */
    /* retval = get_socket_rcvbuf(sock->fd); */

    /* fprintf(stderr, "[nl_sock_create] check2, error, retval, len = %d %d %d\n", error, retval, len); */

    if (error < 0) {
        error = -error;
        goto error;
    }

    /* fprintf(stderr, "[nl_sock_create] check3\n"); */

    /* if (retval < 0) { */
    /*     retval = -retval; */
    /*     goto error; */
    /* } */
    sock->rcvbuf = retval;
    retval = 0;

    /* Connect to kernel (pid 0) as remote address. */
    memset(&remote, 0, sizeof remote);
    remote.nl_family = AF_NETLINK;
    remote.nl_pid = 0;
    if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
        goto error;
    }

    /* Obtain pid assigned by kernel. */
    local_size = sizeof local;
    if (getsockname(sock->fd, (struct sockaddr *) &local, &local_size) < 0) {
        goto error;
    }
    if (local_size < sizeof local || local.nl_family != AF_NETLINK) {
        retval = EINVAL;
        goto error;
    }
    sock->pid = local.nl_pid;

    *sockp = sock;
    return 0;

error:
    if (retval == 0) {
        retval = errno;
        if (retval == 0) {
            retval = EINVAL;
        }
    }

    if (sock->fd >= 0) {
        close(sock->fd);
    }

    free(sock);
    return retval;
}

/* Creates a new netlink socket for the same protocol as 'src'.  Returns 0 and
 * sets '*sockp' to the new socket if successful, otherwise returns a positive
 * errno value.  */
int
nl_sock_clone(const struct nl_sock *src, struct nl_sock **sockp)
{
    return nl_sock_create(src->protocol, sockp);
}

/* Destroys netlink socket 'sock'. */
void
nl_sock_destroy(struct nl_sock *sock)
{
    if (sock) {
        close(sock->fd);
        free(sock);
    }
}

/* Tries to add 'sock' as a listener for 'multicast_group'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * A socket that is subscribed to a multicast group that receives asynchronous
 * notifications must not be used for Netlink transactions or dumps, because
 * transactions and dumps can cause notifications to be lost.
 *
 * Multicast group numbers are always positive.
 *
 * It is not an error to attempt to join a multicast group to which a socket
 * already belongs. */
int
nl_sock_join_mcgroup(struct nl_sock *sock, unsigned int multicast_group)
{
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &multicast_group, sizeof multicast_group) < 0) {
        return errno;
    }

    return 0;
}

/* Tries to make 'sock' stop listening to 'multicast_group'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * Multicast group numbers are always positive.
 *
 * It is not an error to attempt to leave a multicast group to which a socket
 * does not belong.
 *
 * On success, reading from 'sock' will still return any messages that were
 * received on 'multicast_group' before the group was left. */
int
nl_sock_leave_mcgroup(struct nl_sock *sock, unsigned int multicast_group)
{
    if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                   &multicast_group, sizeof multicast_group) < 0) {
        return errno;
    }

    return 0;
}

static int
nl_sock_send__(struct nl_sock *sock, const struct ofpbuf *msg,
               uint32_t nlmsg_seq, bool wait)
{
    struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(msg);
    int error;

    nlmsg->nlmsg_len = msg->size;
    nlmsg->nlmsg_seq = nlmsg_seq;
    nlmsg->nlmsg_pid = sock->pid;
    do {
        int retval;
        retval = send(sock->fd, msg->data, msg->size,
                      wait ? 0 : MSG_DONTWAIT);

        error = retval < 0 ? errno : 0;
    } while (error == EINTR);
    /* if (!error) { */
    /*     COVERAGE_INC(netlink_sent); */
    /* } */
    return error;
}

/* Tries to send 'msg', which must contain a Netlink message, to the kernel on
 * 'sock'.  nlmsg_len in 'msg' will be finalized to match msg->size, nlmsg_pid
 * will be set to 'sock''s pid, and nlmsg_seq will be initialized to a fresh
 * sequence number, before the message is sent.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If
 * 'wait' is true, then the send will wait until buffer space is ready;
 * otherwise, returns EAGAIN if the 'sock' send buffer is full. */
int
nl_sock_send(struct nl_sock *sock, const struct ofpbuf *msg, bool wait)
{
    return nl_sock_send_seq(sock, msg, nl_sock_allocate_seq(sock, 1), wait);
}

/* Tries to send 'msg', which must contain a Netlink message, to the kernel on
 * 'sock'.  nlmsg_len in 'msg' will be finalized to match msg->size, nlmsg_pid
 * will be set to 'sock''s pid, and nlmsg_seq will be initialized to
 * 'nlmsg_seq', before the message is sent.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If
 * 'wait' is true, then the send will wait until buffer space is ready;
 * otherwise, returns EAGAIN if the 'sock' send buffer is full.
 *
 * This function is suitable for sending a reply to a request that was received
 * with sequence number 'nlmsg_seq'.  Otherwise, use nl_sock_send() instead. */
int
nl_sock_send_seq(struct nl_sock *sock, const struct ofpbuf *msg,
                 uint32_t nlmsg_seq, bool wait)
{
    return nl_sock_send__(sock, msg, nlmsg_seq, wait);
}

static int
nl_sock_recv__(struct nl_sock *sock, struct ofpbuf *buf, bool wait)
{
    /* We can't accurately predict the size of the data to be received.  The
     * caller is supposed to have allocated enough space in 'buf' to handle the
     * "typical" case.  To handle exceptions, we make available enough space in
     * 'tail' to allow Netlink messages to be up to 64 kB long (a reasonable
     * figure since that's the maximum length of a Netlink attribute). */
    struct nlmsghdr *nlmsghdr;
    uint8_t tail[65536];
    struct iovec iov[2];
    struct msghdr msg;
    ssize_t retval;
    int error;

    /* ovs_assert(buf->allocated >= sizeof *nlmsghdr); */
    ofpbuf_clear(buf);

    iov[0].iov_base = buf->base;
    iov[0].iov_len = buf->allocated;
    iov[1].iov_base = tail;
    iov[1].iov_len = sizeof tail;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    /* Receive a Netlink message from the kernel.
     *
     * This works around a kernel bug in which the kernel returns an error code
     * as if it were the number of bytes read.  It doesn't actually modify
     * anything in the receive buffer in that case, so we can initialize the
     * Netlink header with an impossible message length and then, upon success,
     * check whether it changed. */
    nlmsghdr = buf->base;
    do {
        nlmsghdr->nlmsg_len = UINT32_MAX;

        retval = recvmsg(sock->fd, &msg, wait ? 0 : MSG_DONTWAIT);

        error = (retval < 0 ? errno
                 : retval == 0 ? ECONNRESET /* not possible? */
                 : nlmsghdr->nlmsg_len != UINT32_MAX ? 0
                 : retval);
    } while (error == EINTR);
    if (error) {
        if (error == ENOBUFS) {
            /* Socket receive buffer overflow dropped one or more messages that
             * the kernel tried to send to us. */
            /* COVERAGE_INC(netlink_overflow); */
	  ;
        }
        return error;
    }

    if (msg.msg_flags & MSG_TRUNC) {
        return E2BIG;
    }

    if (retval < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len > retval) {
        return EPROTO;
    }

    buf->size = MIN(retval, buf->allocated);
    if (retval > buf->allocated) {
        /* COVERAGE_INC(netlink_recv_jumbo); */
        ofpbuf_put(buf, tail, retval - buf->allocated);
    }

    /* COVERAGE_INC(netlink_received); */

    return 0;
}

/* Tries to receive a Netlink message from the kernel on 'sock' into 'buf'.  If
 * 'wait' is true, waits for a message to be ready.  Otherwise, fails with
 * EAGAIN if the 'sock' receive buffer is empty.
 *
 * The caller must have initialized 'buf' with an allocation of at least
 * NLMSG_HDRLEN bytes.  For best performance, the caller should allocate enough
 * space for a "typical" message.
 *
 * On success, returns 0 and replaces 'buf''s previous content by the received
 * message.  This function expands 'buf''s allocated memory, as necessary, to
 * hold the actual size of the received message.
 *
 * On failure, returns a positive errno value and clears 'buf' to zero length.
 * 'buf' retains its previous memory allocation.
 *
 * Regardless of success or failure, this function resets 'buf''s headroom to
 * 0. */
int
nl_sock_recv(struct nl_sock *sock, struct ofpbuf *buf, bool wait)
{
    return nl_sock_recv__(sock, buf, wait);
}

static void
nl_sock_record_errors__(struct nl_transaction **transactions, size_t n,
                        int error)
{
    size_t i;

    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];

        txn->error = error;
        if (txn->reply) {
            ofpbuf_clear(txn->reply);
        }
    }
}

static int
nl_sock_transact_multiple__(struct nl_sock *sock,
                            struct nl_transaction **transactions, size_t n,
                            size_t *done)
{
    uint64_t tmp_reply_stub[1024 / 8];
    struct nl_transaction tmp_txn;
    struct ofpbuf tmp_reply;

    uint32_t base_seq;
    struct iovec iovs[MAX_IOVS];
    struct msghdr msg;
    int error;
    int i;

    /* fprintf(stderr, "[nl_sock_transact_multiple__], n = %d\n", n); */

    base_seq = nl_sock_allocate_seq(sock, n);
    *done = 0;
    for (i = 0; i < n; i++) {
        struct nl_transaction *txn = transactions[i];
	struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(txn->request);

        nlmsg->nlmsg_len = txn->request->size;
        nlmsg->nlmsg_seq = base_seq + i;
        nlmsg->nlmsg_pid = sock->pid;

        iovs[i].iov_base = txn->request->data;
        iovs[i].iov_len = txn->request->size;
    }

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iovs;
    msg.msg_iovlen = n;
    do {
        error = sendmsg(sock->fd, &msg, 0) < 0 ? errno : 0;
    } while (error == EINTR);

    /* for (i = 0; i < n; i++) { */
    /*     struct nl_transaction *txn = transactions[i]; */

    /* } */
    /* if (!error) { */
    /*     COVERAGE_ADD(netlink_sent, n); */
    /* } */

    if (error) {
        return error;
    }

    ofpbuf_use_stub(&tmp_reply, tmp_reply_stub, sizeof tmp_reply_stub);
    tmp_txn.request = NULL;
    tmp_txn.reply = &tmp_reply;
    tmp_txn.error = 0;

    while (n > 0) {
        struct nl_transaction *buf_txn, *txn;
        uint32_t seq;

        /* Find a transaction whose buffer we can use for receiving a reply.
         * If no such transaction is left, use tmp_txn. */
        buf_txn = &tmp_txn;
        for (i = 0; i < n; i++) {
            if (transactions[i]->reply) {
                buf_txn = transactions[i];
                break;
            }
        }

        /* Receive a reply. */
        error = nl_sock_recv__(sock, buf_txn->reply, false);
        if (error) {
            if (error == EAGAIN) {
                /* nl_sock_record_errors__(transactions, n, 0); */
                *done += n;
                error = 0;
            }
            break;
        }

        /* /\* Match the reply up with a transaction. *\/ */
        /* seq = nl_msg_nlmsghdr(buf_txn->reply)->nlmsg_seq; */
        /* if (seq < base_seq || seq >= base_seq + n) { */
        /*     continue; */
        /* } */
        /* i = seq - base_seq; */
        /* txn = transactions[i]; */

        /* /\* Fill in the results for 'txn'. *\/ */
        /* if (nl_msg_nlmsgerr(buf_txn->reply, &txn->error)) { */
        /*     if (txn->reply) { */
        /*         ofpbuf_clear(txn->reply); */
        /*     } */
        /*     if (txn->error) { */
	/*       ; */
        /*     } */
        /* } else { */
        /*     txn->error = 0; */
        /*     if (txn->reply && txn != buf_txn) { */
        /*         /\* Swap buffers. *\/ */
        /*         struct ofpbuf *reply = buf_txn->reply; */
        /*         buf_txn->reply = txn->reply; */
        /*         txn->reply = reply; */
        /*     } */
        /* } */

        /* Fill in the results for transactions before 'txn'.  (We have to do
         * this after the results for 'txn' itself because of the buffer swap
         * above.) */
        /* nl_sock_record_errors__(transactions, i, 0); */

        /* Advance. */
        *done += i + 1;
        transactions += i + 1;
        n -= i + 1;
        base_seq += i + 1;
    }
    ofpbuf_uninit(&tmp_reply);

    return error;
}

static void
nl_sock_transact_multiple(struct nl_sock *sock,
                          struct nl_transaction **transactions, size_t n)
{
    int max_batch_count;
    int error;

    if (!n) {
        return;
    }

    /* In theory, every request could have a 64 kB reply.  But the default and
     * maximum socket rcvbuf size with typical Dom0 memory sizes both tend to
     * be a bit below 128 kB, so that would only allow a single message in a
     * "batch".  So we assume that replies average (at most) 4 kB, which allows
     * a good deal of batching.
     *
     * In practice, most of the requests that we batch either have no reply at
     * all or a brief reply. */
    max_batch_count = MAX(sock->rcvbuf / 4096, 1);
    max_batch_count = MIN(max_batch_count, MAX_IOVS);
    /* max_batch_count = MIN(max_batch_count, max_iovs); */

    /* fprintf(stderr, "[nl_sock_transact_multiple] check0\n"); */

    while (n > 0) {
        size_t count, bytes;
        size_t done;

        /* Batch up to 'max_batch_count' transactions.  But cap it at about a
         * page of requests total because big skbuffs are expensive to
         * allocate in the kernel.  */
#if defined(PAGESIZE)
        enum { MAX_BATCH_BYTES = MAX(1, PAGESIZE - 512) };
#else
        enum { MAX_BATCH_BYTES = 4096 - 512 };
#endif
        bytes = transactions[0]->request->size;
        for (count = 1; count < n && count < max_batch_count; count++) {
            if (bytes + transactions[count]->request->size > MAX_BATCH_BYTES) {
                break;
            }
            bytes += transactions[count]->request->size;
        }

        error = nl_sock_transact_multiple__(sock, transactions, count, &done);
        transactions += done;
        n -= done;

        if (error == ENOBUFS) {
	  ;
        } else if (error) {
            /* nl_sock_record_errors__(transactions, n, error); */
            /* if (error != EAGAIN) { */
            /*     /\* A fatal error has occurred.  Abort the rest of */
            /*      * transactions. *\/ */
            /*     break; */
            /* } */
	  ;
        }
    }
}

static int
nl_sock_transact(struct nl_sock *sock, const struct ofpbuf *request,
                 struct ofpbuf **replyp)
{
    struct nl_transaction *transactionp;
    struct nl_transaction transaction;

    /* fprintf(stderr, "[nl_sock_transact] check0\n"); */

    transaction.request = CONST_CAST(struct ofpbuf *, request);
    transaction.reply = replyp ? ofpbuf_new(1024) : NULL;
    transactionp = &transaction;

    nl_sock_transact_multiple(sock, &transactionp, 1);

    if (replyp) {
        if (transaction.error) {
            ofpbuf_delete(transaction.reply);
            *replyp = NULL;
        } else {
            *replyp = transaction.reply;
        }
    }

    return transaction.error;
}

/* Drain all the messages currently in 'sock''s receive queue. */
int
nl_sock_drain(struct nl_sock *sock)
{
  int rcvbuf;
  int fd = sock->fd;

  int error;

  rcvbuf = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, NULL);
  /* error = getsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF", &rcvbuf); */
  /* rcvbuf = error ? -error : rcvbuf; */

  /* rcvbuf = get_socket_rcvbuf(fd); */

  if (rcvbuf < 0) {
    return -rcvbuf;
  }

  while (rcvbuf > 0) {
    /* In Linux, specifying MSG_TRUNC in the flags argument causes the
     * datagram length to be returned, even if that is longer than the
     * buffer provided.  Thus, we can use a 1-byte buffer to discard the
     * incoming datagram and still be able to account how many bytes were
     * removed from the receive buffer.
     *
     * On other Unix-like OSes, MSG_TRUNC has no effect in the flags
     * argument. */
    /* char buffer[LINUX ? 1 : 2048]; */
    char buffer[1];
    ssize_t n_bytes = recv(fd, buffer, sizeof buffer,
			   MSG_TRUNC | MSG_DONTWAIT);
    if (n_bytes <= 0 || n_bytes >= rcvbuf) {
      break;
    }
    rcvbuf -= n_bytes;
  }
  return 0;
}

/* Starts a Netlink "dump" operation, by sending 'request' to the kernel on a
 * Netlink socket created with the given 'protocol', and initializes 'dump' to
 * reflect the state of the operation.
 *
 * 'request' must contain a Netlink message.  Before sending the message,
 * nlmsg_len will be finalized to match request->size, and nlmsg_pid will be
 * set to the Netlink socket's pid.  NLM_F_DUMP and NLM_F_ACK will be set in
 * nlmsg_flags.
 *
 * The design of this Netlink socket library ensures that the dump is reliable.
 *
 * This function provides no status indication.  nl_dump_done() provides an
 * error status for the entire dump operation.
 *
 * The caller must eventually destroy 'request'.
 */
void
nl_dump_start(struct nl_dump *dump, int protocol, const struct ofpbuf *request)
{
    nl_msg_nlmsghdr(request)->nlmsg_flags |= NLM_F_DUMP | NLM_F_ACK;

    /* ovs_mutex_init(&dump->mutex); */
    /* ovs_mutex_lock(&dump->mutex); */
    dump->status = nl_pool_alloc(protocol, &dump->sock);
    if (!dump->status) {
        dump->status = nl_sock_send__(dump->sock, request,
                                      nl_sock_allocate_seq(dump->sock, 1),
                                      true);
    }
    dump->nl_seq = nl_msg_nlmsghdr(request)->nlmsg_seq;
    /* ovs_mutex_unlock(&dump->mutex); */
}

static int
nl_dump_refill(struct nl_dump *dump, struct ofpbuf *buffer)
    OVS_REQUIRES(dump->mutex)
{
    struct nlmsghdr *nlmsghdr;
    int error;

    while (!buffer->size) {
        error = nl_sock_recv__(dump->sock, buffer, false);
        if (error) {
            /* The kernel never blocks providing the results of a dump, so
             * error == EAGAIN means that we've read the whole thing, and
             * therefore transform it into EOF.  (The kernel always provides
             * NLMSG_DONE as a sentinel.  Some other thread must have received
             * that already but not yet signaled it in 'status'.)
             *
             * Any other error is just an error. */
            return error == EAGAIN ? EOF : error;
        }

        nlmsghdr = nl_msg_nlmsghdr(buffer);
        if (dump->nl_seq != nlmsghdr->nlmsg_seq) {
            ofpbuf_clear(buffer);
        }
    }

    if (nl_msg_nlmsgerr(buffer, &error) && error) {
        ofpbuf_clear(buffer);
        return error;
    }

    return 0;
}

static int
nl_dump_next__(struct ofpbuf *reply, struct ofpbuf *buffer)
{
    struct nlmsghdr *nlmsghdr = nl_msg_next(buffer, reply);
    if (!nlmsghdr) {
        return EPROTO;
    } else if (nlmsghdr->nlmsg_type == NLMSG_DONE) {
        return EOF;
    } else {
        return 0;
    }
}

/* Attempts to retrieve another reply from 'dump' into 'buffer'. 'dump' must
 * have been initialized with nl_dump_start(), and 'buffer' must have been
 * initialized. 'buffer' should be at least NL_DUMP_BUFSIZE bytes long.
 *
 * If successful, returns true and points 'reply->data' and
 * 'reply->size' to the message that was retrieved. The caller must not
 * modify 'reply' (because it points within 'buffer', which will be used by
 * future calls to this function).
 *
 * On failure, returns false and sets 'reply->data' to NULL and
 * 'reply->size' to 0.  Failure might indicate an actual error or merely
 * the end of replies.  An error status for the entire dump operation is
 * provided when it is completed by calling nl_dump_done().
 *
 * Multiple threads may call this function, passing the same nl_dump, however
 * each must provide independent buffers. This function may cache multiple
 * replies in the buffer, and these will be processed before more replies are
 * fetched. When this function returns false, other threads may continue to
 * process replies in their buffers, but they will not fetch more replies.
 */
bool
nl_dump_next(struct nl_dump *dump, struct ofpbuf *reply, struct ofpbuf *buffer)
{
    int retval = 0;

    /* If the buffer is empty, refill it.
     *
     * If the buffer is not empty, we don't check the dump's status.
     * Otherwise, we could end up skipping some of the dump results if thread A
     * hits EOF while thread B is in the midst of processing a batch. */
    if (!buffer->size) {
        /* ovs_mutex_lock(&dump->mutex); */
        if (!dump->status) {
            /* Take the mutex here to avoid an in-kernel race.  If two threads
             * try to read from a Netlink dump socket at once, then the socket
             * error can be set to EINVAL, which will be encountered on the
             * next recv on that socket, which could be anywhere due to the way
             * that we pool Netlink sockets.  Serializing the recv calls avoids
             * the issue. */
            dump->status = nl_dump_refill(dump, buffer);
        }
        retval = dump->status;
        /* ovs_mutex_unlock(&dump->mutex); */
    }

    /* Fetch the next message from the buffer. */
    if (!retval) {
        retval = nl_dump_next__(reply, buffer);
        if (retval) {
            /* Record 'retval' as the dump status, but don't overwrite an error
             * with EOF.  */
            /* ovs_mutex_lock(&dump->mutex); */
            if (dump->status <= 0) {
                dump->status = retval;
            }
            /* ovs_mutex_unlock(&dump->mutex); */
        }
    }

    if (retval) {
        reply->data = NULL;
        reply->size = 0;
    }
    return !retval;
}

/* Completes Netlink dump operation 'dump', which must have been initialized
 * with nl_dump_start().  Returns 0 if the dump operation was error-free,
 * otherwise a positive errno value describing the problem. */
int
nl_dump_done(struct nl_dump *dump)
{
    int status;

    /* ovs_mutex_lock(&dump->mutex); */
    status = dump->status;
    /* ovs_mutex_unlock(&dump->mutex); */

    /* Drain any remaining messages that the client didn't read.  Otherwise the
     * kernel will continue to queue them up and waste buffer space.
     *
     * XXX We could just destroy and discard the socket in this case. */
    if (!status) {
        uint64_t tmp_reply_stub[NL_DUMP_BUFSIZE / 8];
        struct ofpbuf reply, buf;

        ofpbuf_use_stub(&buf, tmp_reply_stub, sizeof tmp_reply_stub);
        while (nl_dump_next(dump, &reply, &buf)) {
            /* Nothing to do. */
        }
        ofpbuf_uninit(&buf);

        /* ovs_mutex_lock(&dump->mutex); */
        status = dump->status;
        /* ovs_mutex_unlock(&dump->mutex); */
        /* ovs_assert(status); */
    }

    nl_pool_release(dump->sock);
    /* ovs_mutex_destroy(&dump->mutex); */

    return status == EOF ? 0 : status;
}


/* Causes poll_block() to wake up when any of the specified 'events' (which is
 * a OR'd combination of POLLIN, POLLOUT, etc.) occur on 'sock'.
 * On Windows, 'sock' is not treated as const, and may be modified. */
/* void */
/* nl_sock_wait(const struct nl_sock *sock, short int events) */
/* { */
/*     poll_fd_wait(sock->fd, events); */
/* } */

/* Returns the underlying fd for 'sock', for use in "poll()"-like operations
 * that can't use nl_sock_wait().
 *
 * It's a little tricky to use the returned fd correctly, because nl_sock does
 * "copy on write" to allow a single nl_sock to be used for notifications,
 * transactions, and dumps.  If 'sock' is used only for notifications and
 * transactions (and never for dump) then the usage is safe. */
int
nl_sock_fd(const struct nl_sock *sock)
{
    return sock->fd;
}

/* Returns the PID associated with this socket. */
uint32_t
nl_sock_pid(const struct nl_sock *sock)
{
    return sock->pid;
}

/* Miscellaneous.  */

struct genl_family {
    struct hmap_node hmap_node;
    uint16_t id;
    char *name;
};

static struct hmap genl_families = HMAP_INITIALIZER(&genl_families);

static const struct nl_policy family_policy[CTRL_ATTR_MAX + 1] = {
    [CTRL_ATTR_FAMILY_ID] = {.type = NL_A_U16},
    [CTRL_ATTR_MCAST_GROUPS] = {.type = NL_A_NESTED, .optional = true},
};

static struct genl_family *
find_genl_family_by_id(uint16_t id)
{
    struct genl_family *family;

    HMAP_FOR_EACH_IN_BUCKET (family, hmap_node, hash_int(id, 0),
                             &genl_families) {
        if (family->id == id) {
            return family;
        }
    }
    return NULL;
}


static const char *
genl_family_to_name(uint16_t id)
{
    if (id == GENL_ID_CTRL) {
        return "control";
    } else {
        struct genl_family *family = find_genl_family_by_id(id);
        return family ? family->name : "unknown";
    }
}

static int
do_lookup_genl_family(const char *name, struct nlattr **attrs,
                      struct ofpbuf **replyp)
{
    struct nl_sock *sock;
    struct ofpbuf request, *reply;
    int error;

    *replyp = NULL;
    error = nl_sock_create(NETLINK_GENERIC, &sock);
    if (error) {
        return error;
    }

    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 0, GENL_ID_CTRL, NLM_F_REQUEST,
                          CTRL_CMD_GETFAMILY, 1);
    nl_msg_put_string(&request, CTRL_ATTR_FAMILY_NAME, name);
    error = nl_sock_transact(sock, &request, &reply);
    ofpbuf_uninit(&request);
    if (error) {
        nl_sock_destroy(sock);
        return error;
    }

    if (!nl_policy_parse(reply, NLMSG_HDRLEN + GENL_HDRLEN,
                         family_policy, attrs, ARRAY_SIZE(family_policy))
        || nl_attr_get_u16(attrs[CTRL_ATTR_FAMILY_ID]) == 0) {
        nl_sock_destroy(sock);
        ofpbuf_delete(reply);
        return EPROTO;
    }

    nl_sock_destroy(sock);
    *replyp = reply;
    return 0;
}

/* Finds the multicast group called 'group_name' in genl family 'family_name'.
 * When successful, writes its result to 'multicast_group' and returns 0.
 * Otherwise, clears 'multicast_group' and returns a positive error code.
 */
int
nl_lookup_genl_mcgroup(const char *family_name, const char *group_name,
                       unsigned int *multicast_group)
{
    struct nlattr *family_attrs[ARRAY_SIZE(family_policy)];
    const struct nlattr *mc;
    struct ofpbuf *reply;
    unsigned int left;
    int error;

    *multicast_group = 0;
    error = do_lookup_genl_family(family_name, family_attrs, &reply);
    if (error) {
        return error;
    }

    if (!family_attrs[CTRL_ATTR_MCAST_GROUPS]) {
        error = EPROTO;
        goto exit;
    }

    NL_NESTED_FOR_EACH (mc, left, family_attrs[CTRL_ATTR_MCAST_GROUPS]) {
        static const struct nl_policy mc_policy[] = {
            [CTRL_ATTR_MCAST_GRP_ID] = {.type = NL_A_U32},
            [CTRL_ATTR_MCAST_GRP_NAME] = {.type = NL_A_STRING},
        };

        struct nlattr *mc_attrs[ARRAY_SIZE(mc_policy)];
        const char *mc_name;

        if (!nl_parse_nested(mc, mc_policy, mc_attrs, ARRAY_SIZE(mc_policy))) {
            error = EPROTO;
            goto exit;
        }

        mc_name = nl_attr_get_string(mc_attrs[CTRL_ATTR_MCAST_GRP_NAME]);
        if (!strcmp(group_name, mc_name)) {
            *multicast_group =
                nl_attr_get_u32(mc_attrs[CTRL_ATTR_MCAST_GRP_ID]);
            error = 0;
            goto exit;
        }
    }
    error = EPROTO;

exit:
    ofpbuf_delete(reply);
    return error;
}

struct nl_pool {
    struct nl_sock *socks[2048];
    /* struct nl_sock *socks[16]; */
    int n;
};

/* pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER; */
static struct ovs_mutex pool_mutex = OVS_MUTEX_INITIALIZER;
/* static struct nl_pool pools[1024]; */
/* static struct nl_pool pools[MAX_LINKS]; */
static struct nl_pool pools[MAX_LINKS] OVS_GUARDED_BY(pool_mutex);

static int
nl_pool_alloc(int protocol, struct nl_sock **sockp)
{
    struct nl_sock *sock = NULL;
    struct nl_pool *pool;

    /* ovs_assert(protocol >= 0 && protocol < ARRAY_SIZE(pools)); */

    /* fprintf(stdout, "[nl_pool_alloc] check0\n"); */

    /* pthread_mutex_lock(&pool_mutex); */
    /* ovs_mutex_lock(&pool_mutex); */
    pool = &pools[protocol];

    if (pool->n > 0) {
        sock = pool->socks[--pool->n];
    }
    /* pthread_mutex_unlock(&pool_mutex); */
    /* ovs_mutex_unlock(&pool_mutex); */

    if (sock) {
        /* fprintf(stderr, "[nl_pool_alloc] sock = %d (return 0)\n", sock); */
        *sockp = sock;
        return 0;
    } else {
        /* fprintf(stderr, "[nl_pool_alloc] protocol = %d\n", protocol); */
        return nl_sock_create(protocol, sockp);
    }
}

static void
nl_pool_release(struct nl_sock *sock)
{
    if (sock) {
        struct nl_pool *pool = &pools[sock->protocol];

        /* ovs_mutex_lock(&pool_mutex); */
        if (pool->n < ARRAY_SIZE(pool->socks)) {
            pool->socks[pool->n++] = sock;
            sock = NULL;
        }
        /* ovs_mutex_unlock(&pool_mutex); */

        nl_sock_destroy(sock);
    }
}

/* Sends 'request' to the kernel on a Netlink socket for the given 'protocol'
 * (e.g. NETLINK_ROUTE or NETLINK_GENERIC) and waits for a response.  If
 * successful, returns 0.  On failure, returns a positive errno value.
 *
 * If 'replyp' is nonnull, then on success '*replyp' is set to the kernel's
 * reply, which the caller is responsible for freeing with ofpbuf_delete(), and
 * on failure '*replyp' is set to NULL.  If 'replyp' is null, then the kernel's
 * reply, if any, is discarded.
 *
 * Before the message is sent, nlmsg_len in 'request' will be finalized to
 * match msg->size, nlmsg_pid will be set to the pid of the socket used
 * for sending the request, and nlmsg_seq will be initialized.
 *
 * The caller is responsible for destroying 'request'.
 *
 * Bare Netlink is an unreliable transport protocol.  This function layers
 * reliable delivery and reply semantics on top of bare Netlink.
 *
 * In Netlink, sending a request to the kernel is reliable enough, because the
 * kernel will tell us if the message cannot be queued (and we will in that
 * case put it on the transmit queue and wait until it can be delivered).
 *
 * Receiving the reply is the real problem: if the socket buffer is full when
 * the kernel tries to send the reply, the reply will be dropped.  However, the
 * kernel sets a flag that a reply has been dropped.  The next call to recv
 * then returns ENOBUFS.  We can then re-send the request.
 *
 * Caveats:
 *
 *      1. Netlink depends on sequence numbers to match up requests and
 *         replies.  The sender of a request supplies a sequence number, and
 *         the reply echos back that sequence number.
 *
 *         This is fine, but (1) some kernel netlink implementations are
 *         broken, in that they fail to echo sequence numbers and (2) this
 *         function will drop packets with non-matching sequence numbers, so
 *         that only a single request can be usefully transacted at a time.
 *
 *      2. Resending the request causes it to be re-executed, so the request
 *         needs to be idempotent.
 */
int
nl_transact(int protocol, const struct ofpbuf *request,
            struct ofpbuf **replyp)
{
    struct nl_sock *sock;
    int error;

    /* fprintf(stderr, "a\n"); */
    /* fprintf(stderr, "[nl_transact] check0\n"); */
    /* fflush(stdout); */
    /* sleep(1); */

    error = nl_pool_alloc(protocol, &sock);
    if (error) {
      fprintf(stderr, "[nl_transact] error!\n");
        if (replyp) {
            *replyp = NULL;
        }
        return error;
    }

    error = nl_sock_transact(sock, request, replyp);

    nl_pool_release(sock);

    return error;
}

/* Sends the 'request' member of the 'n' transactions in 'transactions' on a
 * Netlink socket for the given 'protocol' (e.g. NETLINK_ROUTE or
 * NETLINK_GENERIC), in order, and receives responses to all of them.  Fills in
 * the 'error' member of each transaction with 0 if it was successful,
 * otherwise with a positive errno value.  If 'reply' is nonnull, then it will
 * be filled with the reply if the message receives a detailed reply.  In other
 * cases, i.e. where the request failed or had no reply beyond an indication of
 * success, 'reply' will be cleared if it is nonnull.
 *
 * The caller is responsible for destroying each request and reply, and the
 * transactions array itself.
 *
 * Before sending each message, this function will finalize nlmsg_len in each
 * 'request' to match the ofpbuf's size, set nlmsg_pid to the pid of the socket
 * used for the transaction, and initialize nlmsg_seq.
 *
 * Bare Netlink is an unreliable transport protocol.  This function layers
 * reliable delivery and reply semantics on top of bare Netlink.  See
 * nl_transact() for some caveats.
 */
void
nl_transact_multiple(int protocol,
                     struct nl_transaction **transactions, size_t n)
{
    struct nl_sock *sock;
    int error;

    error = nl_pool_alloc(protocol, &sock);
    if (!error) {
        nl_sock_transact_multiple(sock, transactions, n);
        nl_pool_release(sock);
    } else {
        nl_sock_record_errors__(transactions, n, error);
    }
}

static uint32_t
nl_sock_allocate_seq(struct nl_sock *sock, unsigned int n)
{
    uint32_t seq = sock->next_seq;

    sock->next_seq += n;

    /* Make it impossible for the next request for sequence numbers to wrap
     * around to 0.  Start over with 1 to avoid ever using a sequence number of
     * 0, because the kernel uses sequence number 0 for notifications. */
    if (sock->next_seq >= UINT32_MAX / 2) {
        sock->next_seq = 1;
    }

    return seq;
}
