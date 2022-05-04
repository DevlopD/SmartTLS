#ifndef __OPTION_H__
#define __OPTION_H__

#include "string.h"

#define VERBOSE_INIT        FALSE
#define VERBOSE_TCP         FALSE
#define VERBOSE_SSL         FALSE
#define VERBOSE_STATE       FALSE
#define VERBOSE_CHUNK       FALSE
#define VERBOSE_KEY         FALSE
#define VERBOSE_AES         FALSE
#define VERBOSE_GCM         FALSE
#define VERBOSE_MAC         FALSE
#define VERBOSE_DATA        FALSE
#define VERBOSE_STAT        TRUE

#define DEBUG_PRINT(fmt, args...) fprintf(stderr, ""fmt"", ##args)

#define UNUSED(x)           (void)(x)

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif


#ifdef likely
#undef likely
#endif /* likely */

#ifdef unlikely
#undef unlikely
#endif /* unlikely */

#ifdef dmb
#undef dmb
#endif /* dmb */

/* optimizations */
#define ONLOAD                           0
#define ZERO_COPY_RECV                   1
#define OFFLOAD_AES_GCM                  0
#define USE_HASHTABLE_FOR_ACTIVE_SESSION 1
#define USE_TC_RULE                      1

#define MODIFY_FLAG                      1
#define DEBUG_FLAG                       0
#define CRYPTO_GETTIME_FLAG FALSE

#if ONLOAD
#define NO_TLS                           0
#endif

#define ENCRYPT_META FALSE

#include <pka.h>
#include <pka_utils.h>

#include "pka_helper.h"

/* debug */
/* #define PKA_RING_CNT 4 */
#define PKA_RING_CNT 8
#define PKA_QUEUE_CNT 16
#define PKA_MAX_OBJS 32
/* note: Maximum queue size should not exceed 8MB (= PKA_QUEUE_MASK_SIZE).
   Also, (1 << 14)*PKA_MAX_OBJS does not work with RSA 4096 bit
   because of memory overflow issue in pka_queue_cmd_dequeue() */
#define CMD_QUEUE_SIZE (1 << 17) * PKA_MAX_OBJS
#define RSLT_QUEUE_SIZE (1 << 12) * PKA_MAX_OBJS
#define MAX_THREAD_NUM 16

typedef struct option
{
    char* key_file;
    char* key_passwd;
} option_t;

extern option_t option;

#endif /* __OPTION_H__ */
