#ifndef __OPTION_H__
#define __OPTION_H__

#include "string.h"
#include "mtcp_api.h"

#define VERBOSE_TCP         FALSE
#define VERBOSE_SSL         FALSE
#define VERBOSE_STATE       FALSE
#define VERBOSE_CHUNK       FALSE
#define VERBOSE_KEY         FALSE
#define VERBOSE_AES         FALSE
#define VERBOSE_GCM         FALSE
#define VERBOSE_MAC         FALSE
#define VERBOSE_DATA        FALSE
#define VERBOSE_APP         FALSE
#define VERBOSE_STAT        FALSE

#define SEG_RECORD_BUF TRUE

#define MODIFY_FLAG TRUE
#define DEBUG_FLAG FALSE
#define CRYPTO_GETTIME_FLAG FALSE

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif


/* #ifdef likely */
/* #undef likely */
/* #endif /\* likely *\/ */

/* #ifdef unlikely */
/* #undef unlikely */
/* #endif /\* unlikely *\/ */

#ifdef dmb
#undef dmb
#endif /* dmb */

#endif /* __OPTION_H__ */
