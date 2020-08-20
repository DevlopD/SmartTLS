#include <sys/queue.h>
#include "ssloff.h"

#define NUM_BINS 1024

typedef struct hash_bucket_head {
    struct tcp_session *tqh_first;
    struct tcp_session **tqh_last;
} hash_bucket_head;

struct hashtable {
  uint32_t bins;

  hash_bucket_head *ht_table;
};

struct hashtable *create_ht(int bins);

void destroy_ht(struct hashtable *ht);

int ht_insert(struct hashtable *ht, struct tcp_session *);
void *ht_remove(struct hashtable *ht, struct tcp_session *);
void *ht_search(struct hashtable *ht, uint32_t client_ip, uint16_t client_port,
		uint32_t server_ip, uint16_t server_port);
