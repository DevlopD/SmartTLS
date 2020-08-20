#include <stdio.h>

#include "fhash.h"

/*---------------------------------------------------------------------------*/
static inline unsigned int
calculate_hash(struct tcp_session *sess)
{
    int hash, i;
    char *key = (char *)&sess->client_ip;

    for (hash = 0, i = 0; i < 12; i++) {
	hash += key[i];
	hash += (hash << 10);
	hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash & (NUM_BINS - 1);
}
/*----------------------------------------------------------------------------*/
struct hashtable *
create_ht(int bins) // no of bins
{
    int i;
    struct hashtable* ht = calloc(1, sizeof(struct hashtable));
    if (!ht){
	fprintf(stderr, "calloc: create_ht");
	return 0;
    }

    ht->bins = bins;

    /* creating bins */
    ht->ht_table = calloc(bins, sizeof(hash_bucket_head));
    if (!ht->ht_table) {
	fprintf(stderr, "calloc: create_ht bins!\n");
	free(ht);
	return 0;
    }
    /* init the tables */
    for (i = 0; i < bins; i++)
	TAILQ_INIT(&ht->ht_table[i]);

    return ht;
}
/*----------------------------------------------------------------------------*/
void
destroy_ht(struct hashtable *ht)
{
    free(ht->ht_table);
    free(ht);
}
/*----------------------------------------------------------------------------*/
int
ht_insert(struct hashtable *ht, struct tcp_session *item)
{
    /* create an entry*/
    int idx;

    assert(ht);

    idx = calculate_hash(item);
    assert(idx >=0 && idx < NUM_BINS);

    TAILQ_INSERT_TAIL(&ht->ht_table[idx], item, active_session_link);

    return 0;
}
/*----------------------------------------------------------------------------*/
void*
ht_remove(struct hashtable *ht, struct tcp_session *item)
{
    hash_bucket_head *head;
    int idx = calculate_hash(item);

    head = &ht->ht_table[idx];
    TAILQ_REMOVE(head, item, active_session_link);

    return (item);
}
/*----------------------------------------------------------------------------*/ 
void *                    
ht_search(struct hashtable *ht, uint32_t client_ip, uint16_t client_port,
	  uint32_t server_ip, uint16_t server_port)
{
    struct tcp_session *walk;
    hash_bucket_head *head;

    struct tcp_session target;
    target.client_ip = client_ip;
    target.client_port = client_port;
    target.server_ip = server_ip;
    target.server_port = server_port;

    head = &ht->ht_table[calculate_hash(&target)];
    TAILQ_FOREACH(walk, head, active_session_link) {
	assert(walk->state != TCP_SESSION_IDLE);

	if ((walk->client_ip == client_ip) &&
	    (walk->client_port == client_port) &&
	    (walk->server_ip == server_ip) &&
	    (walk->server_port == server_port))
	    return walk;
    }

    return NULL;
}
/*----------------------------------------------------------------------------*/
