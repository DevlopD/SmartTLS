#include "tc.h"

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/if_ether.h>

#define INTERFACE_TO_NETWORK  "p0"
/* #define INTERFACE_TO_HOST     "pf0hpf" */
#define INTERFACE_TO_HOST     "p0"

#define ENABLE_BATCH 0

uint32_t ifindex;
uint32_t ifindex_out;
uint16_t prio;
uint32_t handle;
struct tc_flower *flower, *flower_reverse;

/*----------------------------------------------------------------------------------------*/
void usage()
{
    fprintf(stderr, "usage: ./tc_test [mode]\n");
    fprintf(stderr, "[mode]\n"
	    "0: test add/delete seperately.\n"
	    "1: test add and delete together.\n"
	    "2 interval: add tc rules with tcp client ports in alternating order, to both side (network <-> host). default interval is 1.\n");
}
/*----------------------------------------------------------------------------------------*/
/* add 10000 rules and delete them. measure each elapsed time and calculate performance */
void TestAddDeleteSeparate()
{
    struct timeval tv_start, tv_end;
    int i, port_start = 101, port_end = 1100;
    int add_cnt = 0, del_cnt = 0;
    size_t elapsed_us;
    struct tc_flower *flowers;
#if ENABLE_BATCH
    int n = 10, cnt = 0;		/* used for batching */
    uint16_t *prios = (uint16_t*)calloc(n, sizeof(uint16_t));
    flowers = (struct tc_flower*)calloc(n, sizeof(struct tc_flower));
#endif /* ENABLE_BATCH */


    /* call tc_replace_flower */
    printf("Adding tc rules...\n");
    gettimeofday(&tv_start, NULL);
    for(i = port_start; i <= port_end; i++) {

		flower->prio = i;
		flower->key.tcp_src = htons(i);

#if ENABLE_BATCH
		prios[cnt] = i;
		flowers[cnt] = *flower;
		cnt++;
		if(cnt == n) {
			tc_replace_flowers(ifindex, prios, handle, flowers, n);
			cnt = 0;
		}
#else /* ENABLE_BATCH */
		int ret;
		ret = tc_replace_flower(ifindex, i, handle, flower);

		/* debug */
		fprintf(stderr, "tc_replace_flower return %d, total %d\n", ret, i);
#endif /* !ENABLE_BATCH */
    }

#if ENABLE_BATCH
    if(cnt != 0) {
		tc_replace_flowers(ifindex, prios, handle, flowers, cnt);
		cnt = 0;
    }
#endif /* ENABLE_BATCH */

    gettimeofday(&tv_end, NULL);
    elapsed_us = (tv_end.tv_sec - tv_start.tv_sec)*1000000 + (tv_end.tv_usec - tv_start.tv_usec);
    printf("Elapsed total time: %lu usec, add rate: %.3f operations/sec\n",
	   elapsed_us, (float)1000000*(port_end - port_start + 1)/elapsed_us);

    /* call tc_del_flower */
    printf("Deleting tc rules...\n");
    gettimeofday(&tv_start, NULL);
    for(i = port_start; i <= port_end; i++) {
		tc_del_filter(ifindex, i, handle);
		fprintf(stderr, "tc_del_filter, total %d\n", i);
    }
    gettimeofday(&tv_end, NULL);
    elapsed_us = (tv_end.tv_sec - tv_start.tv_sec)*1000000 + (tv_end.tv_usec - tv_start.tv_usec);
    printf("Elapsed total time: %lu usec, delete rate: %.3f operations/sec\n",
	   elapsed_us, (float)1000000*(port_end - port_start + 1)/elapsed_us);
}
/*----------------------------------------------------------------------------------------*/
/* maintaining 5000 rules, iteratively add/delete tc rules */
void TestAddDeleteTogether()
{
    struct timeval tv1, tv2;
    size_t elapsed_us;

    int i, j, port_start = 1000, port_end = 20000, thre_up = 5009, thre_down = 4990;
    int add_cnt = 0, del_cnt = 0, cur_tc_cnt = 0;
    enum {add_tc, del_tc};
    int status = add_tc;

    gettimeofday(&tv1, NULL);
    /* main loop: add and delete tc rule */
    /* call tc_replace_flower */
    i = port_start;
    j = port_start;
    while(true) {
	if(i > port_end)
	    i = port_start;
	if(j > port_end)
	    j = port_start;

	/* print status */
	if(i%30 == 0) {
	    gettimeofday(&tv2, NULL);
	    elapsed_us = (tv2.tv_sec - tv1.tv_sec)*1000000 + (tv2.tv_usec - tv1.tv_usec);
	    if(elapsed_us > 1000000) {
		tv1 = tv2;
		printf("\n-----------------------------------------\n");
		printf("current tc rules: %d\n", cur_tc_cnt);
		printf("add rate:    %7.3f operations/sec\n", (float)1000000*(add_cnt)/elapsed_us);
		printf("delete rate: %7.3f operations/sec\n", (float)1000000*(del_cnt)/elapsed_us);
		add_cnt = 0;
		del_cnt = 0;
	    }
	}

	/* update tc rule */
	if(status == add_tc) {
	    flower->prio = i;
	    flower->key.tcp_src = htons(i);
	    tc_replace_flower(ifindex, i, handle, flower);
	    add_cnt++;
	    cur_tc_cnt++;
	    i++;
	} else {
	    flower->prio = j;
	    flower->key.tcp_src = htons(j);
	    tc_del_filter(ifindex, j, handle);
	    del_cnt++;
	    cur_tc_cnt--;
	    j++;
	}

	/* update status */
	if(status == add_tc && cur_tc_cnt > thre_up)
	    status = del_tc;
	else if(status == del_tc && cur_tc_cnt < thre_down)
	    status = add_tc;
    }
}
/*----------------------------------------------------------------------------------------*/
/* add tc rules of TCP port */
void AddTCPRulesInAlternatingOrder(int interval)
{
    int i, port_start = 1024, port_end = 0xffff;
    int add_cnt = 0, del_cnt = 0;
    struct tc_flower *flowers;
#if ENABLE_BATCH
    int n = 10, cnt = 0;		/* used for batching */
    uint16_t *prios = (uint16_t*)calloc(n, sizeof(uint16_t));
    flowers = (struct tc_flower*)calloc(n, sizeof(struct tc_flower));
#endif /* ENABLE_BATCH */

    if(interval <= 0) {
	usage();
	exit(0);
    }

    /* install tc rules from network to host */
    printf("Adding tc rules...\n");
    for(i = port_start; i <= port_end; i++) {
	if((i%interval) != 0)
	    continue;

	flower->prio = i;
	flower->key.tcp_src = htons(i);

#if ENABLE_BATCH
	prios[cnt] = i;
	flowers[cnt] = *flower;
	cnt++;
	if(cnt == n) {
	    tc_replace_flowers(ifindex, prios, handle, flowers, n);
	    cnt = 0;
	}
#else /* ENABLE_BATCH */
	tc_replace_flower(ifindex, i, handle, flower);
#endif /* !ENABLE_BATCH */
    }

#if ENABLE_BATCH
    if(cnt != 0) {
	tc_replace_flowers(ifindex, prios, handle, flowers, cnt);
	cnt = 0;
    }
#endif /* ENABLE_BATCH */


    /* install tc rules from host to network */
    printf("Adding tc rules...\n");
    for(i = port_start; i <= port_end; i++) {
	if((i%interval) != 0)
	    continue;

	flower_reverse->prio = i;
	flower_reverse->key.tcp_dst = htons(i);

#if ENABLE_BATCH
	prios[cnt] = i;
	flowers[cnt] = *flower_reverse;
	cnt++;
	if(cnt == n) {
	    tc_replace_flowers(ifindex_out, prios, handle, flowers, n);
	    cnt = 0;
	}
#else /* ENABLE_BATCH */
	tc_replace_flower(ifindex_out, i, handle, flower_reverse);
#endif /* !ENABLE_BATCH */
    }

#if ENABLE_BATCH
    if(cnt != 0) {
	tc_replace_flowers(ifindex_out, prios, handle, flowers, cnt);
	cnt = 0;
    }
#endif /* ENABLE_BATCH */
}
/*----------------------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    /* initialize */
    ifindex = if_nametoindex(INTERFACE_TO_NETWORK);
    ifindex_out = if_nametoindex(INTERFACE_TO_HOST);
    prio = 1234;
    handle = 0x1;

    /* initialize flower filter */
    flower = (struct tc_flower*)calloc(1, sizeof(struct tc_flower));
    flower->handle = handle;
    flower->prio = prio;
    flower->key.eth_type = htons(ETH_P_IP);
    flower->key.ip_proto = IPPROTO_TCP;
    flower->mask.ip_proto = 0xff;
    flower->key.ipv4.ipv4_dst = htonl(0xa002d0d);
    flower->mask.ipv4.ipv4_dst = 0xffffffff;
    flower->key.tcp_dst = htons(prio); /* use same number with priority */
    flower->mask.tcp_dst = 0xffff;
    flower->ifindex_out = ifindex_out;

    flower_reverse = (struct tc_flower*)calloc(1, sizeof(struct tc_flower));
    flower_reverse->handle = handle;
    flower_reverse->prio = prio;
    flower_reverse->key.eth_type = htons(ETH_P_IP);
    flower_reverse->key.ip_proto = IPPROTO_TCP;
    flower_reverse->mask.ip_proto = 0xff;
    flower_reverse->key.ipv4.ipv4_dst = htonl(0xa002d0d);
    flower_reverse->mask.ipv4.ipv4_dst = 0xffffffff;
    flower_reverse->key.tcp_dst = htons(prio); /* use same number with priority */
    flower_reverse->mask.tcp_dst = 0xffff;
    flower_reverse->ifindex_out = ifindex;

    if(argc < 2) {
	usage();
	exit(0);
    }

    if(argv[1][0] == '0') {
	TestAddDeleteSeparate();
    } else if(argv[1][0] == '1') {
	TestAddDeleteTogether();
    } else if(argv[1][0] == '2') {
	if(argc >= 3)
	    AddTCPRulesInAlternatingOrder(atoi(argv[2]));
	else
	    AddTCPRulesInAlternatingOrder(1);
    } else {
	usage();
	exit(0);
    }

    return 0;
}


