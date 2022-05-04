/*
 * Copyright (c) 2009-2017 Nicira, Inc.
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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
#include "tc.h"

#include <errno.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/gen_stats.h>
#include <net/if.h>
#include <unistd.h>

#include "byte-order.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
/* #include "openvswitch/vlog.h" */
#include "packets.h"
#include "timeval.h"
#include "unaligned.h"

/* VLOG_DEFINE_THIS_MODULE(tc); */

/* static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5); */

enum tc_offload_policy {
    TC_POLICY_NONE,
    TC_POLICY_SKIP_SW,
    TC_POLICY_SKIP_HW
};

static enum tc_offload_policy tc_policy = TC_POLICY_NONE;

struct tcmsg *
tc_make_request(int ifindex, int type, unsigned int flags,
                struct ofpbuf *request)
{
    struct tcmsg *tcmsg;

    ofpbuf_init(request, 512);
    nl_msg_put_nlmsghdr(request, sizeof *tcmsg, type, NLM_F_REQUEST | flags);
    tcmsg = ofpbuf_put_zeros(request, sizeof *tcmsg);
    tcmsg->tcm_family = AF_UNSPEC;
    tcmsg->tcm_ifindex = ifindex;
    /* Caller should fill in tcmsg->tcm_handle. */
    /* Caller should fill in tcmsg->tcm_parent. */

    return tcmsg;
}

int
tc_transact(struct ofpbuf *request, struct ofpbuf **replyp)
{
    int error = nl_transact(NETLINK_ROUTE, request, replyp);
    ofpbuf_uninit(request);
    return error;
}

/* Adds or deletes a root ingress qdisc on device with specified ifindex.
 *
 * This function is equivalent to running the following when 'add' is true:
 *     /sbin/tc qdisc add dev <devname> handle ffff: ingress
 *
 * This function is equivalent to running the following when 'add' is false:
 *     /sbin/tc qdisc del dev <devname> handle ffff: ingress
 *
 * Where dev <devname> is the device with specified ifindex name.
 *
 * The configuration and stats may be seen with the following command:
 *     /sbin/tc -s qdisc show dev <devname>
 *
 * Returns 0 if successful, otherwise a positive errno value.
 */
int
tc_add_del_ingress_qdisc(int ifindex, bool add)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    int error;
    int type = add ? RTM_NEWQDISC : RTM_DELQDISC;
    int flags = add ? NLM_F_EXCL | NLM_F_CREATE : 0;

    tcmsg = tc_make_request(ifindex, type, flags, &request);
    tcmsg->tcm_handle = TC_H_MAKE(TC_H_INGRESS, 0);
    tcmsg->tcm_parent = 0xffff;
    /* tcmsg->tcm_parent = TC_H_INGRESS; */
    nl_msg_put_string(&request, TCA_KIND, "ingress");
    nl_msg_put_unspec(&request, TCA_OPTIONS, NULL, 0);

    error = tc_transact(&request, NULL);
    if (error) {
        /* If we're deleting the qdisc, don't worry about some of the
         * error conditions. */
        if (!add && (error == ENOENT || error == EINVAL)) {
            return 0;
        }
        return error;
    }

    return 0;
}

static const struct nl_policy tca_policy[] = {
    [TCA_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_STATS] = { .type = NL_A_UNSPEC,
                    .min_len = sizeof(struct tc_stats), .optional = true, },
    [TCA_STATS2] = { .type = NL_A_NESTED, .optional = true, },
};

static const struct nl_policy tca_flower_policy[] = {
    [TCA_FLOWER_CLASSID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_INDEV] = { .type = NL_A_STRING, .max_len = IFNAMSIZ,
                           .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST] = { .type = NL_A_UNSPEC,
                                 .min_len = ETH_ALEN, .optional = true, },
    [TCA_FLOWER_KEY_ETH_SRC_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_DST_MASK] = { .type = NL_A_UNSPEC,
                                      .min_len = ETH_ALEN,
                                      .optional = true, },
    [TCA_FLOWER_KEY_ETH_TYPE] = { .type = NL_A_U16, .optional = false, },
    [TCA_FLOWER_FLAGS] = { .type = NL_A_U32, .optional = false, },
    [TCA_FLOWER_ACT] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_FLOWER_KEY_IP_PROTO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST] = {.type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_SRC_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV4_DST_MASK] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST] = { .type = NL_A_UNSPEC,
                                  .min_len = sizeof(struct in6_addr),
                                  .optional = true, },
    [TCA_FLOWER_KEY_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                       .min_len = sizeof(struct in6_addr),
                                       .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_TCP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_UDP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_SRC_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_SCTP_DST_MASK] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_PRIO] = { .type = NL_A_U8, .optional = true, },
    [TCA_FLOWER_KEY_VLAN_ETH_TYPE] = { .type = NL_A_U16, .optional = true, },
    [TCA_FLOWER_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV4_DST_MASK] = { .type = NL_A_U32,
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_IPV6_DST_MASK] = { .type = NL_A_UNSPEC,
                                           .min_len = sizeof(struct in6_addr),
                                           .optional = true, },
    [TCA_FLOWER_KEY_ENC_UDP_DST_PORT] = { .type = NL_A_U16,
                                          .optional = true, },
};

static const struct nl_policy tunnel_key_policy[] = {
    [TCA_TUNNEL_KEY_PARMS] = { .type = NL_A_UNSPEC,
                               .min_len = sizeof(struct tc_tunnel_key),
                               .optional = false, },
    [TCA_TUNNEL_KEY_ENC_IPV4_SRC] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV4_DST] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV6_SRC] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_TUNNEL_KEY_ENC_IPV6_DST] = { .type = NL_A_UNSPEC,
                                      .min_len = sizeof(struct in6_addr),
                                      .optional = true, },
    [TCA_TUNNEL_KEY_ENC_KEY_ID] = { .type = NL_A_U32, .optional = true, },
    [TCA_TUNNEL_KEY_ENC_DST_PORT] = { .type = NL_A_U16, .optional = true, },
};

static const struct nl_policy gact_policy[] = {
    [TCA_GACT_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_gact),
                         .optional = false, },
    [TCA_GACT_TM] = { .type = NL_A_UNSPEC,
                      .min_len = sizeof(struct tcf_t),
                      .optional = false, },
};

static const struct nl_policy mirred_policy[] = {
    [TCA_MIRRED_PARMS] = { .type = NL_A_UNSPEC,
                           .min_len = sizeof(struct tc_mirred),
                           .optional = false, },
    [TCA_MIRRED_TM] = { .type = NL_A_UNSPEC,
                        .min_len = sizeof(struct tcf_t),
                        .optional = false, },
};

static const struct nl_policy vlan_policy[] = {
    [TCA_VLAN_PARMS] = { .type = NL_A_UNSPEC,
                         .min_len = sizeof(struct tc_vlan),
                         .optional = false, },
    [TCA_VLAN_PUSH_VLAN_ID] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PROTOCOL] = { .type = NL_A_U16, .optional = true, },
    [TCA_VLAN_PUSH_VLAN_PRIORITY] = { .type = NL_A_U8, .optional = true, },
};

static const struct nl_policy act_policy[] = {
    [TCA_ACT_KIND] = { .type = NL_A_STRING, .optional = false, },
    [TCA_ACT_COOKIE] = { .type = NL_A_UNSPEC, .optional = true, },
    [TCA_ACT_OPTIONS] = { .type = NL_A_NESTED, .optional = false, },
    [TCA_ACT_STATS] = { .type = NL_A_NESTED, .optional = false, },
};

static const struct nl_policy stats_policy[] = {
    [TCA_STATS_BASIC] = { .type = NL_A_UNSPEC,
                          .min_len = sizeof(struct gnet_stats_basic),
                          .optional = false, },
};

#define TCA_ACT_MIN_PRIO 1

int
tc_dump_flower_start(int ifindex, struct nl_dump *dump)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;

    tcmsg = tc_make_request(ifindex, RTM_GETTFILTER, NLM_F_DUMP, &request);
    tcmsg->tcm_parent = TC_INGRESS_PARENT;
    tcmsg->tcm_info = TC_H_UNSPEC;
    tcmsg->tcm_handle = 0;

    nl_dump_start(dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    return 0;
}

int
tc_flush(int ifindex)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;

    tcmsg = tc_make_request(ifindex, RTM_DELTFILTER, NLM_F_ACK, &request);
    tcmsg->tcm_parent = TC_INGRESS_PARENT;
    tcmsg->tcm_info = TC_H_UNSPEC;

    return tc_transact(&request, NULL);
}

int
tc_del_filter(int ifindex, int prio, int handle)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error;

    tcmsg = tc_make_request(ifindex, RTM_DELTFILTER, NLM_F_ECHO, &request);
    tcmsg->tcm_parent = TC_INGRESS_PARENT;
    tcmsg->tcm_info = tc_make_handle(prio, 0);
    tcmsg->tcm_handle = handle;

    error = tc_transact(&request, &reply);
    if (!error) {
        ofpbuf_delete(reply);
    }
    return error;
}

static int
tc_get_tc_cls_policy(enum tc_offload_policy policy)
{
    if (policy == TC_POLICY_SKIP_HW) {
        return TCA_CLS_FLAGS_SKIP_HW;
    } else if (policy == TC_POLICY_SKIP_SW) {
        return TCA_CLS_FLAGS_SKIP_SW;
    }

    return 0;
}

static void
nl_msg_put_act_drop(struct ofpbuf *request)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "gact");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_gact p = { .action = TC_ACT_SHOT };

        nl_msg_put_unspec(request, TCA_GACT_PARMS, &p, sizeof p);
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_act_redirect(struct ofpbuf *request, int ifindex)
{
    size_t offset;

    nl_msg_put_string(request, TCA_ACT_KIND, "mirred");
    offset = nl_msg_start_nested(request, TCA_ACT_OPTIONS);
    {
        struct tc_mirred m = { .action = TC_ACT_STOLEN,
                               .eaction = TCA_EGRESS_REDIR,
                               .ifindex = ifindex };

        nl_msg_put_unspec(request, TCA_MIRRED_PARMS, &m, sizeof m);
    }
    nl_msg_end_nested(request, offset);
}

static inline void
nl_msg_put_act_cookie(struct ofpbuf *request, struct tc_cookie *ck) {
    if (ck->len) {
        nl_msg_put_unspec(request, TCA_ACT_COOKIE, ck->data, ck->len);
    }
}

static void
nl_msg_put_flower_acts(struct ofpbuf *request, struct tc_flower *flower)
{
    size_t offset;
    size_t act_offset;

    offset = nl_msg_start_nested(request, TCA_FLOWER_ACT);
    {
        uint16_t act_index = 1;

        if (flower->ifindex_out) {
            act_offset = nl_msg_start_nested(request, act_index++);
            /* nl_msg_put_act_redirect(request, flower->ifindex_out); */
            nl_msg_put_act_drop(request);
            /* nl_msg_put_act_cookie(request, &flower->act_cookie); */
      	    /* fprintf(stderr, "[nl_msg_put_flower_acts] check2-3\n"); */
            nl_msg_end_nested(request, act_offset);
        } else {
            act_offset = nl_msg_start_nested(request, act_index++);
            nl_msg_put_act_drop(request);
            nl_msg_put_act_cookie(request, &flower->act_cookie);
            nl_msg_end_nested(request, act_offset);
        }
    }
    nl_msg_end_nested(request, offset);
}

static void
nl_msg_put_masked_value(struct ofpbuf *request, uint16_t type,
                        uint16_t mask_type, const void *data,
                        const void *mask_data, size_t len)
{
    if (mask_type != TCA_FLOWER_UNSPEC) {
        /* if (is_all_zeros(mask_data, len)) { */
        /*     return; */
        /* } */

        nl_msg_put_unspec(request, mask_type, mask_data, len);
    }
    nl_msg_put_unspec(request, type, data, len);
}

#define FLOWER_PUT_MASKED_VALUE(member, type) \
    nl_msg_put_masked_value(request, type, type##_MASK, &flower->key.member, \
                            &flower->mask.member, sizeof flower->key.member)

static void
nl_msg_put_flower_options(struct ofpbuf *request, struct tc_flower *flower)
{
    uint16_t host_eth_type = ntohs(flower->key.eth_type);
    bool is_vlan = (host_eth_type == ETH_TYPE_VLAN);

    /* if (is_vlan) { */
    /*     host_eth_type = ntohs(flower->key.encap_eth_type); */
    /* } */

    FLOWER_PUT_MASKED_VALUE(dst_mac, TCA_FLOWER_KEY_ETH_DST);
    FLOWER_PUT_MASKED_VALUE(src_mac, TCA_FLOWER_KEY_ETH_SRC);

    if (host_eth_type == ETH_P_IP || host_eth_type == ETH_P_IPV6) {
        if (flower->mask.ip_proto && flower->key.ip_proto) {
            nl_msg_put_u8(request, TCA_FLOWER_KEY_IP_PROTO,
                          flower->key.ip_proto);
        }

        if (flower->key.ip_proto == IPPROTO_UDP) {
            FLOWER_PUT_MASKED_VALUE(udp_src, TCA_FLOWER_KEY_UDP_SRC);
            FLOWER_PUT_MASKED_VALUE(udp_dst, TCA_FLOWER_KEY_UDP_DST);
        } else if (flower->key.ip_proto == IPPROTO_TCP) {
            FLOWER_PUT_MASKED_VALUE(tcp_src, TCA_FLOWER_KEY_TCP_SRC);
            FLOWER_PUT_MASKED_VALUE(tcp_dst, TCA_FLOWER_KEY_TCP_DST);
        } else if (flower->key.ip_proto == IPPROTO_SCTP) {
            FLOWER_PUT_MASKED_VALUE(sctp_src, TCA_FLOWER_KEY_SCTP_SRC);
            FLOWER_PUT_MASKED_VALUE(sctp_dst, TCA_FLOWER_KEY_SCTP_DST);
        }
    }

    if (host_eth_type == ETH_P_IP) {
            FLOWER_PUT_MASKED_VALUE(ipv4.ipv4_src, TCA_FLOWER_KEY_IPV4_SRC);
            FLOWER_PUT_MASKED_VALUE(ipv4.ipv4_dst, TCA_FLOWER_KEY_IPV4_DST);
    } else if (host_eth_type == ETH_P_IPV6) {
            FLOWER_PUT_MASKED_VALUE(ipv6.ipv6_src, TCA_FLOWER_KEY_IPV6_SRC);
            FLOWER_PUT_MASKED_VALUE(ipv6.ipv6_dst, TCA_FLOWER_KEY_IPV6_DST);
    }

    nl_msg_put_be16(request, TCA_FLOWER_KEY_ETH_TYPE, flower->key.eth_type);

    /* if (is_vlan) { */
    /*     if (flower->key.vlan_id || flower->key.vlan_prio) { */
    /*         nl_msg_put_u16(request, TCA_FLOWER_KEY_VLAN_ID, */
    /*                        flower->key.vlan_id); */
    /*         nl_msg_put_u8(request, TCA_FLOWER_KEY_VLAN_PRIO, */
    /*                       flower->key.vlan_prio); */
    /*     } */
    /*     if (flower->key.encap_eth_type) { */
    /*         nl_msg_put_be16(request, TCA_FLOWER_KEY_VLAN_ETH_TYPE, */
    /*                         flower->key.encap_eth_type); */
    /*     } */
    /* } */

    /* we should offload rules into the hardware */
    /* nl_msg_put_u32(request, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_SW); */
    nl_msg_put_u32(request, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_SW);
    /* nl_msg_put_u32(request, TCA_FLOWER_FLAGS, tc_get_tc_cls_policy(tc_policy)); */

    nl_msg_put_flower_acts(request, flower);
}

int
tc_replace_flower(int ifindex, uint16_t prio, uint32_t handle,
                  struct tc_flower *flower)
{
    struct ofpbuf request;
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error = 0;
    size_t basic_offset;

    uint16_t eth_type = (OVS_FORCE uint16_t) flower->key.eth_type;

    tcmsg = tc_make_request(ifindex, RTM_NEWTFILTER,
                            NLM_F_CREATE, &request);
    /* tcmsg = tc_make_request(ifindex, RTM_NEWTFILTER, */
    /*                         NLM_F_CREATE | NLM_F_ECHO, &request); */
    tcmsg->tcm_parent = TC_INGRESS_PARENT;
    tcmsg->tcm_info = tc_make_handle(prio, eth_type);
    tcmsg->tcm_handle = handle;


    nl_msg_put_string(&request, TCA_KIND, "flower");
    basic_offset = nl_msg_start_nested(&request, TCA_OPTIONS);
    {
        nl_msg_put_flower_options(&request, flower);
    }
    nl_msg_end_nested(&request, basic_offset);

    error = tc_transact(&request, &reply);
    if (!error) {
        /* struct tcmsg *tc = */
        /*     ofpbuf_at_assert(reply, NLMSG_HDRLEN, sizeof *tc); */

        /* flower->prio = tc_get_major(tc->tcm_info); */
        /* flower->handle = tc->tcm_handle; */

        ofpbuf_delete(reply);
    }

    return error;
}

/* add many flower filters at once. this may reduce overhead of communication between user and kernel */
int
tc_replace_flowers(int ifindex, uint16_t *prios, uint32_t handle,
		   struct tc_flower *flowers, int n)
{
    struct ofpbuf request[n];
    struct tcmsg *tcmsg;
    struct ofpbuf *reply;
    int error = 0;
    size_t basic_offset;
    struct nl_transaction **transactionp = (struct nl_transaction **)calloc(n, sizeof(struct nl_transaction*));
    struct nl_transaction transactions[n];
    uint16_t eth_type;
    int i;

    for(i = 0; i < n; i++) {
      eth_type = (OVS_FORCE uint16_t) flowers[i].key.eth_type;

      tcmsg = tc_make_request(ifindex, RTM_NEWTFILTER,
			      NLM_F_CREATE, &(request[i]));
      /* tcmsg = tc_make_request(ifindex, RTM_NEWTFILTER, */
      /*                         NLM_F_CREATE | NLM_F_ECHO, &request); */
      tcmsg->tcm_parent = TC_INGRESS_PARENT;
      tcmsg->tcm_info = tc_make_handle(prios[i], eth_type);
      tcmsg->tcm_handle = handle;

      nl_msg_put_string(&(request[i]), TCA_KIND, "flower");
      basic_offset = nl_msg_start_nested(&(request[i]), TCA_OPTIONS);
      {
        nl_msg_put_flower_options(&(request[i]), &flowers[i]);
      }
      nl_msg_end_nested(&(request[i]), basic_offset);

      transactions[i].request = CONST_CAST(struct ofpbuf *, &(request[i]));
      transactions[i].reply = NULL;
      transactionp[i] = &transactions[i];
    }

    nl_transact_multiple(NETLINK_ROUTE, transactionp, n);

    return error;
}

void
tc_set_policy(const char *policy)
{
    if (!policy) {
        return;
    }

    if (!strcmp(policy, "skip_sw")) {
        tc_policy = TC_POLICY_SKIP_SW;
    } else if (!strcmp(policy, "skip_hw")) {
        tc_policy = TC_POLICY_SKIP_HW;
    } else if (!strcmp(policy, "none")) {
        tc_policy = TC_POLICY_NONE;
    } else {
        /* VLOG_WARN("tc: Invalid policy '%s'", policy); */
        return;
    }

    /* VLOG_INFO("tc: Using policy '%s'", policy); */
}
