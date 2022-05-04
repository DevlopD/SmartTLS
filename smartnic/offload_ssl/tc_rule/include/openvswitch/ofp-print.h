/*
 * Copyright (c) 2008, 2009, 2011, 2012, 2015, 2017 Nicira, Inc.
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

/* OpenFlow protocol pretty-printer. */

#ifndef OPENVSWITCH_OFP_PRINT_H
#define OPENVSWITCH_OFP_PRINT_H 1

#include <stdint.h>
#include <stdio.h>

#include <openvswitch/types.h>

struct ds;
struct ofp10_match;
struct ofp_flow_mod;
struct ofp_header;
struct ofputil_flow_stats;
struct ofputil_port_map;
struct ofputil_table_features;
struct ofputil_table_stats;
struct dp_packet;

#ifdef  __cplusplus
extern "C" {
#endif

void ofp_print(FILE *, const void *, size_t, const struct ofputil_port_map *,
               int verbosity);
void ofp_print_packet(FILE *stream, const void *data,
                      size_t len, ovs_be32 packet_type);
void ofp_print_dp_packet(FILE *stream, const struct dp_packet *packet);

void ofp10_match_print(struct ds *, const struct ofp10_match *,
                       const struct ofputil_port_map *, int verbosity);

char *ofp_to_string(const void *, size_t, const struct ofputil_port_map *,
                    int verbosity);
char *ofp10_match_to_string(const struct ofp10_match *,
                            const struct ofputil_port_map *, int verbosity);
char *ofp_packet_to_string(const void *data, size_t len, ovs_be32 packet_type);
char *ofp_dp_packet_to_string(const struct dp_packet *packet);

void ofp_print_version(const struct ofp_header *, struct ds *);
void ofp_print_table_features(
    struct ds *, const struct ofputil_table_features *features,
    const struct ofputil_table_features *prev_features,
    const struct ofputil_table_stats *stats,
    const struct ofputil_table_stats *prev_stats);

void ofp_print_flow_stats(struct ds *, const struct ofputil_flow_stats *,
                          const struct ofputil_port_map *, bool show_stats);

#ifdef  __cplusplus
}
#endif

#endif /* ofp-print.h */
