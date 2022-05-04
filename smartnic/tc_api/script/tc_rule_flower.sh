#!/bin/sh

## reset qdisc
tc qdisc del dev p0 ingress 
tc qdisc del dev pf0hpf ingress 
tc qdisc add dev p0 ingress
tc qdisc add dev pf0hpf ingress

# from host to network
tc filter add dev pf0hpf protocol 802.1Q parent ffff: \
    flower skip_sw \
    src_mac b8:59:9f:38:57:fc \
    action mirred egress redirect dev p0


# from network to host, with specific src port and priority
SET=$(seq 500 500)
for i in $SET
do
    tc filter add dev p0 protocol ip parent ffff: \
        prio $i \
        flower skip_sw \
        src_ip 10.0.43.4 \
        ip_proto tcp src_port $i \
        action mirred egress redirect dev pf0hpf
done

## show filters
# tc -s -d filter show dev p0 ingress
# tc -s -d filter show dev pf0hpf ingress

## delete specific filter with pref
# tc filter delete dev p0 parent ffff: protocol ip pref 49151 flower
