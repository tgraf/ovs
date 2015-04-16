#!/bin/bash

/usr/share/openvswitch/scripts/ovs-ctl start

ovs-vsctl del-br br0 2> /dev/null
ovs-vsctl add-br br0

################################################################################
# NAT GATEWAY
################################################################################
ip netns del natns 2> /dev/null
ip netns add natns

# interface into namespace
ovs-vsctl add-port br0 nat-in -- set Interface nat-in type=internal
ip link set nat-in netns natns
ip netns exec natns ip link set nat-in up
ip netns exec natns ip addr add 10.1.1.2/24 dev nat-in

# interface out of namespace
ovs-vsctl add-port br0 nat-out -- set Interface nat-out type=internal
ip link set nat-out netns natns
ip netns exec natns ip link set nat-out up
ip netns exec natns ip addr add 10.1.2.2/24 dev nat-out

# nat-in -> nat-out
ip netns exec natns ip rule add iif nat-in lookup 100
ip netns exec natns ip route add default via 10.1.2.1 table 100

# nat-out -> nat-in
ip netns exec natns ip rule add iif nat-out lookup 200
ip netns exec natns ip route add default via 10.1.1.1 table 200

#ip netns exec natns iptables -t raw -A PREROUTING -i nat-in -d 40.0.0.0/8 -j CT --zone 1
#ip netns exec natns iptables -t raw -A PREROUTING -i nat-in -d 50.0.0.0/8 -j CT --zone 2
#ip netns exec natns iptables -t raw -A PREROUTING -i nat-in -d 60.0.0.0/8 -j CT --zone 3

#ip netns exec natns iptables -t nat -A POSTROUTING -o nat-out -d 40.0.0.0/8 -j SNAT --to 40.1.1.100
#ip netns exec natns iptables -t nat -A POSTROUTING -o nat-out -d 50.0.0.0/8 -j SNAT --to 50.1.1.100
#ip netns exec natns iptables -t nat -A POSTROUTING -o nat-out -d 60.0.0.0/8 -j SNAT --to 60.1.1.100
#ip netns exec natns iptables -t nat -A POSTROUTING -o nat-out -j LOG

################################################################################
# TENANT 1
################################################################################
ip netns del net1 2> /dev/null
ip netns add net1
ovs-vsctl add-port br0 p1 -- set Interface p1 type=internal
ip link set p1 netns net1
ip netns exec net1 ip link set p1 up
ip netns exec net1 ip addr add 40.1.1.1/24 dev p1
ip netns exec net1 ip route add 1.1.1.1/32 dev p1
ip netns exec net1 ip route add default via 1.1.1.1

################################################################################
# TENANT 2
################################################################################
ip netns del net2 2> /dev/null
ip netns add net2
ovs-vsctl add-port br0 p2 -- set Interface p2 type=internal
ip link set p2 netns net2
ip netns exec net2 ip link set p2 up
ip netns exec net2 ip addr add 50.1.1.1/24 dev p2
ip netns exec net2 ip route add 1.1.1.1/32 dev p2
ip netns exec net2 ip route add default via 1.1.1.1 dev p2

################################################################################
# TENANT 3
################################################################################
ip netns del net3 2> /dev/null
ip netns add net3
ovs-vsctl add-port br0 p3 -- set Interface p3 type=internal
ip link set p3 netns net3
ip netns exec net3 ip link set p3 up
ip netns exec net3  ip addr add 60.1.1.1/24 dev p3
ip netns exec net3 ip route add 1.1.1.1/32 dev p3
ip netns exec net3 ip route add default via 1.1.1.1 dev p3

ovs-ofctl del-flows br0

function get_ofport()
{
        local N=$(ovs-ofctl show br0 | grep $1 | cut -d'(' -f1)

        if [ -z "$N" ]; then
                exit 1
        fi

        echo $N
}

function ip2hex()
{
        echo -n 0x
        printf '%02X' ${1//./ }
}

function mac2hex()
{
        echo 0x${1//:/}
}

function arp_responder()
{
	ovs-ofctl add-flow br0 "arp, arp_op=1, arp_tpa=$1, \
							actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[], \
							mod_dl_src:$2, \
							load:2->NXM_OF_ARP_OP[], \
							move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[], \
							load:$(mac2hex $2)->NXM_NX_ARP_SHA[], \
							move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[], \
							load:$(ip2hex $1)->NXM_OF_ARP_SPA[], \
							in_port"
}

# Respond to all ARPs for 1.1.1.1 with MAC of NAT gateway
arp_responder 1.1.1.1 "dd:dd:dd:dd:dd:dd"

# Provide ARPs for logical gateways
arp_responder 10.1.1.1 "dd:dd:dd:dd:dd:dd"
arp_responder 10.1.2.1 "dd:dd:dd:dd:dd:dd"

function filter_tenant()
{
	ovs-ofctl add-flow br0 "priority=100,pkt_mark=0,in_port=$1,conn_state=-trk,actions=load:$2->NXM_NX_PKT_MARK[], \
						   ct(commit,recirc,zone=$2)"
}

# Mark packets and pass through CT
filter_tenant $(get_ofport p1) 1
filter_tenant $(get_ofport p2) 2
filter_tenant $(get_ofport p3) 3

ovs-ofctl add-flow br0 "priority=100,in_port=$(get_ofport nat-in),actions=resubmit(,2)"
ovs-ofctl add-flow br0 "priority=100,in_port=$(get_ofport nat-out),actions=resubmit(,2)"

MAC=$(ip netns exec natns ip link show nat-in | grep ether | awk '{print $2}')
NAT_IN="mod_dl_dst:$MAC,mod_dl_src:dd:dd:dd:dd:dd:dd,output:$(get_ofport nat-in)"

MAC=$(ip netns exec natns ip link show nat-out | grep ether | awk '{print $2}')
NAT_OUT="mod_dl_dst:$MAC,mod_dl_src:dd:dd:dd:dd:dd:dd,output:$(get_ofport nat-out)"

# Do L3 into NAT gateway, If we've seen the connection before, nat-out, else nat-in
ovs-ofctl add-flow br0 "priority=50,conn_state=+trk-rpl,actions=$NAT_IN"
ovs-ofctl add-flow br0 "priority=50,conn_state=+trk+rpl,actions=$NAT_OUT"
ovs-ofctl add-flow br0 "priority=10,actions=drop"

# GW-MAC PREFIX NEXTHOP
function do_l3()
{
	ovs-ofctl add-flow br0 "table=2,priority=100,ip,nw_dst=$2,actions= \
							mod_dl_dst:$3, \
							dec_ttl, \
							mod_dl_src:$1, \
							output:$4"
}

GW_MAC="dd:dd:dd:dd:dd:dd"
TENANT_MAC=$(ip netns exec net1 ip link show p1 | grep ether | awk '{print $2}')
do_l3 $GW_MAC 40.1.1.1 $TENANT_MAC $(get_ofport p1)

TENANT_MAC=$(ip netns exec net2 ip link show p2 | grep ether | awk '{print $2}')
do_l3 $GW_MAC 50.1.1.1 $TENANT_MAC $(get_ofport p2)

TENANT_MAC=$(ip netns exec net3 ip link show p3 | grep ether | awk '{print $2}')
do_l3 $GW_MAC 60.1.1.1 $TENANT_MAC $(get_ofport p3)

# Drop everything else
ovs-ofctl add-flow br0 "table=2,priority=10,actions=drop"
