#!/bin/bash

BR=br0
GW_IP=1.1.1.1
GW_MAC="dd:dd:dd:dd:dd:dd"

################################################################################
# NAT GATEWAY
################################################################################
function setup_nat_gw()
{
	ip netns del $1 2> /dev/null
	ip netns add $1

	# interface into namespace
	ovs-vsctl add-port $BR $1 -- set Interface $1 type=internal
	ip link set $1 netns $1
	ip netns exec $1 ip link set $1 up

	# route everything back out
	ip netns exec $1 ip rule add iif $1 lookup 100
	ip netns exec $1 ip route add $GW_IP/32 dev $1
	ip netns exec $1 ip route add default via $GW_IP table 100

	echo "NAT-GW: $1"
}

function add_nat()
{
	ip netns exec $1 iptables -t nat -A POSTROUTING -o $1 -d $2 -j SNAT --to $3

	echo "SNAT-MAP: dst = $2 => --to-source $3"
}

################################################################################
# TENANTS
################################################################################

function tenant_to_nat_gw()
{
	MAC=$(ip netns exec $3 ip link show $3 | grep ether | awk '{print $2}')

	ovs-ofctl add-flow $BR "priority=100,in_port=$1,actions=load:$2->NXM_NX_PKT_MARK[], \
				mod_dl_dst:$MAC,mod_dl_src:$GW_MAC,output:$(get_ofport $3)"
			
}

function do_l3_into_tenant()
{
	local MAC=$(ip netns exec $1 ip link show $2 | grep ether | awk '{print $2}')

	ovs-ofctl add-flow $BR "table=2,priority=100,ip,nw_dst=$3,actions= \
				mod_dl_dst:$MAC, \
				dec_ttl, \
				mod_dl_src:$GW_MAC, \
				output:$(get_ofport $2)"
}

# NETNS PORT-NAME PREFIX MARK-VALUE NAT_GW
function setup_tenant()
{
	ip netns del $1 2> /dev/null
	ip netns add $1
	ovs-vsctl add-port $BR $2 -- set Interface $2 type=internal
	ip link set $2 netns $1
	ip netns exec $1 ip link set $2 up
	ip netns exec $1 ip addr add $3/24 dev $2
	ip netns exec $1 ip route add $GW_IP/32 dev $2
	ip netns exec $1 ip route add default via $GW_IP

	tenant_to_nat_gw $(get_ofport $2) $4 $5
	do_l3_into_tenant $1 $2 $3

	echo "Tenant: $1 port=$2 ip=$3 mark=$4 nat-gw=$5"
}

################################################################################
# OVS BITZ
################################################################################

function get_ofport()
{
        local N=$(ovs-ofctl show $BR | grep $1 | cut -d'(' -f1)

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
	ovs-ofctl add-flow $BR "arp, arp_op=1, arp_tpa=$1, \
				actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[], \
				mod_dl_src:$2, \
				load:2->NXM_OF_ARP_OP[], \
				move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[], \
				load:$(mac2hex $2)->NXM_NX_ARP_SHA[], \
				move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[], \
				load:$(ip2hex $1)->NXM_OF_ARP_SPA[], \
				in_port"
}

################################################################################
# MAIN
################################################################################

/usr/share/openvswitch/scripts/ovs-ctl start

ovs-vsctl del-br $BR 2> /dev/null
ovs-vsctl add-br $BR

setup_nat_gw nat-gw

# SNAT matching DEST-PREFIX
add_nat nat-gw 40.0.0.0/8 80.1.1.100
add_nat nat-gw 50.0.0.0/8 90.1.1.100
add_nat nat-gw 60.0.0.0/8 100.1.1.100

ovs-ofctl del-flows $BR

arp_responder $GW_IP $GW_MAC

# All packets from tenants need to go through NAT-GW, mark packets with
# tenant specific metadata
setup_tenant net1 p1 40.1.1.1 1 nat-gw
setup_tenant net2 p2 50.1.1.1 2 nat-gw
setup_tenant net3 p3 60.1.1.1 3 nat-gw

# Packets coming out of the NAT box go to table 2
ovs-ofctl add-flow $BR "priority=100,in_port=$(get_ofport nat-gw),actions=resubmit(,2)"

# Drop everything else
ovs-ofctl add-flow $BR "priority=10,actions=drop"
ovs-ofctl add-flow $BR "table=2,priority=10,actions=drop"
