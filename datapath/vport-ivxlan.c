/*
 * Copyright (c) 2013 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/ip_tunnels.h>
#ifdef HAVE_UDP_TUNNEL_HANDLE_OFFLOADS
#include <net/udp_tunnel.h>
#endif
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/ivxlan.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "vport.h"

struct ivxlanhdr_word1 {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 reserved_flags:3,
	      instance_id_present:1,
	      map_version_present:1,
	      solicit_echo_nonce:1,
	      locator_status_bits_present:1,
	      nonce_present:1,

	      dre_or_mcast_bits:3,
	      dst_epg_policy_applied:1,
	      src_epg_policy_applied:1,
	      forward_exception:1,
	      dont_learn_addr_to_tep:1,
	      load_balancing_enabled:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 nonce_present:1,
	      locator_status_bits_present:1,
	      solicit_echo_nonce:1,
	      map_version_present:1,
	      instance_id_present:1,
	      reserved_flags:3,

	      load_balancing_enabled:1,
	      dont_learn_addr_to_tep:1,
	      forward_exception:1,
	      src_epg_policy_applied:1,
	      dst_epg_policy_applied:1,
	      dre_or_mcast_bits:3;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	__be16 src_group;
};

struct ivxlanhdr {
	union {
		struct ivxlanhdr_word1 word1;
		__be32 vx_flags;
	} u1;
	__be32 vx_vni;
};

#define IVXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct ivxlanhdr))

#define IVXLAN_FLAGS 0x08000000  /* struct ivxlanhdr.vx_flags required value. */

/**
 * struct ivxlan_port - Keeps track of open UDP ports
 * @vs: vxlan_sock created for the port.
 * @name: vport name.
 */
struct ivxlan_port {
	struct vxlan_sock *vs;
	__be16 ivxlan_sepg;
	char name[IFNAMSIZ];
};

static inline struct ivxlan_port *ivxlan_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

static inline void ivxlan_parse_header(struct ovs_tunnel_info *tun_info, struct ivxlanhdr *ivxh)
{
	tun_info->tunnel.ivxlan_sepg = ivxh->u1.word1.src_group;

	tun_info->tunnel.ivxlan_flags = 0;
	if (ivxh->u1.word1.src_epg_policy_applied)
		tun_info->tunnel.ivxlan_flags |= IVXLAN_SPA;
	if (ivxh->u1.word1.dst_epg_policy_applied)
		tun_info->tunnel.ivxlan_flags |= IVXLAN_DPA;
	if (ivxh->u1.word1.load_balancing_enabled)
		tun_info->tunnel.ivxlan_flags |= IVXLAN_LB;
	if (ivxh->u1.word1.dont_learn_addr_to_tep)
		tun_info->tunnel.ivxlan_flags |= IVXLAN_DL;
	if (ivxh->u1.word1.forward_exception)
		tun_info->tunnel.ivxlan_flags |= IVXLAN_FE;
	//printk(KERN_ERR "parse: flags %x, epg %d\n", tun_info->tunnel.ivxlan_flags,
	//       tun_info->tunnel.ivxlan_sepg);
}

static void ivxlan_construct_hdr(struct sk_buff *skb, __be32 vni)
{
	struct ivxlanhdr *ivxh = (struct ivxlanhdr *) __skb_push(skb, sizeof(*ivxh));
	struct ovs_key_ipv4_tunnel *tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	ivxh->u1.vx_flags = htonl(IVXLAN_FLAGS);
	ivxh->vx_vni = vni;
	ivxh->u1.word1.nonce_present = 1;
	ivxh->u1.word1.src_group = tun_key->ivxlan_sepg;

	if (tun_key->ivxlan_flags & IVXLAN_SPA)
		ivxh->u1.word1.src_epg_policy_applied = 1;
	if (tun_key->ivxlan_flags & IVXLAN_DPA)
		ivxh->u1.word1.dst_epg_policy_applied = 1;
	if (tun_key->ivxlan_flags & IVXLAN_LB)
		ivxh->u1.word1.load_balancing_enabled = 1;
	if (tun_key->ivxlan_flags & IVXLAN_DL)
		ivxh->u1.word1.dont_learn_addr_to_tep = 1;
	if (tun_key->ivxlan_flags & IVXLAN_FE)
		ivxh->u1.word1.forward_exception = 1;
	//printk(KERN_ERR "construct: flags %x, epg %d\n", tun_key->ivxlan_flags,
	//       tun_key->ivxlan_sepg);
}

/* Called with rcu_read_lock and BH disabled. */
static void ivxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb, __be32 vx_vni)
{
    BUG();
}

static int ivxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);
	__be16 dst_port = inet_sport(ivxlan_port->vs->sock->sk);

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(dst_port)))
		return -EMSGSIZE;

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_EPG,
	    ntohs(ivxlan_port->ivxlan_sepg)))
		return -EMSGSIZE;

	return 0;
}

static void ivxlan_tnl_destroy(struct vport *vport)
{
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);

	vxlan_sock_release(ivxlan_port->vs);

	ovs_vport_deferred_free(vport);
}

/* Called with rcu_read_lock and BH disabled from vxlan_udp_encap_recv. */
static int ivxlan_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct ivxlanhdr *ivxh;
	struct ovs_tunnel_info tun_info;
	struct vxlan_sock *vs;
	struct iphdr *iph;
	struct vport *vport;
	__be64 key;

	/* Need Vxlan and inner Ethernet header to be present */
	if (!pskb_may_pull(skb, IVXLAN_HLEN))
		goto error;

	ivxh = (struct ivxlanhdr *)(udp_hdr(skb) + 1);
	if (likely(ivxh->u1.word1.nonce_present)) {
		ivxlan_parse_header(&tun_info, ivxh);
	} else if (ivxh->u1.vx_flags != htonl(IVXLAN_FLAGS) ||
		   (ivxh->vx_vni & htonl(0xff))) {
		pr_warn("invalid vxlan flags=%#x vni=%#x\n",
			ntohl(ivxh->u1.vx_flags), ntohl(ivxh->vx_vni));
		goto error;
	}

	vs = rcu_dereference_sk_user_data(sk);
	if (!vs || iptunnel_pull_header(skb, IVXLAN_HLEN, htons(ETH_P_TEB)))
		goto drop;

	vport = vs->data;
	iph = ip_hdr(skb);
	key = cpu_to_be64(ntohl(ivxh->vx_vni) >> 8);
	/* MUST not zero tun_info */
	ovs_flow_tun_info_init(&tun_info, iph,
				udp_hdr(skb)->source, udp_hdr(skb)->dest,
				key, TUNNEL_KEY, NULL, 0);

	ovs_vport_receive(vport, skb, &tun_info);
	return 0;

drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;

error:
        /* Return non vxlan pkt */
	return 1;
}

static struct vport *ivxlan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct ivxlan_port *ivxlan_port;
	struct vxlan_sock *vs;
	//struct vxlan_ext vext;
	struct vport *vport;
	struct nlattr *a;
	u16 dst_port, epg;
	int err;

	if (!options) {
		err = -EINVAL;
		goto error;
	}
	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	a = nla_find_nested(options, OVS_TUNNEL_ATTR_EPG);
	if (a && nla_len(a) == sizeof(u16)) {
		epg = nla_get_u16(a);
	} else {
		epg = 0;
	}

	vport = ovs_vport_alloc(sizeof(struct ivxlan_port),
			    &ovs_ivxlan_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	ivxlan_port = ivxlan_vport(vport);
	strncpy(ivxlan_port->name, parms->name, IFNAMSIZ);

	ivxlan_port->ivxlan_sepg = htons(epg);

	vs = vxlan_sock_add(net, htons(dst_port), ivxlan_rcv, vport, true, false);
	if (IS_ERR(vs)) {
		ovs_vport_free(vport);
		return (void *)vs;
	}

	/* Noiro: Liberal iVXLAN parsing */
	udp_sk(vs->sock->sk)->encap_rcv = &ivxlan_udp_encap_rcv;

	//vext.parse = ivxlan_udp_encap_parse_hdr;
	//vext.construct = ivxlan_construct_hdr;
	//vxlan_register_extensions(vs, &vext);
	ivxlan_port->vs = vs;

	return vport;

error:
	return ERR_PTR(err);
}

#ifndef HAVE_IPTUNNEL_HANDLE_OFFLOADS
static struct sk_buff *iptunnel_handle_offloads(struct sk_buff *skb,
					 bool csum_help,
					 int gso_type_mask)
{
	int err;

	if (likely(!skb->encapsulation)) {
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
	}

	if (skb_is_gso(skb)) {
		err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			goto error;
		skb_shinfo(skb)->gso_type |= gso_type_mask;
		return skb;
	}

	/* If packet is not gso and we are resolving any partial checksum,
	 * clear encapsulation flag. This allows setting CHECKSUM_PARTIAL
	 * on the outer header without confusing devices that implement
	 * NETIF_F_IP_CSUM with encapsulation.
	 */
	if (csum_help)
		skb->encapsulation = 0;

	if (skb->ip_summed == CHECKSUM_PARTIAL && csum_help) {
		err = skb_checksum_help(skb);
		if (unlikely(err))
			goto error;
	} else if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_NONE;

	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(err);
}
#endif

#ifndef HAVE_UDP_TUNNEL_HANDLE_OFFLOADS
static inline struct sk_buff *vxlan_handle_offloads(struct sk_buff *skb,
	                                                    bool udp_csum)
{
	int type = SKB_GSO_UDP_TUNNEL;
	return iptunnel_handle_offloads(skb, udp_csum, type);
}
#endif

#ifndef HAVE_UDP_V4_CHECK
static inline __sum16 udp_v4_check(int len, __be32 saddr,
                                   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, base);
}
#endif

#ifndef HAVE_UDP_SET_CSUM
static void udp_set_csum(bool nocheck, struct sk_buff *skb,
                  __be32 saddr, __be32 daddr, int len)
{
        struct udphdr *uh = udp_hdr(skb);

        if (nocheck)
                uh->check = 0;
        else if (skb_is_gso(skb))
                uh->check = ~udp_v4_check(len, saddr, daddr, 0);
        else if (skb_dst(skb) && skb_dst(skb)->dev &&
                 (skb_dst(skb)->dev->features & NETIF_F_V4_CSUM)) {

                BUG_ON(skb->ip_summed == CHECKSUM_PARTIAL);

                skb->ip_summed = CHECKSUM_PARTIAL;
                skb->csum_start = skb_transport_header(skb) - skb->head;
                skb->csum_offset = offsetof(struct udphdr, check);
                uh->check = ~udp_v4_check(len, saddr, daddr, 0);
        } else {
                __wsum csum;

                BUG_ON(skb->ip_summed == CHECKSUM_PARTIAL);

                uh->check = 0;
                csum = skb_checksum(skb, 0, len, 0);
                uh->check = udp_v4_check(len, saddr, daddr, csum);
                if (uh->check == 0)
                        uh->check = CSUM_MANGLED_0;

                skb->ip_summed = CHECKSUM_UNNECESSARY;
        }
}
EXPORT_SYMBOL(udp_set_csum);

#endif

static int ivxlan_xmit_skb(struct vxlan_sock *vs,
                    struct rtable *rt, struct sk_buff *skb,
                    __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
                    __be16 src_port, __be16 dst_port, __be32 vni, bool xnet)
{
	int min_headroom;
	int err;
#ifndef HAVE_UDP_TUNNEL_XMIT_SKB
	struct udphdr *uh;
#endif

#ifdef HAVE_UDP_TUNNEL_HANDLE_OFFLOADS
	bool udp_sum = !vs->sock->sk->sk_no_check_tx;

	skb = udp_tunnel_handle_offloads(skb, udp_sum);
#else
	skb = vxlan_handle_offloads(skb, false);
#endif
	if (IS_ERR(skb))
		return -EINVAL;

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ IVXLAN_HLEN + sizeof(struct iphdr)
			+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

	/* Need space for new headers (invalidates iph ptr) */
	err = skb_cow_head(skb, min_headroom);
	if (unlikely(err))
		return err;

#ifdef HAVE_VLAN_HWACCEL_PUSH_INSIDE
	skb = vlan_hwaccel_push_inside(skb);
	if (WARN_ON(!skb))
		return -ENOMEM;
#else
	if (vlan_tx_tag_present(skb)) {
		if (WARN_ON(!__vlan_put_tag(skb,
					    skb->vlan_proto,
					    vlan_tx_tag_get(skb))))
			return -ENOMEM;

		skb->vlan_tci = 0;
	}
#endif

	ivxlan_construct_hdr(skb, vni);

#ifdef HAVE_UDP_TUNNEL_XMIT_SKB
	skb_set_inner_protocol(skb, htons(ETH_P_TEB));

	return udp_tunnel_xmit_skb(vs->sock, rt, skb, src, dst, tos,
				   ttl, df, src_port, dst_port, xnet);
#else
	__skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);

	uh->dest = dst_port;
	uh->source = src_port;

	uh->len = htons(skb->len);

	udp_set_csum(false, skb,
		     src, dst, skb->len);

	return iptunnel_xmit(vs->sock->sk, rt, skb, src, dst, IPPROTO_UDP,
			     tos, ttl, df, xnet);
#endif
}

static int ivxlan_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct ovs_key_ipv4_tunnel *tun_key;
	struct net *net = ovs_dp_get_net(vport->dp);
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);
	__be16 dst_port = inet_sport(ivxlan_port->vs->sock->sk);
	struct rtable *rt;
	__be16 src_port;
	__be32 saddr;
	__be16 df;
	int err;

	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	/* Route lookup */
	saddr = tun_key->ipv4_src;
	rt = find_route(ovs_dp_get_net(vport->dp),
			&saddr, tun_key->ipv4_dst,
			IPPROTO_UDP,
			tun_key->ipv4_tos,
			skb->mark);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	skb->ignore_df = 1;

	src_port = udp_flow_src_port(net, skb, 0, 0, true);

	if (tun_key->ivxlan_sepg == 0)
		tun_key->ivxlan_sepg = ivxlan_port->ivxlan_sepg;
	err = ivxlan_xmit_skb(ivxlan_port->vs, rt, skb,
			      saddr, tun_key->ipv4_dst,
			      tun_key->ipv4_tos,
			      tun_key->ipv4_ttl, df,
			      src_port, dst_port,
			      htonl(be64_to_cpu(tun_key->tun_id) << 8),
			      false);
	if (err < 0)
		ip_rt_put(rt);
error:
	return err;
}

static const char *ivxlan_get_name(const struct vport *vport)
{
	struct ivxlan_port *ivxlan_port = ivxlan_vport(vport);
	return ivxlan_port->name;
}

const struct vport_ops ovs_ivxlan_vport_ops = {
	.type         = OVS_VPORT_TYPE_IVXLAN,
	.create       = ivxlan_tnl_create,
	.destroy      = ivxlan_tnl_destroy,
	.get_name     = ivxlan_get_name,
	.get_options  = ivxlan_get_options,
	.send         = ivxlan_tnl_send,
};
