/*
 * Copyright (c) 2015 Nicira, Inc.
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

#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include "datapath.h"
#include "flow_netlink.h"

struct ovs_conntrack_info {
	u32 flags;
	u16 zone;
	struct nf_conn *ct;
};

/* Determine whether skb->nfct is equal to the result of conntrack lookup. */
static bool skb_has_valid_nfct(const struct net *net, u16 zone,
			       const struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	if (!ct)
		return false;
	if (!net_eq(net, ct->ct_net))
		return false;
	if (zone != nf_ct_zone(ct))
		return false;
	return true;
}

static int ovs_ct_lookup__(struct nf_conn *tmpl, struct sk_buff *skb)
{
	struct net *net;
	u16 zone = tmpl ? nf_ct_zone(tmpl) : NF_CT_DEFAULT_ZONE;

#ifdef CONFIG_NET_NS
	{
		struct vport *vport;

		vport = OVS_CB(skb)->input_vport;
		if (!vport)
			return -EINVAL;

		net = vport->dp->net;
	}
#else
	net = &init_net;
#endif

	if (!skb_has_valid_nfct(net, zone, skb)) {
		/* Associate skb with specified zone. */
		if (tmpl) {
			atomic_inc(&tmpl->ct_general.use);
			skb->nfct = &tmpl->ct_general;
			skb->nfctinfo = IP_CT_NEW;
		}

		if (nf_conntrack_in(net, PF_INET, NF_INET_PRE_ROUTING, skb) !=
		    NF_ACCEPT)
			return -ENOENT;
	}

	return 0;
}

int ovs_ct_lookup(struct net *net, u16 zone, struct sk_buff *skb)
{
	struct nf_conntrack_tuple t;
	struct nf_conn *tmpl;
	int err;

	/* nf_ct_get_tuplepr ??? */

#ifdef CONFIG_NF_CONNTRACK_ZONES
	memset(&t, 0, sizeof(t));
	tmpl = nf_conntrack_alloc(net, zone, &t, &t, GFP_KERNEL);
	if (IS_ERR(tmpl))
		return PTR_ERR(tmpl);
#else
	tmpl = NULL;
#endif

	err = ovs_ct_lookup__(tmpl, skb);
	nf_ct_put(tmpl);
	return err;
}

/* Map SKB connection state into the values used by flow definition. */
u8 ovs_ct_get_state(const struct sk_buff *skb)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	enum ip_conntrack_info ctinfo;
	u8 cstate = OVS_CS_F_TRACKED;

	if (!nf_ct_get(skb, &ctinfo))
		return 0;

	switch(ctinfo) {
	case IP_CT_ESTABLISHED_REPLY:
	case IP_CT_RELATED_REPLY:
	case IP_CT_NEW_REPLY:
		cstate |= OVS_CS_F_REPLY_DIR;
		break;
	default:
		break;
	}

	switch(ctinfo) {
	case IP_CT_ESTABLISHED:
	case IP_CT_ESTABLISHED_REPLY:
		cstate |= OVS_CS_F_ESTABLISHED;
		break;
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		cstate |= OVS_CS_F_RELATED;
		break;
	case IP_CT_NEW:
	case IP_CT_NEW_REPLY:
		cstate |= OVS_CS_F_NEW;
		break;
	default:
		break;
	}

	return cstate;
#else
	return 0;
#endif /* CONFIG_NF_CONNTRACK || CONFIG_NF_CONNTRACK_MODULE */
}

u16 ovs_ct_get_zone(const struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);

	return ct ? nf_ct_zone(ct) : NF_CT_DEFAULT_ZONE;
}

u32 ovs_ct_get_mark(const struct sk_buff *skb)
{
#if defined(CONFIG_NF_CONNTRACK_MARK)
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	return ct ? ct->mark : 0;
#else
	return 0;
#endif
}

int ovs_ct_set_mark(struct sk_buff *skb, struct sw_flow_key *key,
		    u32 conn_mark)
{
#if defined(CONFIG_NF_CONNTRACK_MARK)
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return -EINVAL;

	if (ct->mark != conn_mark) {
		ct->mark = conn_mark;
		nf_conntrack_event_cache(IPCT_MARK, ct);
		key->phy.conn_mark = conn_mark;
	}
#endif

	return 0;
}

int ovs_ct_execute(struct sk_buff *skb, struct sw_flow_key *key,
		   const struct ovs_conntrack_info *info)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	int nh_ofs = skb_network_offset(skb);
	struct nf_conn *tmpl = info->ct;

	/* The conntrack module expects to be working at L3. */
	skb_pull(skb, nh_ofs);

	if (ovs_ct_lookup__(tmpl, skb))
		goto err_push_skb;

	if (info->flags & OVS_CT_F_COMMIT) {
		enum ip_conntrack_info ctinfo;
		struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

		if (!nf_ct_is_confirmed(ct) &&
		    nf_conntrack_confirm(skb) != NF_ACCEPT)
			goto err_push_skb;
	}

	/* Point back to L2, which OVS expects. */
	skb_push(skb, nh_ofs);

	key->phy.conn_state = ovs_ct_get_state(skb);
	key->phy.conn_zone = ovs_ct_get_zone(skb);
	key->phy.conn_mark = ovs_ct_get_mark(skb);

	return 0;

err_push_skb:
	skb_push(skb, nh_ofs);
#endif /* CONFIG_NF_CONNTRACK || CONFIG_NF_CONNTRACK_MODULE */
	return -EINVAL;
}

int ovs_ct_copy_action(struct net *net, const struct nlattr *attr,
			      const struct sw_flow_key *key,
			      struct sw_flow_actions **sfa,  bool log)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct ovs_conntrack_info ct_info;
	struct nf_conntrack_tuple t;
	struct nlattr *a;
	int rem;

	memset(&ct_info, 0, sizeof(ct_info));

	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		static const u32 ovs_ct_attr_lens[OVS_CT_ATTR_MAX + 1] = {
			[OVS_CT_ATTR_FLAGS] = sizeof(u32),
			[OVS_CT_ATTR_ZONE] = sizeof(u16),
		};

		if (type > OVS_CT_ATTR_MAX) {
			OVS_NLERR(log,
				  "Unknown conntrack attr (type=%d, max=%d).\n",
				  type, OVS_CT_ATTR_MAX);
			return -EINVAL;
		}

		if (ovs_ct_attr_lens[type] != nla_len(a) &&
				ovs_ct_attr_lens[type] != -1) {
			OVS_NLERR(log,
				  "Conntrack attr type has unexpected length (type=%d, length=%d, expected=%d).\n",
				  type, nla_len(a), ovs_ct_attr_lens[type]);
			return -EINVAL;
		}

		switch (type) {
#ifdef CONFIG_NF_CONNTRACK_ZONES
			case OVS_CT_ATTR_ZONE:
				memset(&t, 0, sizeof(t));
				ct_info.zone = nla_get_u16(a);
				ct_info.ct = nf_conntrack_alloc(net,
						ct_info.zone, &t, &t,
						GFP_KERNEL);
				if (IS_ERR(ct_info.ct))
					return PTR_ERR(ct_info.ct);

				nf_conntrack_tmpl_insert(net, ct_info.ct);
				break;
#endif
			case OVS_CT_ATTR_FLAGS:
				ct_info.flags = nla_get_u32(a);
				break;
			default:
				OVS_NLERR(log, "Unknown conntrack attr (%d).\n",
					  type);
				return -EINVAL;
		}
	}

	if (rem > 0) {
		OVS_NLERR(log, "Conntrack attr has %d unknown bytes.\n", rem);
		return -EINVAL;
	}

	return ovs_nla_add_action(sfa, OVS_ACTION_ATTR_CT, &ct_info,
				  sizeof(ct_info), log);
#else
	OVS_NLERR(log, "Conntrack disabled in kernel.\n");
	return -EINVAL;
#endif /* CONFIG_NF_CONNTRACK || CONFIG_NF_CONNTRACK_MODULE */
}

int ovs_ct_action_to_attr(const struct ovs_conntrack_info *ct_info,
			  struct sk_buff *skb)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct nlattr *start;

	start = nla_nest_start(skb, OVS_ACTION_ATTR_CT);
	if (!start)
		return -EMSGSIZE;

	if (nla_put_u32(skb, OVS_CT_ATTR_FLAGS, ct_info->flags))
		return -EMSGSIZE;

	if (nla_put_u16(skb, OVS_CT_ATTR_ZONE, ct_info->zone))
		return -EMSGSIZE;

	nla_nest_end(skb, start);

#endif /* CONFIG_NF_CONNTRACK || CONFIG_NF_CONNTRACK_MODULE */
	return 0;
}

void ovs_ct_free_acts(struct sw_flow_actions *sf_acts)
{
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	if (sf_acts) {
		struct ovs_conntrack_info *ct_info;
		struct nlattr *a;
		int rem, len = sf_acts->actions_len;

		for (a = sf_acts->actions, rem = len; rem > 0;
		     a = nla_next(a, &rem)) {
			switch (nla_type(a)) {
				case OVS_ACTION_ATTR_CT:
					ct_info = nla_data(a);
					if (ct_info->ct)
						nf_ct_put(ct_info->ct);
					break;
			}
		}
	}
#endif /* CONFIG_NF_CONNTRACK || CONFIG_NF_CONNTRACK_MODULE */
}

