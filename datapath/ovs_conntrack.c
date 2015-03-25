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
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0)

#include <linux/module.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/openvswitch.h>

#include "datapath.h"
#include "ovs_conntrack.h"
#include "flow.h"
#include "flow_netlink.h"

struct ovs_ct_len_tbl {
	size_t maxlen;
	size_t minlen;
};

struct ovs_conntrack_info {
	struct nf_conntrack_helper *helper;
	struct nf_conn *ct;
	u32 flags;
	u16 zone;
};

/* Determine whether skb->nfct is equal to the result of conntrack lookup. */
static bool skb_nfct_cached(const struct net *net, const struct sk_buff *skb,
			    const struct ovs_conntrack_info *info)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return false;
	WARN(!net_eq(net, read_pnet(&ct->ct_net)),
	     "Packet has conntrack association from different namespace\n");
	if (!net_eq(net, read_pnet(&ct->ct_net))) {
		return false;
	}
	if (info->zone != nf_ct_zone(ct))
		return false;
	if (info->helper) {
		struct nf_conn_help *help;

		help = nf_ct_ext_find(ct, NF_CT_EXT_HELPER);
		if (help && help->helper != info->helper)
			return false;
	}

	return true;
}

static struct net *ovs_get_net(const struct sk_buff *skb)
{
	struct vport *vport;

	vport = OVS_CB(skb)->input_vport;
	if (!vport)
		return ERR_PTR(-EINVAL);

	return read_pnet(&vport->dp->net);
}

/* Map SKB connection state into the values used by flow definition. */
u8 ovs_ct_get_state(const struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	u8 cstate = OVS_CS_F_TRACKED;

	if (!nf_ct_get(skb, &ctinfo))
		return 0;

	switch (ctinfo) {
	case IP_CT_ESTABLISHED_REPLY:
	case IP_CT_RELATED_REPLY:
	case IP_CT_NEW_REPLY:
		cstate |= OVS_CS_F_REPLY_DIR;
		break;
	default:
		break;
	}

	switch (ctinfo) {
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
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	return ct ? ct->mark : 0;
}

void ovs_ct_get_label(const struct sk_buff *skb,
		      struct ovs_key_conn_label *label)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn_labels *cl = NULL;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct)
		cl = nf_ct_labels_find(ct);

	if (cl) {
		size_t len = cl->words * sizeof(long);

		if (len > OVS_CT_LABEL_LEN)
			len = OVS_CT_LABEL_LEN;
		else if (len < OVS_CT_LABEL_LEN)
			memset(label, 0, OVS_CT_LABEL_LEN);
		memcpy(label, cl->bits, len);
	} else {
		memset(label, 0, OVS_CT_LABEL_LEN);
	}
}

bool ovs_ct_state_valid(const struct sw_flow_key *key)
{
	return (key->phy.conn_state &&
		!(key->phy.conn_state & OVS_CS_F_INVALID));
}

static int ovs_ct_lookup__(struct net *net, struct sw_flow_key *key,
			   const struct ovs_conntrack_info *info,
			   struct sk_buff *skb)
{
	struct nf_conn *tmpl = info->ct;

	/* If we are recirculating packets to match on conntrack fields and
	 * committing with a separate conntrack action,  then we don't need to
	 * actually run the packet through conntrack twice unless it's for a
	 * different zone. */
	if (!skb_nfct_cached(net, skb, info)) {
		uint8_t pf;

		/* Associate skb with specified zone. */
		if (tmpl) {
			if (skb->nfct)
				nf_conntrack_put(skb->nfct);
			nf_conntrack_get(&tmpl->ct_general);
			skb->nfct = &tmpl->ct_general;
			skb->nfctinfo = IP_CT_NEW;
		}

		pf = key->eth.type == htons(ETH_P_IP) ? PF_INET
		   : key->eth.type == htons(ETH_P_IPV6) ? PF_INET6
		   : PF_UNSPEC;
		if (nf_conntrack_in(net, pf, NF_INET_PRE_ROUTING, skb) !=
		    NF_ACCEPT)
			return -ENOENT;
	}

	/* XXX This probably doesn't need doing if it's cached. */
	if (skb->nfct) {
		key->phy.conn_state = ovs_ct_get_state(skb);
		key->phy.conn_zone = ovs_ct_get_zone(skb);
	} else {
		key->phy.conn_state = OVS_CS_F_TRACKED | OVS_CS_F_INVALID;
		key->phy.conn_zone = info->zone;
	}
	key->phy.conn_mark = ovs_ct_get_mark(skb);
	ovs_ct_get_label(skb, &key->phy.conn_label);

	return 0;
}

static int ovs_ct_lookup(struct net *net, struct sw_flow_key *key,
			 struct sk_buff *skb)
{
	struct ovs_conntrack_info info;
	struct nf_conntrack_tuple t;
	struct nf_conn *tmpl = NULL;
	u16 zone;
	int err;

	zone = key->phy.conn_zone;
	if (zone != NF_CT_DEFAULT_ZONE) {
		memset(&t, 0, sizeof(t));
		tmpl = nf_conntrack_alloc(net, zone, &t, &t, GFP_KERNEL);
		if (IS_ERR(tmpl))
			return PTR_ERR(tmpl);
		/* XXX The other place does some bit twiddling to ensure this is treated as a template */
		__set_bit(IPS_TEMPLATE_BIT, &tmpl->status);
		__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
		nf_conntrack_get(&tmpl->ct_general);
	}

	info.ct = tmpl;
	info.flags = 0;
	info.zone = zone;
	info.helper = NULL;
	err = ovs_ct_lookup__(net, key, &info, skb);
	if (tmpl && skb->nfct == &tmpl->ct_general)
		nf_ct_put(tmpl);

	return err;
}

int ovs_ct_execute(struct sk_buff *skb, struct sw_flow_key *key,
		   const struct ovs_conntrack_info *info)
{
	struct net *net;
	int nh_ofs, err;

	net = ovs_get_net(skb);
	if (IS_ERR(net))
		return PTR_ERR(net);

	/* The conntrack module expects to be working at L3. */
	nh_ofs = skb_network_offset(skb);
	skb_pull(skb, nh_ofs);

	err = -EINVAL;
	if (ovs_ct_lookup__(net, key, info, skb))
		goto err_push_skb;

	if (info->flags & OVS_CT_F_COMMIT && ovs_ct_state_valid(key) &&
	    nf_conntrack_confirm(skb) != NF_ACCEPT)
		goto err_push_skb;

	err = 0;
err_push_skb:
	/* Point back to L2, which OVS expects. */
	skb_push(skb, nh_ofs);
	return err;
}

/* If conntrack is performed on a packet which is subsequently sent to
 * userspace, then on execute the returned packet won't have conntrack
 * available in the skb. Initialize it if it is needed.
 *
 * Typically this should boil down to a no-op.
 */
static int reinit_skb_nfct(struct sk_buff *skb, struct sw_flow_key *key)
{
	struct net *net;
	int err;

	if (!ovs_ct_state_valid(key))
		return -EINVAL;

	net = ovs_get_net(skb);
	if (IS_ERR(net))
		return PTR_ERR(net);

	err = ovs_ct_lookup(net, key, skb);
	if (err)
		return err;

	return 0;
}

int ovs_ct_set_mark(struct sk_buff *skb, struct sw_flow_key *key,
		    u32 conn_mark, u32 mask)
{
#ifdef CONFIG_NF_CONNTRACK_MARK
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	u32 new_mark;
	int err;

	err = reinit_skb_nfct(skb, key);
	if (err)
		return err;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return -EINVAL;

	new_mark = conn_mark | (ct->mark & ~(mask));
	if (ct->mark != new_mark) {
		ct->mark = new_mark;
		nf_conntrack_event_cache(IPCT_MARK, ct);
		key->phy.conn_mark = conn_mark;
	}

	return 0;
#else
	return -ENOTSUPP;
#endif
}

int ovs_ct_set_label(struct sk_buff *skb, struct sw_flow_key *key,
		     const struct ovs_key_conn_label *label,
		     const struct ovs_key_conn_label *mask)
{
#ifdef CONFIG_NF_CONNTRACK_LABELS
	enum ip_conntrack_info ctinfo;
	struct nf_conn_labels *cl;
	struct nf_conn *ct;
	int err;

	err = reinit_skb_nfct(skb, key);
	if (err)
		return err;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return -EINVAL;

	cl = nf_ct_labels_find(ct);
	if (!cl) {
		nf_ct_labels_ext_add(ct);
		cl = nf_ct_labels_find(ct);
	}
	if (!cl || cl->words * sizeof(long) < OVS_CT_LABEL_LEN)
		return -ENOSPC;

	/* XXX: nf_connlabels_replace() depends on CONFIG_NF_CT_NETLINK. */
	err = nf_connlabels_replace(ct, (u32 *)label, (u32 *)mask,
				    OVS_CT_LABEL_LEN / sizeof(u32));
	if (err)
		return err;

	ovs_ct_get_label(skb, &key->phy.conn_label);
	return 0;
#else
	return -ENOTSUPP;
#endif
}

int ovs_ct_verify(u64 attrs)
{
	int err = 0;

#ifndef CONFIG_NF_CONNTRACK_ZONES
	if (attrs & (1ULL << OVS_KEY_ATTR_CONN_ZONE))
		return -ENOTSUPP;
#endif
#ifndef CONFIG_NF_CONNTRACK_MARK
	if (attrs & (1ULL << OVS_KEY_ATTR_CONN_MARK))
		return -ENOTSUPP;
#endif
#ifndef CONFIG_NF_CONNTRACK_LABELS
	if (attrs & (1ULL << OVS_KEY_ATTR_CONN_LABEL))
		return -ENOTSUPP;
#endif

	return err;
}

static u16 get_family(const struct sw_flow_key *key)
{
	switch (ntohs(key->eth.type)) {
	case ETH_P_IP:
		return AF_INET;
	case ETH_P_IPV6:
		return AF_INET6;
	default:
		return 0;
	}
}

static int ovs_ct_add_helper(struct ovs_conntrack_info *info, const char *name,
			     const struct sw_flow_key *key, bool log)
{
	struct nf_conntrack_helper *helper;
	struct nf_conn_help *help;

	helper = nf_conntrack_helper_try_module_get(name, get_family(key),
						    key->ip.proto);
	if (!helper) {
		OVS_NLERR(log, "Unknown helper \"%s\"", name);
		return -ENOENT;
	}

	help = nf_ct_helper_ext_add(info->ct, helper, GFP_KERNEL);
	if (!help) {
		module_put(helper->me);
		return -ENOMEM;
	}

	help->helper = helper;
	info->helper = helper;
	return 0;
}

static const struct ovs_ct_len_tbl ovs_ct_attr_lens[OVS_CT_ATTR_MAX + 1] = {
	[OVS_CT_ATTR_FLAGS]	= { .minlen = sizeof(u32),
				    .maxlen = sizeof(u32) },
	[OVS_CT_ATTR_ZONE]	= { .minlen = sizeof(u16),
				    .maxlen = sizeof(u16) },
	[OVS_CT_ATTR_HELPER]	= { .minlen = 1,
				    .maxlen = NF_CT_HELPER_NAME_LEN }
};

int ovs_ct_copy_action(struct net *net, const struct nlattr *attr,
		       const struct sw_flow_key *key,
		       struct sw_flow_actions **sfa,  bool log)
{
	struct ovs_conntrack_info ct_info;
	const char *helper = NULL;
	struct nlattr *a;
	int rem, err;

	if (key->eth.type != htons(ETH_P_IP) &&
	    key->eth.type != htons(ETH_P_IPV6))
		return -EINVAL;

	memset(&ct_info, 0, sizeof(ct_info));

	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		int maxlen = ovs_ct_attr_lens[type].maxlen;
		int minlen = ovs_ct_attr_lens[type].minlen;

		if (type > OVS_CT_ATTR_MAX) {
			OVS_NLERR(log,
				  "Unknown conntrack attr (type=%d, max=%d)",
				  type, OVS_CT_ATTR_MAX);
			return -EINVAL;
		}
		if (nla_len(a) < minlen || nla_len(a) > maxlen) {
			OVS_NLERR(log,
				  "Conntrack attr type has unexpected length (type=%d, length=%d, expected=%d)",
				  type, nla_len(a), maxlen);
			return -EINVAL;
		}

		switch (type) {
#ifdef CONFIG_NF_CONNTRACK_ZONES
		case OVS_CT_ATTR_ZONE:
			ct_info.zone = nla_get_u16(a);
			break;
#endif
		case OVS_CT_ATTR_FLAGS:
			ct_info.flags = nla_get_u32(a);
			break;
		case OVS_CT_ATTR_HELPER:
			helper = nla_data(a);
			if (!memchr(helper, '\0', nla_len(a))) {
				OVS_NLERR(log, "Invalid conntrack helper");
				return -EINVAL;
			}
			break;
		default:
			OVS_NLERR(log, "Unknown conntrack attr (%d)",
				  type);
			return -EINVAL;
		}
	}

	if (rem > 0) {
		OVS_NLERR(log, "Conntrack attr has %d unknown bytes", rem);
		return -EINVAL;
	}

	if (ct_info.zone || helper) {
		struct nf_conntrack_tuple t;

		memset(&t, 0, sizeof(t));
		ct_info.ct = nf_conntrack_alloc(net, ct_info.zone, &t, &t,
						GFP_KERNEL);
		if (IS_ERR(ct_info.ct)) {
			err = PTR_ERR(ct_info.ct);
			goto err_free_ct;
		}
		if (helper) {
			err = ovs_ct_add_helper(&ct_info, helper, key, log);
			if (err)
				goto err_free_ct;
		}
		nf_conntrack_tmpl_insert(net, ct_info.ct);
	}

	return ovs_nla_add_action(sfa, OVS_ACTION_ATTR_CT, &ct_info,
				  sizeof(ct_info), log);
err_free_ct:
	nf_conntrack_free(ct_info.ct);
	return err;
}

int ovs_ct_action_to_attr(const struct ovs_conntrack_info *ct_info,
			  struct sk_buff *skb)
{
	struct nlattr *start;

	start = nla_nest_start(skb, OVS_ACTION_ATTR_CT);
	if (!start)
		return -EMSGSIZE;

	if (nla_put_u32(skb, OVS_CT_ATTR_FLAGS, ct_info->flags))
		return -EMSGSIZE;
#ifdef CONFIG_NF_CONNTRACK_ZONES
	if (nla_put_u16(skb, OVS_CT_ATTR_ZONE, ct_info->zone))
		return -EMSGSIZE;
#endif
	if (ct_info->helper) {
		if (nla_put_string(skb, OVS_CT_ATTR_HELPER,
				   ct_info->helper->name))
			return -EMSGSIZE;
	}

	nla_nest_end(skb, start);

	return 0;
}

void ovs_ct_free_acts(struct sw_flow_actions *sf_acts)
{
	if (sf_acts) {
		struct ovs_conntrack_info *ct_info;
		struct nlattr *a;
		int rem, len = sf_acts->actions_len;

		for (a = sf_acts->actions, rem = len; rem > 0;
		     a = nla_next(a, &rem)) {
			switch (nla_type(a)) {
			case OVS_ACTION_ATTR_CT:
				ct_info = nla_data(a);
				if (ct_info->helper)
					module_put(ct_info->helper->me);
				if (ct_info->ct)
					nf_ct_put(ct_info->ct);
				break;
			}
		}
	}
}

/* Load connlabel and ensure it supports 128-bit labels */
static struct xt_match *load_connlabel(struct net *net)
{
#ifdef CONFIG_NF_CONNTRACK_LABELS
	struct xt_match *match;
	struct xt_mtchk_param mtpar;
	struct xt_connlabel_mtinfo info;
	int err = -EINVAL;

	match = xt_request_find_match(NFPROTO_UNSPEC, "connlabel", 0);
	if (IS_ERR(match)) {
		match = NULL;
		goto exit;
	}

	info.bit = sizeof(struct ovs_key_conn_label) * 8 - 1;
	info.options = 0;

	mtpar.net	= net;
	mtpar.table	= match->table;
	mtpar.entryinfo = NULL;
	mtpar.match	= match;
	mtpar.matchinfo = &info;
	mtpar.hook_mask = BIT(NF_INET_PRE_ROUTING);
	mtpar.family	= NFPROTO_IPV4;

	err = xt_check_match(&mtpar, XT_ALIGN(match->matchsize), match->proto,
			     0);
	if (err)
		goto exit;

	return match;

exit:
	OVS_NLERR(true, "Failed to set connlabel length");
	if (match)
		module_put(match->me);
#endif
	return NULL;
}

void ovs_ct_init(struct net *net, struct ovs_net *ovs_net)
{
	ovs_net->ct_net.xt_label = load_connlabel(net);
}

void ovs_ct_exit(struct net *net, struct ovs_net *ovs_net)
{
	const struct xt_match *match = ovs_net->ct_net.xt_label;

	if (match) {
		struct xt_mtdtor_param mtd;

		mtd.net = net;
		mtd.match = match;
		mtd.matchinfo = NULL;
		mtd.family = NFPROTO_IPV4;

		module_put(match->me);
		mtd.match->destroy(&mtd);
	}
}

#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0) */
