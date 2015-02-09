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

#ifndef OVS_CONNTRACK_H
#define OVS_CONNTRACK_H 1

struct ovs_conntrack_info;

int ovs_ct_copy_action(struct net *, const struct nlattr *,
		       const struct sw_flow_key *, struct sw_flow_actions **,
		       bool log);
int ovs_ct_action_to_attr(const struct nlattr *, struct sk_buff *);

int ovs_ct_lookup(struct net *net, u16 zone, struct sk_buff *skb);
int ovs_ct_execute(struct sk_buff *, struct sw_flow_key *,
		   const struct ovs_conntrack_info *);
u8 ovs_ct_get_state(const struct sk_buff *skb);
u16 ovs_ct_get_zone(const struct sk_buff *skb);
u32 ovs_ct_get_mark(struct sk_buff *skb);
int ovs_ct_set_mark(struct sk_buff *, struct sw_flow_key *, u32 conn_mark);
void ovs_ct_free_acts(struct sw_flow_actions *sf_acts);

#endif /* ovs_conntrack.h */
