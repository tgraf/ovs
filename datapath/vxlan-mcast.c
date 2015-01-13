/*
 * Copyright (c) 2015 Cisco Systems, Inc.
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
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rculist.h>
#include <linux/openvswitch.h>
#include <linux/igmp.h>
#include <linux/in.h>
#include <net/vxlan.h>
#include <net/net_namespace.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include "datapath.h"
#include "vxlan-mcast.h"

struct vxlan_sock *vxlan_find_sock(struct net *net, __be16 port);

static struct kmem_cache *vxlan_mcast_cache;

static void init_bucket(struct vxlan_mcast_bucket *bucket)
{
	INIT_HLIST_HEAD(&bucket->head);
	spin_lock_init(&bucket->lock);
}

static struct vxlan_mcast_bucket *
get_bucket(struct vxlan_mcast_table *table, u32 hash)
{
	return &table->buckets[hash % VXLAN_MCAST_HASH_SIZE];
}

static u32 vxlan_mcast_hash(u32 ip, u16 port)
{
	return jhash_2words(ip, (__force u32) port, 0);
}

static struct vxlan_mcast_entry *
vxlan_mcast_find__(struct hlist_head *head, u32 hash, u32 ip, u16 port)
{
	struct vxlan_mcast_entry *e = NULL;

	hlist_for_each_entry_rcu(e, head, node) {
		if (hash == e->hash && ip == e->ip && port == e->port)
		    break;
	}
	return e;
}

/* adds an entry only if one does not exist. returns entry or NULL
 * and an error code in result. */
static struct vxlan_mcast_entry *
vxlan_mcast_add(struct vxlan_mcast_table *table, u32 ip, u16 port, int *result)
{
	u32 hash = vxlan_mcast_hash(ip, port);
	struct vxlan_mcast_bucket *bucket = get_bucket(table, hash);
	struct vxlan_mcast_entry *e;

	spin_lock(&bucket->lock);

	e = vxlan_mcast_find__(&bucket->head, hash, ip, port);
	if (e) {
		*result = -EEXIST;
		goto unlock_exit;
	}

	e = kmem_cache_alloc(vxlan_mcast_cache, GFP_KERNEL);
	if (e) {
		e->hash = hash;
		e->ip = ip;
		e->port = port;
		hlist_add_head_rcu(&e->node, &bucket->head);
		atomic_inc(&table->n_entries);
		*result = 0;
	} else {
		*result = -ENOMEM;
	}

unlock_exit:
	spin_unlock(&bucket->lock);
	return e;
}

static void vxlan_mcast_free(struct rcu_head *head)
{
	struct vxlan_mcast_entry *e;

	e = container_of(head, struct vxlan_mcast_entry, rcu);
	kmem_cache_free(vxlan_mcast_cache, e);
}

static int
vxlan_mcast_delete(struct vxlan_mcast_table *table, u32 ip, u16 port)
{
	u32 hash = vxlan_mcast_hash(ip, port);
	struct vxlan_mcast_bucket *bucket = get_bucket(table, hash);
	struct vxlan_mcast_entry *e;
	int result;

	spin_lock(&bucket->lock);

	e = vxlan_mcast_find__(&bucket->head, hash, ip, port);
	if (e) {
		hlist_del_rcu(&e->node);
		call_rcu(&e->rcu, vxlan_mcast_free);
		atomic_dec(&table->n_entries);
		result = 0;
	} else {
		result = -ENOENT;
	}

	spin_unlock(&bucket->lock);
	return result;
}

int vxlan_mcast_init(struct vxlan_mcast_table *table)
{
	int i;

	atomic_set(&table->n_entries, 0);
	if (vxlan_mcast_cache == NULL)
		vxlan_mcast_cache =
			kmem_cache_create("vxlan_mcast_table",
					  sizeof(struct vxlan_mcast_entry),
					  0, 0, NULL);
	if (vxlan_mcast_cache == NULL)
		return -ENOMEM;

	for (i = 0; i < VXLAN_MCAST_HASH_SIZE; i++) {
		init_bucket(&table->buckets[i]);
	}
	return 0;
}

void vxlan_mcast_destroy(struct vxlan_mcast_table *table)
{
	int i;
	for (i = 0; i < VXLAN_MCAST_HASH_SIZE; i++) {
		struct vxlan_mcast_bucket *bucket = &table->buckets[i];
		struct hlist_node *n;
		struct vxlan_mcast_entry *e;

		spin_lock(&bucket->lock);

		hlist_for_each_entry_safe(e, n, &bucket->head, node) {
			hlist_del_rcu(&e->node);
			call_rcu(&e->rcu, vxlan_mcast_free);
			atomic_dec(&table->n_entries);
		}

		spin_unlock(&bucket->lock);
	}
}

int vxlan_configure_igmp(struct datapath *dp, u16 vxlan_port,
			 u8 igmp_cmd, u32 igmp_ip)
{
	int result;
	struct vxlan_sock *vs;
	struct sock *sk;
	struct ip_mreqn mreq = {
		.imr_multiaddr.s_addr = igmp_ip,
		.imr_ifindex          = 0,
	};

	vs = vxlan_find_sock(dp->net, vxlan_port);
	if (!vs)
		return -EINVAL;
	sk = vs->sock->sk;

	printk(KERN_ERR "cmd %d, vxlan-port %d, ip %x \n",
		igmp_cmd, vxlan_port, igmp_ip);

	if (igmp_cmd == VXLAN_IGMP_CMD_JOIN) {
		vxlan_mcast_add(&dp->vxlan_igmp_table, igmp_ip,
				vxlan_port, &result);
	} else if (igmp_cmd == VXLAN_IGMP_CMD_LEAVE) {
		result = vxlan_mcast_delete(&dp->vxlan_igmp_table,
				igmp_ip, vxlan_port);
	} else {
		return -EINVAL;
	}

	if (result == 0) {
		lock_sock(sk);
		if (igmp_cmd == VXLAN_IGMP_CMD_JOIN) {
			result = ip_mc_join_group(sk, &mreq);
		} else {
			result = ip_mc_leave_group(sk, &mreq);
		}
		release_sock(sk);
	}
	return result;
}

int vxlan_dump_igmp(struct datapath *dp, u16 vxlan_port, u32* buf)
{
	int i, j = 0;
	for (i = 0; i < VXLAN_MCAST_HASH_SIZE; i++) {
		struct vxlan_mcast_bucket *bucket =
			&dp->vxlan_igmp_table.buckets[i];
		struct vxlan_mcast_entry *e;

		hlist_for_each_entry_rcu(e, &bucket->head, node) {
			if (vxlan_port == e->port)
				buf[j++] = e->ip;
			if (j == 1024)
				return j;
		}
	}
	printk(KERN_ERR "count %d, returned %d\n", 
		atomic_read(&dp->vxlan_igmp_table.n_entries), j);
	return j;
}
