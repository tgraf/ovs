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
#ifndef __VXLAN_MCAST_H
#define __VXLAN_MCAST_H

#define VXLAN_MCAST_HASH_BITS 10
#define VXLAN_MCAST_HASH_SIZE (1<<VXLAN_MCAST_HASH_BITS)

struct vxlan_mcast_bucket {
        struct hlist_head head;
        spinlock_t lock;
};

struct vxlan_mcast_table {
        atomic_t n_entries;
        struct vxlan_mcast_bucket buckets[VXLAN_MCAST_HASH_SIZE];
};

struct vxlan_mcast_entry {
        struct hlist_node node;
        struct rcu_head rcu;
        u32 hash;
        u32 ip;
        u16 port;
};

int vxlan_mcast_init(struct vxlan_mcast_table *table);
void vxlan_mcast_destroy(struct vxlan_mcast_table *table);
int vxlan_dump_igmp(struct datapath *dp, u16 vxlan_port, u32* buf);
int vxlan_configure_igmp(struct datapath *dp, u16 vxlan_port,
				u8 igmp_cmd, u32 igmp_ip);
#endif
