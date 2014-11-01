#ifndef __NF_CONNTRACK_WRAPPER_H
#define __NF_CONNTRACK_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/netfilter/nf_conntrack.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
void nf_conntrack_tmpl_insert(struct net *net, struct nf_conn *tmpl);
#endif

#endif /* net/netfilter/nf_conntrack.h */
