#ifndef __NET_IVXLAN_WRAPPER_H
#define __NET_IVXLAN_WRAPPER_H  1

enum ivxlan_extension_flags {
	IVXLAN_SPA    = 1 << 0, /* Source Policy Applied */
	IVXLAN_DPA    = 1 << 1, /* Destination Policy Applied */
	IVXLAN_LB     = 1 << 2, /* Load Balancing Enabled */
	IVXLAN_DL     = 1 << 3, /* Don't Learn inner source addr to TEP */
	IVXLAN_FE     = 1 << 4, /* Forwarding exception seen */
	IVXLAN_MCAST  = 1 << 5, /* Multicast Routing Enabled */
	IVXLAN_MARK   = 1 << 6  /* Marker for atomic counters */
};

struct ivxlan_opts {
	__be16 sepg;
	u8     flags;
};

#endif
