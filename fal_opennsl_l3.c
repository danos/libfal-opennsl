/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Note: only a single unit is supported for L3 functionality at the
 * moment.
 */
#include <bsd/sys/tree.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <opennsl/types.h>
#include <opennsl/error.h>
#include <opennsl/l2.h>
#include <opennsl/l3.h>
#include <opennsl/multicast.h>

#include <fal_plugin.h>

#include "pmd/rte_eth_opennslsw.h"
#include "fal_opennsl.h"
#include "fal_opennsl_l3.h"
#include "fal_opennsl_debug.h"

/* Needed for RB_* */
#define __unused __attribute__((unused))

#define FAL_PCM_IP_PFX_LEN (INET6_ADDRSTRLEN + 4 /* "/128" */)
#define FAL_OPENNSL_IP_ADDR_LEN INET6_ADDRSTRLEN

struct fal_opennsl_l3_intf {
	uint32_t ifindex;
	opennsl_if_t l3_intf_id;
	uint32_t vlan;
	RB_ENTRY(fal_opennsl_l3_intf) ifi_link;
	RB_ENTRY(fal_opennsl_l3_intf) vlan_link;
};

struct fal_opennsl_l3_nh;

struct fal_opennsl_l3_neigh {
	uint32_t ifindex;
	struct fal_ip_address_t ipaddr;

	bool sourced;

	/* does this neighbour have forwarding information? */
	bool complete;
	struct ether_addr mac_addr;
	opennsl_if_t encap_id;
	opennsl_gport_t out_gport;

	RB_ENTRY(fal_opennsl_l3_neigh) ifi_addr_link;
	RB_ENTRY(fal_opennsl_l3_neigh) ifi_macaddr_link;
	LIST_HEAD(fal_opennsl_l3_nh_list, fal_opennsl_l3_nh) dep_nh_list;
};

struct fal_opennsl_l3_nh {
	struct fal_opennsl_l3_nh_group *nhg;
	opennsl_if_t fec_id;
	struct fal_opennsl_l3_neigh *neigh;
	LIST_ENTRY(fal_opennsl_l3_nh) neigh_entry;
};

struct fal_opennsl_l3_nh_group {
	uint32_t nh_count;
	opennsl_if_t fec_id;
	struct fal_opennsl_l3_nh **nhs;
};

RB_HEAD(fal_opennsl_l3_intf_tree, fal_opennsl_l3_intf);
RB_HEAD(fal_opennsl_l3_intf_vlan_tree, fal_opennsl_l3_intf);
/* L3 interfaces keyed by ifindex */
static struct fal_opennsl_l3_intf_tree fal_opennsl_l3_intf_tree;
/* L3 interfaces keyed by vlan */
static struct fal_opennsl_l3_intf_vlan_tree fal_opennsl_l3_intf_vlan_tree;

RB_HEAD(fal_opennsl_l3_neigh_ifi_addr_tree, fal_opennsl_l3_neigh);
RB_HEAD(fal_opennsl_l3_neigh_ifi_macaddr_tree, fal_opennsl_l3_neigh);
static struct fal_opennsl_l3_neigh_ifi_addr_tree fal_opennsl_l3_neigh_ifi_addr_tree;
static struct fal_opennsl_l3_neigh_ifi_macaddr_tree
	fal_opennsl_l3_neigh_ifi_macaddr_tree;

/* For all traffic that the FAL has asked us to trap */
static int fal_opennsl_l3_trap_id;

/* FEC for blackholing traffic */
static opennsl_if_t fal_opennsl_l3_black_hole_fec_id;
/* FEC for trapping for unspecified reason */
static opennsl_if_t fal_opennsl_l3_trap_fec_id;

/*
 * Mutex protecting reads and writes to L3 neighbours, next-hops and
 * next-hop groups.
 */
static pthread_mutex_t fal_opennsl_l3_lock;

static int
fal_opennsl_update_forward_fec(struct fal_opennsl_l3_nh *nh);

static char *fal_opennsl_ip_addr2a(char *buf, size_t buf_size,
			       const struct fal_ip_address_t *ipaddr)
{
	buf[0] = '\0';
	switch (ipaddr->addr_family) {
	case FAL_IP_ADDR_FAMILY_IPV4:
		inet_ntop(AF_INET, &ipaddr->addr, buf, buf_size);
		break;
	case FAL_IP_ADDR_FAMILY_IPV6:
		inet_ntop(AF_INET6, &ipaddr->addr, buf, buf_size);
		break;
	}
	return buf;
}

static char *fal_opennsl_ip_pfx2a(char *buf, size_t buf_size,
			      const struct fal_ip_address_t *ipaddr,
			      uint8_t prefixlen)
{
	fal_opennsl_ip_addr2a(buf, buf_size, ipaddr);
	snprintf(buf + strlen(buf), buf_size - strlen(buf), "/%d",
		 prefixlen);
	return buf;
}

static int fal_ip_addr_cmp(const struct fal_ip_address_t *ipaddr1,
			   const struct fal_ip_address_t *ipaddr2)
{
	if (ipaddr1->addr_family > ipaddr2->addr_family)
		return 1;
	else if (ipaddr1->addr_family < ipaddr2->addr_family)
		return -1;
	switch (ipaddr1->addr_family) {
	case FAL_IP_ADDR_FAMILY_IPV4:
		return memcmp(&ipaddr1->addr.ip4, &ipaddr2->addr.ip4,
			      sizeof(ipaddr1->addr.ip4));
	case FAL_IP_ADDR_FAMILY_IPV6:
		return memcmp(&ipaddr1->addr.ip6, &ipaddr2->addr.ip6,
			      sizeof(ipaddr1->addr.ip6));
	}
	return 0;
}

struct fal_opennsl_l3_encap_param {
	uint32_t flags;
	uint32_t flags2;

	int vlan;
	opennsl_mac_t nh_mac;
	int qos_map_id;
	opennsl_if_t tunnel_rif;
};

struct fal_opennsl_l3_fec_param {
	uint32_t flags;
	uint32_t flags2;

	opennsl_if_t rif;
	opennsl_gport_t out_gport;
	opennsl_failover_t failover_id;
	opennsl_if_t failover_if_id;

	opennsl_if_t encap_id;
};

/*
 * Wrapper around opennsl_l3_egress_create to only expose fields related
 * to encap object create
 */
static int fal_opennsl_create_l3_encap_create(
	int unit, uint32_t allocation_flags,
	const struct fal_opennsl_l3_encap_param *l3_enc, opennsl_if_t *id)
{
	/* parameter used on ingress object create only */
	opennsl_if_t l3_ing_only_ignore;
	opennsl_l3_egress_t l3eg;
	int rc;

	opennsl_l3_egress_t_init(&l3eg);

	l3eg.flags = l3_enc->flags;
	l3eg.flags2 = l3_enc->flags2;
	memcpy(&l3eg.mac_addr, l3_enc->nh_mac, sizeof(l3eg.mac_addr));
	l3eg.vlan = l3_enc->vlan;
	l3eg.qos_map_id = l3_enc->qos_map_id;
	l3eg.intf = l3_enc->tunnel_rif;

	if (allocation_flags & (OPENNSL_L3_WITH_ID | OPENNSL_L3_REPLACE))
		l3eg.encap_id = *id;

	rc = opennsl_l3_egress_create(unit, OPENNSL_L3_EGRESS_ONLY | allocation_flags,
				  &l3eg, &l3_ing_only_ignore);
	if (OPENNSL_SUCCESS(rc))
		*id = l3eg.encap_id;

	return rc;
}

static int fal_opennsl_destroy_l3_encap(int unit, opennsl_if_t encap_id)
{
	return opennsl_l3_egress_destroy(unit, encap_id);
}

/*
 * Wrapper around opennsl_l3_egress_create to only expose fields related
 * to FEC object create
 */
static int fal_opennsl_create_l3_fec(
	int unit, uint32_t allocation_flags,
	const struct fal_opennsl_l3_fec_param *l3_fec, opennsl_if_t *id)
{
	uint32_t mod_alloc_flags = allocation_flags;
	opennsl_l3_egress_t l3eg;
	int ret;

	opennsl_l3_egress_t_init(&l3eg);

	if (!(allocation_flags & OPENNSL_L3_WITH_ID)) {
		ret = fal_opennsl_pre_alloc_res(
			unit, FAL_OPENNSL_RES_FEC, 1, id,
			&mod_alloc_flags);
		if (ret < 0)
			return OPENNSL_E_FULL;
	}

	if (mod_alloc_flags & OPENNSL_L3_WITH_ID) {
		INFO("%s - fec 0x%x\n", __func__, *id);
	}

	l3eg.flags = l3_fec->flags;
	l3eg.flags2 = l3_fec->flags2;
	l3eg.intf = l3_fec->rif;
	l3eg.port = l3_fec->out_gport;
	l3eg.reserved9 = l3_fec->failover_id;
	l3eg.reserved10 = l3_fec->failover_if_id;
	l3eg.encap_id = l3_fec->encap_id;

	ret = opennsl_l3_egress_create(unit,
				   OPENNSL_L3_INGRESS_ONLY | mod_alloc_flags,
				   &l3eg, id);
	if (OPENNSL_FAILURE(ret) &&
	    !(allocation_flags & OPENNSL_L3_WITH_ID))
		fal_opennsl_pre_alloc_res_free(
			unit, FAL_OPENNSL_RES_FEC, *id);

	return ret;
}

static int fal_opennsl_destroy_l3_fec(int unit, opennsl_if_t fec_id)
{
	int first_unit = 0;
	int ret;

	if (unit == first_unit) {
		ret = fal_opennsl_pre_alloc_res_free(
			first_unit, FAL_OPENNSL_RES_FEC, fec_id);
		if (ret < 0)
			return OPENNSL_E_NOT_FOUND;
	}

	return opennsl_l3_egress_destroy(unit, fec_id);
}

static int fal_opennsl_l3_intf_ifi_cmp(const struct fal_opennsl_l3_intf *if1,
				   const struct fal_opennsl_l3_intf *if2)
{
	return if1->ifindex - if2->ifindex;
}

static int fal_opennsl_l3_intf_vlan_cmp(const struct fal_opennsl_l3_intf *if1,
				    const struct fal_opennsl_l3_intf *if2)
{
	return if1->vlan - if2->vlan;
}

/* Generate internal functions and make them static. */
RB_GENERATE_STATIC(fal_opennsl_l3_intf_tree, fal_opennsl_l3_intf, ifi_link,
		   fal_opennsl_l3_intf_ifi_cmp)
RB_GENERATE_STATIC(fal_opennsl_l3_intf_vlan_tree, fal_opennsl_l3_intf, vlan_link,
		   fal_opennsl_l3_intf_vlan_cmp)

/*
 * Create an L3 interface and add it to the L3 intf tree
 */
static int
fal_opennsl_new_l3_intf(uint32_t ifindex, uint32_t parent_ifindex,
			uint16_t vlan, const struct ether_addr *mac_addr,
			uint32_t vrf, uint16_t mtu, fal_object_t *obj)
{
	opennsl_rx_mtu_config_t rif_mtu_cfg;
	struct fal_opennsl_l3_intf *intf;
	struct fal_opennsl_l3_intf *old;
	opennsl_l2_station_t station;
	opennsl_l3_intf_t l3_intf;
	int station_id;
	int unit = 0;
	char buf[32];
	int ret;
	int rv;

	fal_opennsl_create_vlan(unit, vlan);

	intf = malloc(sizeof(*intf));
	if (!intf)
		return -ENOMEM;

	ether_format_addr(buf, sizeof(buf), mac_addr);
	INFO("%s(%d, %d, %d, %s, %d, %d)\n",
	     __func__, ifindex, parent_ifindex, vlan,
	     buf, vrf, mtu);

	opennsl_l2_station_t_init(&station);
	memcpy(&station.dst_mac, mac_addr, sizeof(station.dst_mac));
	memset(&station.dst_mac_mask, 0xff, sizeof(station.dst_mac_mask));
	station.src_port = 0; /* global my-mac */
	station.src_port_mask = 0; /* global my-mac */
	/*
	 * Request setting of vlan-wide my-mac, not per-vlan
	 * my-mac. We don't allow the setting of mac addresses on VIFs,
	 * but even if we did there would be the restriction that we only
	 * allow setting the 12 LSBs which would be hard to model in the
	 * config. So don't even try to allow this.
	 */
	station.vlan_mask = 0;
	station.flags = 0;
	rv = opennsl_l2_station_add(unit, &station_id, &station);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to add L2 station MAC: %s\n",
		      opennsl_errmsg(rv));
		ret = -ENOSPC;
		goto error;
	}

	opennsl_l3_intf_t_init(&l3_intf);
	l3_intf.l3a_vid = vlan;
	l3_intf.l3a_vrf = vrf;
	l3_intf.l3a_ttl = 255;
	l3_intf.l3a_mtu = 0;
	memcpy(&l3_intf.l3a_mac_addr, mac_addr, sizeof(*mac_addr));

	rv = opennsl_l3_intf_create(unit, &l3_intf);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to create L3 intf for %d: %s\n", ifindex,
		      opennsl_errmsg(rv));
		ret = -ENOSPC;
		goto error;
	}

	INFO("Created L3 intf %d for ifindex %d\n", l3_intf.l3a_intf_id,
	     ifindex);

	/*
	 * Use RX MTU in preference to L3 interface MTU as the latter
	 * applies to a VSI, regardless of whether traffic is being L2
	 * switched or L3 forwarded, whereas the former applies to when
	 * the L3 interface is just being used for forwarding.
	 */
	memset(&rif_mtu_cfg, 0, sizeof(rif_mtu_cfg));
	rif_mtu_cfg.flags = OPENNSL_RX_MTU_RIF;
	rif_mtu_cfg.intf = l3_intf.l3a_intf_id;
	rif_mtu_cfg.mtu = mtu;
	rv = opennsl_rx_mtu_set(unit, &rif_mtu_cfg);
	if (OPENNSL_FAILURE(rv) && rv != OPENNSL_E_UNAVAIL) {
		ERROR("Failed to set L3 MTU for %d: %s\n", ifindex,
		      opennsl_errmsg(rv));
		ret = -ENOSPC;
		goto l3_intf_del;
	}

	intf->ifindex = ifindex;
	intf->vlan = vlan;
	intf->l3_intf_id = l3_intf.l3a_intf_id;

	ret = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (ret) {
		ERROR("%s: unable to acquire L3 lock\n", __func__);
		goto l3_intf_del;
	}

	old = RB_INSERT(fal_opennsl_l3_intf_tree, &fal_opennsl_l3_intf_tree,
			intf);
	if (old)
		ERROR("L3 intf %d already exists for ifindex %d\n",
		      old->l3_intf_id, old->ifindex);

	old = RB_INSERT(fal_opennsl_l3_intf_vlan_tree,
			&fal_opennsl_l3_intf_vlan_tree, intf);
	if (old)
		ERROR("L3 intf %d already exists for vlan %d\n",
		      old->l3_intf_id, old->vlan);

	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	*obj = (uintptr_t)(old ? old : intf);

	return 0;

l3_intf_del:
	opennsl_l3_intf_delete(unit, &l3_intf);
error:
	free(intf);
	return ret;
}

static int
fal_opennsl_lookup_l3_intf_info(uint32_t ifindex, opennsl_if_t *l3_intf_id,
			    uint32_t *vlan)
{
	struct fal_opennsl_l3_intf k = {
		.ifindex = ifindex,
	};
	struct fal_opennsl_l3_intf *entry;

	entry = RB_FIND(fal_opennsl_l3_intf_tree, &fal_opennsl_l3_intf_tree,
			&k);
	if (!entry)
		return -ENOENT;

	*l3_intf_id = entry->l3_intf_id;
	*vlan = entry->vlan;
	return 0;
}

static int
fal_opennsl_lookup_l3_intf_by_vlan(uint32_t vlan,
			       struct fal_opennsl_l3_intf **entry)
{
	struct fal_opennsl_l3_intf k = {
		.vlan = vlan,
	};

	*entry = RB_FIND(fal_opennsl_l3_intf_vlan_tree,
			 &fal_opennsl_l3_intf_vlan_tree, &k);
	return *entry ? 0 : -ENOENT;
}

static int
fal_opennsl_upd_l3_intf_vlan(struct fal_opennsl_l3_intf *entry, uint32_t vlan)
{
	ERROR("%s: Updating interface %d vlan to %d not implemented\n",
	      __func__, entry->ifindex, vlan);

	return 0;
}

static int
fal_opennsl_upd_l3_intf_vrf(struct fal_opennsl_l3_intf *entry, uint32_t vrf)
{
	opennsl_l3_intf_t l3_intf;
	int unit = 0;
	int rv;

	opennsl_l3_intf_t_init(&l3_intf);
	l3_intf.l3a_intf_id = entry->l3_intf_id;
	rv = opennsl_l3_intf_get(unit, &l3_intf);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: Failed to get L3 intf for %d: %s\n",
		      __func__, entry->ifindex, opennsl_errmsg(rv));
		return -ENOENT;
	}

	l3_intf.l3a_flags |= OPENNSL_L3_REPLACE | OPENNSL_L3_WITH_ID;
	l3_intf.l3a_vrf = vrf;
	rv = opennsl_l3_intf_create(unit, &l3_intf);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: Failed to update L3 intf for %d: %s\n",
		      __func__, entry->ifindex, opennsl_errmsg(rv));
		return -ENOSPC;
	}

	return 0;
}

static int
fal_opennsl_upd_l3_intf_mtu(struct fal_opennsl_l3_intf *entry, uint32_t mtu)
{
	opennsl_rx_mtu_config_t rif_mtu_cfg;
	int unit = 0;
	int rv;

	memset(&rif_mtu_cfg, 0, sizeof(rif_mtu_cfg));
	rif_mtu_cfg.flags = OPENNSL_RX_MTU_RIF;
	rif_mtu_cfg.intf = entry->l3_intf_id;
	rif_mtu_cfg.mtu = mtu;
	rv = opennsl_rx_mtu_set(unit, &rif_mtu_cfg);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to set L3 MTU for %d: %s\n",
		      entry->ifindex, opennsl_errmsg(rv));
		return -ENOSPC;
	}

	return 0;
}

static int
fal_opennsl_upd_l3_intf_mac_addr(struct fal_opennsl_l3_intf *entry,
				 const struct ether_addr *mac)
{
	ERROR("%s: Updating interface %d mac address not implemented\n",
	      __func__, entry->ifindex);

	return 0;
}

/*
 * Delete an L3 interface and remove it from the L3 intf tree
 */
static int
fal_opennsl_del_l3_intf(struct fal_opennsl_l3_intf *entry)
{
	opennsl_l3_intf_t l3_intf;
	int unit = 0;
	int ret;
	int rv;

	ret = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (ret) {
		ERROR("%s: unable to acquire L3 lock\n", __func__);
		return ret;
	}

	opennsl_l3_intf_t_init(&l3_intf);
	l3_intf.l3a_intf_id = entry->l3_intf_id;
	rv = opennsl_l3_intf_delete(unit, &l3_intf);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to delete L3 interface %d with id 0x%x: %s\n",
		      entry->ifindex, entry->l3_intf_id, opennsl_errmsg(rv));
		ret = -EINVAL;
		goto unlock;
	}

	RB_REMOVE(fal_opennsl_l3_intf_vlan_tree,
		  &fal_opennsl_l3_intf_vlan_tree, entry);
	RB_REMOVE(fal_opennsl_l3_intf_tree, &fal_opennsl_l3_intf_tree, entry);
	free(entry);

unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	return ret;
}

static int fal_opennsl_l3_neigh_ifi_addr_cmp(
	const struct fal_opennsl_l3_neigh *n1,
	const struct fal_opennsl_l3_neigh *n2)
{
	if (n1->ifindex > n2->ifindex)
		return 1;
	else if (n1->ifindex < n2->ifindex)
		return -1;
	return fal_ip_addr_cmp(&n1->ipaddr, &n2->ipaddr);
}

/* Generate internal functions and make them static. */
RB_GENERATE_STATIC(fal_opennsl_l3_neigh_ifi_addr_tree, fal_opennsl_l3_neigh,
		   ifi_addr_link, fal_opennsl_l3_neigh_ifi_addr_cmp)

static int fal_opennsl_l3_neigh_ifi_macaddr_cmp(
	const struct fal_opennsl_l3_neigh *n1,
	const struct fal_opennsl_l3_neigh *n2)
{
	int ret;

	if (n1->ifindex > n2->ifindex)
		return 1;
	else if (n1->ifindex < n2->ifindex)
		return -1;

	ret = memcmp(&n1->mac_addr, &n2->mac_addr, sizeof(n1->mac_addr));
	if (ret)
		return ret;

	/*
	 * Include the IP address in the key just for uniqueness - a
	 * full lookup won't be done, but it allows a subtree walk to
	 * be done.
	 */
	return fal_ip_addr_cmp(&n1->ipaddr, &n2->ipaddr);
}

/* Generate internal functions and make them static. */
RB_GENERATE_STATIC(fal_opennsl_l3_neigh_ifi_macaddr_tree, fal_opennsl_l3_neigh,
		   ifi_macaddr_link, fal_opennsl_l3_neigh_ifi_macaddr_cmp)

static int
fal_opennsl_lookup_l3_neigh(uint32_t ifindex,
			const struct fal_ip_address_t *ipaddr,
			struct fal_opennsl_l3_neigh **entry)
{
	struct fal_opennsl_l3_neigh k = {
		.ifindex = ifindex,
		.ipaddr = *ipaddr,
	};
	char buf[FAL_OPENNSL_IP_ADDR_LEN];

	INFO("%s(ifindex %d, %s, ...)\n",
	     __func__, ifindex,
	     fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr));

	*entry = RB_FIND(fal_opennsl_l3_neigh_ifi_addr_tree,
			 &fal_opennsl_l3_neigh_ifi_addr_tree, &k);
	INFO("%s got entry %p for %s\n", __func__, *entry,
		 fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr));
	return *entry ? 0 : -ENOENT;
}

static int
fal_opennsl_insert_l3_neigh(uint32_t ifindex,
			const struct fal_ip_address_t *ipaddr,
			struct fal_opennsl_l3_neigh **neigh)
{
	struct fal_opennsl_l3_neigh *old;
	char buf[FAL_OPENNSL_IP_ADDR_LEN];

	INFO("%s(ifindex %d, %s, ...)\n",
	     __func__, ifindex,
	     fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr));

	*neigh = malloc(sizeof(**neigh));
	if (!*neigh)
		return -ENOMEM;

	(*neigh)->ifindex = ifindex;
	(*neigh)->ipaddr = *ipaddr;
	(*neigh)->complete = false;
	(*neigh)->sourced = false;
	LIST_INIT(&(*neigh)->dep_nh_list);

	old = RB_INSERT(fal_opennsl_l3_neigh_ifi_addr_tree,
			&fal_opennsl_l3_neigh_ifi_addr_tree, *neigh);
	/*
	 * We'd better not be overriding a previous entry, otherwise
	 * we're going to lose the linkages with the NHs.
	 */
	if (old)
		ERROR("%s: duplicate neighbour\n", __func__);

	return 0;
}

static void
fal_opennsl_delete_l3_neigh(struct fal_opennsl_l3_neigh *neigh)
{
	int unit = 0;

	RB_REMOVE(fal_opennsl_l3_neigh_ifi_addr_tree,
		  &fal_opennsl_l3_neigh_ifi_addr_tree, neigh);

	if (neigh->complete) {
		if (OPENNSL_GPORT_IS_MCAST(neigh->out_gport))
			opennsl_multicast_destroy(
				0, OPENNSL_GPORT_MCAST_GET(neigh->out_gport));
		fal_opennsl_destroy_l3_encap(unit, neigh->encap_id);
	}

	free(neigh);
}

static void
fal_opennsl_delete_l3_neigh_if_unused(struct fal_opennsl_l3_neigh *neigh)
{
	if (LIST_EMPTY(&neigh->dep_nh_list) && !neigh->sourced)
		fal_opennsl_delete_l3_neigh(neigh);
}

/*
 * Make an ingress-only copy of the flood group, adding in the MAC
 * address encap for each member.
 */
static int
fal_opennsl_l3_flood_for_nh(int unit, opennsl_multicast_t flood_group,
			opennsl_if_t mac_encap,
			opennsl_multicast_t *mac_flood_group)
{
	opennsl_multicast_replication_t *rep_array;
	uint32_t mcast_flags;
	int count;
	int rv;
	int i;

	/* get number of member of flood group */
	rv = opennsl_multicast_get(unit, flood_group, 0, 0, NULL, &count);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("opennsl_multicast_get: %s\n", opennsl_errmsg(rv));
		return -EINVAL;
	}
	rep_array = calloc(count, sizeof(*rep_array));
	if (!rep_array) {
		ERROR("%s: out of memory\n", __func__);
		return -ENOMEM;
	}

	/* get contents of members of flood group */
	rv = opennsl_multicast_get(unit, flood_group, 0, count, rep_array, &count);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("opennsl_multicast_get: %s\n", opennsl_errmsg(rv));
		free(rep_array);
		return -EINVAL;
	}

	mcast_flags = OPENNSL_MULTICAST_INGRESS_GROUP |
		OPENNSL_MULTICAST_TYPE_L2;

	/* Pre-allocate an ID in case SDK allocation not supported */
	rv = fal_opennsl_pre_alloc_res(
		unit, FAL_OPENNSL_RES_MCAST, 1,
		mac_flood_group, &mcast_flags);
	if (rv < 0)
		return rv;

	rv = opennsl_multicast_create(
		unit, mcast_flags,
		mac_flood_group);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("opennsl_multicast_create: %s\n", opennsl_errmsg(rv));
		free(rep_array);
		return -ENOSPC;
	}

	/*
	 * Add each member since opennsl_multicast_add with multiple
	 * members isn't supported on DNX.
	 */
	for (i = 0; i < count; i++) {
		rv = opennsl_multicast_ingress_add(
			unit, *mac_flood_group,
			rep_array[i].port, OPENNSL_L3_ITF_VAL_GET(mac_encap));
		if (OPENNSL_FAILURE(rv)) {
			ERROR("opennsl_multicast_ingress_add: %s\n",
			      opennsl_errmsg(rv));
			free(rep_array);
			fal_opennsl_pre_alloc_res_free(
				unit, FAL_OPENNSL_RES_MCAST,
				*mac_flood_group);
			opennsl_multicast_destroy(unit, *mac_flood_group);
			*mac_flood_group = 0;
			return rv;
		}
	}
	free(rep_array);

	return 0;
}

/*
 * Update the port for an L3 neighbour
 *
 * The physical outport is needed for FEC programming, so get it
 * here. If the mapping from L2 mac to {vlan, outport} is known then
 * that is the port used. Otherwise, we need to flood to the vlan
 * using a multicast gport.
 */
static int
fal_opennsl_l3_neigh_update_port(
	int unit, struct fal_opennsl_l3_neigh *neigh)
{
	char buf[FAL_OPENNSL_IP_ADDR_LEN];
	opennsl_if_t l3_intf;
	char namebuf[64];
	opennsl_port_t port;
	bool is_static;
	uint32_t vlan;
	int rv;

	rv = fal_opennsl_lookup_l3_intf_info(neigh->ifindex, &l3_intf, &vlan);
	if (rv < 0) {
		ERROR("not l3 intf %d for nh %s\n", neigh->ifindex,
		      fal_opennsl_ip_addr2a(buf, sizeof(buf), &neigh->ipaddr));
		return 0;
	}

	rv = fal_opennsl_lookup_l2_addr(unit, vlan, &neigh->mac_addr,
				    &port, &is_static);
	if (OPENNSL_FAILURE(rv)) {
		char eth_buf[32];
		opennsl_multicast_t ucast_flood_group;
		opennsl_multicast_t mac_ucast_flood_group;

		/* No port for MAC + VLAN, so need to flood */

		rv = fal_opennsl_vlan_get_ucast_flood_group(unit, vlan,
							&ucast_flood_group);
		if (OPENNSL_FAILURE(rv)) {
			ERROR("unable to get ucast flood group for vlan %d\n",
			      vlan);
			return -ENOENT;
		}

		/*
		 * create a copy of the ucast flood group, adding in
		 * the encap to use as the destination MAC address by
		 * specifying it as the multicast CUD for each member.
		 */
		rv = fal_opennsl_l3_flood_for_nh(
			unit, ucast_flood_group, neigh->encap_id,
			&mac_ucast_flood_group);
		if (rv < 0)
			return rv;
		OPENNSL_GPORT_MCAST_SET(neigh->out_gport, mac_ucast_flood_group);

		ether_format_addr(eth_buf, sizeof(eth_buf), &neigh->mac_addr);
		INFO("no port for neighbour %s intf %d (MAC %s vlan %d) - flooding to 0x%x\n",
		     fal_opennsl_ip_addr2a(buf, sizeof(buf), &neigh->ipaddr),
		     neigh->ifindex, eth_buf, vlan, neigh->out_gport);
		return 0;
	}

	INFO("updating l3 neighbour %s intf %d to use port %s (0x%x)\n",
	     fal_opennsl_ip_addr2a(buf, sizeof(buf), &neigh->ipaddr),
	     neigh->ifindex,
	     fal_opennsl_get_gport_name(unit, port, namebuf, sizeof(namebuf)),
	     port);

	neigh->out_gport = port;
	return 0;
}

/*
 * Update any dependencies of the L3 neighbour
 */
static void
fal_opennsl_l3_neigh_update_deps(struct fal_opennsl_l3_neigh *neigh)
{
	struct fal_opennsl_l3_nh *nh;

	LIST_FOREACH(nh, &neigh->dep_nh_list, neigh_entry)
		fal_opennsl_update_forward_fec(nh);
}

/*
 * Update output port of L3 neighbour, notifying dependencies
 */
static int
fal_opennsl_l3_neigh_update_port_w_deps(struct fal_opennsl_l3_neigh *neigh)
{
	bool was_complete = false;
	opennsl_gport_t old_gport = 0;
	int unit = 0;
	int rv;

	if (neigh->complete) {
		was_complete = true;
		old_gport = neigh->out_gport;
	}

	rv = fal_opennsl_l3_neigh_update_port(unit, neigh);
	if (rv < 0)
		return rv;

	neigh->complete = true;

	fal_opennsl_l3_neigh_update_deps(neigh);

	/*
	 * Wait until NHs have stopped using the encap/mcast group
	 * before freeing.
	 */
	if (was_complete) {
		if (OPENNSL_GPORT_IS_MCAST(old_gport)) {
			fal_opennsl_pre_alloc_res_free(
				unit, FAL_OPENNSL_RES_MCAST,
				OPENNSL_GPORT_MCAST_GET(old_gport));
			opennsl_multicast_destroy(
				unit, OPENNSL_GPORT_MCAST_GET(old_gport));
		}
	}

	return 0;
}

/*
 * Set the mac address for a neighbour
 *
 * This makes the neighbour complete, if it wasn't before. Triggers
 * updates of any dependencies.
 */
static int
fal_opennsl_set_l3_neigh_mac(struct fal_opennsl_l3_neigh *neigh,
			 const struct ether_addr *mac_addr)
{
	struct fal_opennsl_l3_encap_param l3_enc = { 0 };
	struct fal_opennsl_l3_neigh *old;
	bool was_complete = false;
	opennsl_if_t old_encap_id = 0;
	opennsl_if_t encap_id;
	int unit = 0;
	int rv;

	memcpy(&l3_enc.nh_mac, mac_addr, sizeof(l3_enc.nh_mac));

	rv = fal_opennsl_create_l3_encap_create(unit, 0, &l3_enc, &encap_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("failed to create encap object: %s\n", opennsl_errmsg(rv));
		return -ENOSPC;
	}

	INFO("encap_id = 0x%x\n", encap_id);

	if (neigh->complete) {
		was_complete = true;
		old_encap_id = neigh->encap_id;
		RB_REMOVE(fal_opennsl_l3_neigh_ifi_macaddr_tree,
			  &fal_opennsl_l3_neigh_ifi_macaddr_tree, neigh);
	}

	neigh->mac_addr = *mac_addr;
	old = RB_INSERT(fal_opennsl_l3_neigh_ifi_macaddr_tree,
			&fal_opennsl_l3_neigh_ifi_macaddr_tree, neigh);
	if (old)
		ERROR("duplicate neighbour %p for ifindex, macaddr, ipaddr in tree\n",
		      old);
	neigh->encap_id = encap_id;

	rv = fal_opennsl_l3_neigh_update_port_w_deps(neigh);
	if (rv < 0) {
		neigh->encap_id = old_encap_id;
		fal_opennsl_destroy_l3_encap(unit, encap_id);
		return rv;
	}

	if (was_complete)
		fal_opennsl_destroy_l3_encap(unit, old_encap_id);

	return 0;
}

static int
fal_opennsl_unset_l3_neigh_mac(struct fal_opennsl_l3_neigh *neigh)
{
	opennsl_if_t old_encap_id;
	opennsl_gport_t old_gport;
	int unit = 0;
	int rv;

	if (!neigh->complete)
		return 0;

	RB_REMOVE(fal_opennsl_l3_neigh_ifi_macaddr_tree,
		  &fal_opennsl_l3_neigh_ifi_macaddr_tree, neigh);

	old_encap_id = neigh->encap_id;
	old_gport = neigh->out_gport;
	memset(&neigh->mac_addr, 0, sizeof(neigh->mac_addr));
	neigh->encap_id = 0;
	neigh->out_gport = 0;
	neigh->complete = false;

	fal_opennsl_l3_neigh_update_deps(neigh);

	/*
	 * Wait until NHs have stopped using the encap/mcast group
	 * before freeing.
	 */
	if (OPENNSL_GPORT_IS_MCAST(old_gport)) {
		rv = opennsl_multicast_destroy(
			unit, OPENNSL_GPORT_MCAST_GET(old_gport));
		if (OPENNSL_FAILURE(rv)) {
			ERROR("%s: failed to delete multicast group: %s\n",
			      __func__, opennsl_errmsg(rv));
			return -EINVAL;
		}
	}
	rv = fal_opennsl_destroy_l3_encap(unit, old_encap_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: failed to delete L3 encap: %s\n",
		      __func__, opennsl_errmsg(rv));
		return -EINVAL;
	}

	return 0;
}

/*
 * Notification that a change to an L2 address has occurred
 *
 * Note: this function is not called from the dataplane master thread,
 * but instead is called from a separate OPENNSL thread. Therefore steps
 * must be taken to ensure reads/writes to state shared with the
 * dataplane master thread be done in a thread-safe manner.
 */
static void
fal_opennsl_l3_neigh_l2_addr_cb(int unit, opennsl_l2_addr_t *info,
			    int operation, void *userdata)
{
	struct fal_opennsl_l3_neigh *neigh_next;
	struct fal_opennsl_l3_neigh *neigh;
	struct fal_opennsl_l3_intf *intf;
	char buf[32];
	int ret;

	switch (operation) {
	case OPENNSL_L2_CALLBACK_ADD:
	case OPENNSL_L2_CALLBACK_DELETE:
	case OPENNSL_L2_CALLBACK_LEARN_EVENT:
	case OPENNSL_L2_CALLBACK_MOVE_EVENT:
	case OPENNSL_L2_CALLBACK_AGE_EVENT:
		break;
	default:
		return;
	}

	ether_format_addr(buf, sizeof(buf),
			  (struct ether_addr *)&info->mac);
	INFO("%s: MAC=%s VLAN=%d port=0x%x flags=0x%x operation=%d\n",
	     __func__, buf, info->vid, info->port, info->flags,
	     operation);

	ret = fal_opennsl_lookup_l3_intf_by_vlan(info->vid, &intf);
	if (ret < 0) {
		INFO("%s: No L3 interface for vlan %d - nothing to do\n",
		     __func__, info->vid);
		return;
	}

	struct fal_opennsl_l3_neigh neigh_template = {
		.ifindex = intf->ifindex,
	};
	memcpy(&neigh_template.mac_addr, &info->mac,
	       sizeof(neigh_template.mac_addr));

	ret = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (ret) {
		ERROR("%s: unable to acquire L3 lock\n", __func__);
		return;
	}

	neigh_next = RB_NFIND(fal_opennsl_l3_neigh_ifi_macaddr_tree,
			      &fal_opennsl_l3_neigh_ifi_macaddr_tree,
			      &neigh_template);
	RB_FOREACH_FROM(neigh, fal_opennsl_l3_neigh_ifi_macaddr_tree,
			neigh_next) {
		if (neigh->ifindex != intf->ifindex ||
		    memcmp(&info->mac, &neigh->mac_addr,
			   sizeof(neigh->mac_addr)))
			break;

		INFO("updating neigh %p\n", neigh);
		fal_opennsl_l3_neigh_update_port_w_deps(neigh);
	}

	pthread_mutex_unlock(&fal_opennsl_l3_lock);
}

/*
 * Update attributes of a router interface (RIF)
 */

int fal_plugin_create_router_interface(uint32_t attr_count,
				       struct fal_attribute_t *attr_list,
				       fal_object_t *obj)
{
	const struct ether_addr *mac_addr = NULL;
	uint32_t parent_ifindex = 0;
	uint32_t if_index = 0;
	uint16_t vlan = 0;
	uint32_t vrf = 0;
	uint32_t mtu = 0;
	uint i;

	if (!l3_support)
		return -EOPNOTSUPP;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_ROUTER_INTERFACE_ATTR_IFINDEX:
			if_index = attr_list[i].value.u32;
			break;
		case FAL_ROUTER_INTERFACE_ATTR_PARENT_IFINDEX:
			parent_ifindex = attr_list[i].value.u32;
			break;
		case FAL_ROUTER_INTERFACE_ATTR_VLAN_ID:
			vlan = attr_list[i].value.u16;
			break;
		case FAL_ROUTER_INTERFACE_ATTR_VRF_ID:
			vrf = attr_list[i].value.u32;
			break;
		case FAL_ROUTER_INTERFACE_ATTR_MTU:
			mtu = attr_list[i].value.u16;
			break;
		case FAL_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
			mac_addr = &attr_list[i].value.mac;
			break;
		default:
			/* not used */
			break;
		}
	}
	return fal_opennsl_new_l3_intf(if_index, parent_ifindex, vlan,
				   mac_addr, vrf, mtu, obj);
}

int fal_plugin_delete_router_interface(fal_object_t obj)
{
	struct fal_opennsl_l3_intf *intf = (struct fal_opennsl_l3_intf *)obj;

	return fal_opennsl_del_l3_intf(intf);
}

int fal_plugin_set_router_interface_attr(fal_object_t obj,
					 const struct fal_attribute_t *attr)
{
	struct fal_opennsl_l3_intf *intf = (struct fal_opennsl_l3_intf *)obj;
	uint32_t attr_id = attr->id;
	int ret;

	ret = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (ret) {
		ERROR("%s: unable to acquire L3 lock\n", __func__);
		return ret;
	}

	switch (attr_id) {
	case FAL_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
	case FAL_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
	case FAL_ROUTER_INTERFACE_ATTR_ADMIN_MPLS_STATE:
	case FAL_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE:
	case FAL_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE:
		/* not supported by OpenNSL */
		break;
	case FAL_ROUTER_INTERFACE_ATTR_VLAN_ID:
		ret = fal_opennsl_upd_l3_intf_vlan(intf, attr->value.u16);
		goto unlock;
	case FAL_ROUTER_INTERFACE_ATTR_VRF_ID:
		ret = fal_opennsl_upd_l3_intf_vrf(intf, attr->value.u32);
		goto unlock;
	case FAL_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
		ret = fal_opennsl_upd_l3_intf_mac_addr(intf,
						   &attr->value.mac);
		goto unlock;
	case FAL_ROUTER_INTERFACE_ATTR_MTU:
		INFO("Updated L3 intf MTU to %d for %d\n",
		     attr->value.u16, intf->ifindex);
		ret = fal_opennsl_upd_l3_intf_mtu(intf, attr->value.u16);
		goto unlock;
	default:
		ERROR("Failed to update L3 ingress, Unknown attr %d on %d\n",
		      attr_id, intf->ifindex);
		goto unlock;
	}

	INFO("Updating L3 ingress attr %d to %s for %d not supported\n",
	     attr_id,
	     attr->value.booldata ? "Enabled" : "Disabled", intf->l3_intf_id);
unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	return ret;
}

/*
 * Create IP neighbor for address on interface if_index
 */
int fal_plugin_ip_new_neigh(unsigned int ifindex,
			    struct fal_ip_address_t *ipaddr,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	const struct ether_addr *mac_addr = NULL;
	struct fal_opennsl_l3_neigh *neigh;
	char buf[FAL_OPENNSL_IP_ADDR_LEN];
	opennsl_if_t l3_intf_id;
	uint32_t vlan;
	uint32_t i;
	int rv;

	INFO("%s(ifindex %d, %s, attr_count %d, ...)\n",
	     __func__, ifindex,
	     fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr),
	     attr_count);

	if (!l3_support)
		return 0;

	rv = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (rv) {
		ERROR("unable to acquire L3 lock\n");
		return rv;
	}

	rv = fal_opennsl_lookup_l3_intf_info(ifindex, &l3_intf_id, &vlan);
	if (rv < 0) {
		/* Not an interface to do with the switch, so ignore */
		INFO("ignoring for %d, not a switch interface\n", ifindex);
		rv = 0;
		goto unlock;
	}

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS:
			mac_addr = &attr_list[i].value.mac;
			break;
		case FAL_NEIGH_ENTRY_ATTR_STATE:
		case FAL_NEIGH_ENTRY_ATTR_NTF_FLAGS:
			break;
		}
	}

	rv = fal_opennsl_lookup_l3_neigh(ifindex, ipaddr, &neigh);
	if (rv < 0)
		rv = fal_opennsl_insert_l3_neigh(ifindex, ipaddr, &neigh);
	if (rv < 0)
		goto unlock;

	if (neigh->sourced) {
		ERROR("duplicate new neighbour notification for %d, %s\n",
		      ifindex,
		      fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr));
		rv = -EINVAL;
		goto unlock;
	}
	neigh->sourced = true;

	if (!mac_addr) {
		INFO("incomplete, no MAC address\n");
		goto unlock;
	}

	rv = fal_opennsl_set_l3_neigh_mac(neigh, mac_addr);
	if (rv < 0) {
		neigh->sourced = false;
		fal_opennsl_unset_l3_neigh_mac(neigh);
		fal_opennsl_delete_l3_neigh_if_unused(neigh);
		goto unlock;
	}

unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	return rv;
}

/*
 * Update IP neighbor for address on interface if_index
 *
 * Note: this may be called on a dataplane forwarding thread in
 * response to an ARP/ND packet arriving to make a neighbour complete,
 * as well as on the dataplane master thread.
 */
int fal_plugin_ip_upd_neigh(unsigned int ifindex,
			    struct fal_ip_address_t *ipaddr,
			    struct fal_attribute_t *attr)
{
	const struct ether_addr *mac_addr = NULL;
	struct fal_opennsl_l3_neigh *neigh;
	char buf[FAL_OPENNSL_IP_ADDR_LEN];
	int rv;

	INFO("%s(ifindex %d, %s, { id %d, ... })\n",
	     __func__, ifindex,
	     fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr), attr->id);

	if (!l3_support)
		return 0;

	rv = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (rv) {
		ERROR("unable to acquire L3 lock\n");
		return rv;
	}

	rv = fal_opennsl_lookup_l3_neigh(ifindex, ipaddr, &neigh);
	if (rv < 0)
		goto unlock;

	switch (attr->id) {
	case FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS:
		mac_addr = &attr->value.mac;
		rv = fal_opennsl_set_l3_neigh_mac(neigh, mac_addr);
		break;
	case FAL_NEIGH_ENTRY_ATTR_STATE:
	case FAL_NEIGH_ENTRY_ATTR_NTF_FLAGS:
		break;
	}

unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	return rv;
}

/*
 * Delete IP neighbor for address on interface if_index
 */
int fal_plugin_ip_del_neigh(unsigned int ifindex,
			    struct fal_ip_address_t *ipaddr)
{
	struct fal_opennsl_l3_neigh *neigh;
	char buf[FAL_OPENNSL_IP_ADDR_LEN];
	int rv;

	INFO("%s(ifindex %d, %s)\n",
	     __func__, ifindex,
	     fal_opennsl_ip_addr2a(buf, sizeof(buf), ipaddr));

	if (!l3_support)
		return 0;

	rv = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (rv) {
		ERROR("unable to acquire L3 lock\n");
		return rv;
	}

	rv = fal_opennsl_lookup_l3_neigh(ifindex, ipaddr, &neigh);
	if (rv < 0)
		goto unlock;

	neigh->sourced = false;
	rv = fal_opennsl_unset_l3_neigh_mac(neigh);
	fal_opennsl_delete_l3_neigh_if_unused(neigh);

unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	return rv;
}

/*
 * Create a new next-hop-group object
 *
 * Assumes next-hop members will subsequently be added, thus updating
 * the FEC of the next-hop-group object, before a route uses it.
 */
int fal_plugin_ip_new_next_hop_group(uint32_t attr_count,
				     const struct fal_attribute_t *attr_list,
				     fal_object_t *obj)
{
	struct fal_opennsl_l3_nh_group *nhg;
	uint32_t i;

	INFO("%s(%d, ...)\n", __func__, attr_count);

	if (!l3_support)
		return 0;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		default:
			INFO("%s: Unhandled attribute %d\n", __func__,
			     attr_list[i].id);
		}
	}

	nhg = calloc(1, sizeof(*nhg));
	if (!nhg)
		return -ENOMEM;

	*obj = (uintptr_t)nhg;
	INFO("%s <- %p\n", __func__, nhg);

	return 0;
}

/*
 * Update a next-hop-group object
 */
int fal_plugin_ip_upd_next_hop_group(fal_object_t obj,
				     const struct fal_attribute_t *attr)
{
	switch (attr->id) {
	default:
		INFO("%s: Unhandled attribute %d\n", __func__, attr->id);
	}

	return 0;
}

/*
 * Delete a next-hop-group object
 *
 * Assumes all next-hop members removed already.
 */
int fal_plugin_ip_del_next_hop_group(fal_object_t obj)
{
	struct fal_opennsl_l3_nh_group *nhg = (struct fal_opennsl_l3_nh_group *)obj;

	INFO("%s(0x%lx)\n", __func__, obj);

	if (!l3_support)
		return 0;

	free(nhg);

	return 0;
}

static int
fal_opennsl_find_special_fec(int unit, enum fal_packet_action_t action,
			 opennsl_if_t *fec_id)
{
	switch (action) {
	case FAL_PACKET_ACTION_DROP:
		*fec_id = fal_opennsl_l3_black_hole_fec_id;
		break;
	case FAL_PACKET_ACTION_FORWARD:
		/* not a special FEC */
		return -EINVAL;
	case FAL_PACKET_ACTION_TRAP:
	default:
		*fec_id = fal_opennsl_l3_trap_fec_id;
		break;
	}

	return 0;
}

/*
 * Make linkage between nh and neighbour
 *
 * So that the nh can be updated when properties of the neighbour change.
 */
static int
fal_opennsl_lookup_l3_nh_link_to_neigh(struct fal_opennsl_l3_nh *nh,
				   uint32_t ifindex,
				   const struct fal_ip_address_t *nh_addr)
{
	struct fal_opennsl_l3_neigh *neigh;
	int ret;

	ret = fal_opennsl_lookup_l3_neigh(ifindex, nh_addr, &neigh);
	if (ret < 0)
		ret = fal_opennsl_insert_l3_neigh(ifindex, nh_addr, &neigh);
	if (ret < 0)
		return ret;

	nh->neigh = neigh;
	LIST_INSERT_HEAD(&neigh->dep_nh_list, nh, neigh_entry);

	return 0;
}

/*
 * Destroy linkage between nh and neighbour
 */
static void
fal_opennsl_lookup_l3_nh_unlink_from_neigh(struct fal_opennsl_l3_nh *nh)
{
	if (nh->neigh) {
		LIST_REMOVE(nh, neigh_entry);
		fal_opennsl_delete_l3_neigh_if_unused(nh->neigh);
		nh->neigh = NULL;
	}
}

/*
 * Add or update a forwarding (as opposed to special) FEC
 */
static int
fal_opennsl_add_update_forward_fec(struct fal_opennsl_l3_nh *nh,
			       uint32_t ifindex,
			       const struct fal_ip_address_t *nh_addr,
			       uint32_t l3_flags)
{
	struct fal_opennsl_l3_fec_param l3_fec = { 0 };
	uint32_t vlan;
	int unit = 0;
	int ret;
	int rv;

	if (!ifindex) {
		ERROR("%s: unexpected ifindex yet not present\n", __func__);
		return -EINVAL;
	}

	ret = fal_opennsl_lookup_l3_intf_info(ifindex, &l3_fec.rif,
					  &vlan);
	if (ret < 0 || !nh_addr) {
		OPENNSL_GPORT_TRAP_SET(l3_fec.out_gport, fal_opennsl_l3_trap_id,
				   FAL_OPENNSL_RX_TRAP_STRENGTH_L3_PUNT, 0);
		if (ret < 0) {
			INFO("%s: interface %d not a switch VIF\n",
			     __func__, ifindex);
		} else {
			INFO("%s: connected route\n", __func__);
		}
	} else {
		if (!nh->neigh) {
			ret = fal_opennsl_lookup_l3_nh_link_to_neigh(
				nh, ifindex, nh_addr);
			if (ret < 0)
				goto out;
		}

		if (nh->neigh->complete) {
			l3_fec.out_gport = nh->neigh->out_gport;
			l3_fec.encap_id = nh->neigh->encap_id;
		} else {
			INFO("%s: punt for resolution\n", __func__);
			l3_fec.out_gport = fal_opennsl_get_punt_port();
		}
	}

	rv = fal_opennsl_create_l3_fec(unit, l3_flags, &l3_fec, &nh->fec_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("fec create failed: %s\n", opennsl_errmsg(rv));
		ret = -ENOSPC;
		goto unlink;
	}

	INFO("%s: fec_id = 0x%x\n", __func__, nh->fec_id);
	return 0;

unlink:
	fal_opennsl_lookup_l3_nh_unlink_from_neigh(nh);
out:
	return ret;
}

/*
 * Add a batch of forwarding FECs
 */
static int
fal_opennsl_add_forward_fecs(struct fal_opennsl_l3_nh_group *nhg,
			 uint32_t nh_count,
			 const uint32_t *ifindices,
			 const struct fal_ip_address_t **nh_addrs,
			 struct fal_opennsl_l3_nh **nhs)
{
	int first_unit = 0;
	uint32_t flags = 0;
	uint32_t nh_idx;
	int ret = 0;
	int fec_ids[nh_count];

	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		nhs[nh_idx] = calloc(1, sizeof(*nhs[nh_idx]));
		if (!nhs[nh_idx]) {
			ERROR("%s: out of memory\n", __func__);
			ret = -ENOMEM;
			goto free_nhs;
		}
		nhs[nh_idx]->nhg = nhg;
	}


	/*
	 * Due to the restriction on the DPP architecture that ECMP
	 * members must have consecutive FEC IDs, we must allocate a
	 * batch of IDs here.
	 */
	ret = fal_opennsl_pre_alloc_res(
		first_unit, FAL_OPENNSL_RES_FEC, nh_count, fec_ids,
		&flags);
	if (ret < 0)
		return ret;
	if (flags & OPENNSL_L3_WITH_ID) {
		for (nh_idx = 0; nh_idx < nh_count; nh_idx++)
			nhs[nh_idx]->fec_id = fec_ids[nh_idx];
	}

	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		ret = fal_opennsl_add_update_forward_fec(
			nhs[nh_idx], ifindices[nh_idx],
			nh_addrs[nh_idx], flags);
		if (ret < 0)
			goto free_nhs;
	}

	goto out;

free_nhs:
	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		if (nhs[nh_idx] && nhs[nh_idx]->neigh) {
			fal_opennsl_destroy_l3_fec(
				0, nhs[nh_idx]->fec_id);
			fal_opennsl_lookup_l3_nh_unlink_from_neigh(
				nhs[nh_idx]);
		} else {
			/*
			 * if we created a FEC in the SDK then the
			 * free of the ID will be handled in the
			 * conditional just above, but if we didn't then
			 * we need to free the ID manually
			 */
			fal_opennsl_pre_alloc_res_free(
				first_unit, FAL_OPENNSL_RES_FEC,
				nhs[nh_idx]->fec_id);
		}
		free(nhs[nh_idx]);
		nhs[nh_idx] = NULL;
	}

out:
	return ret;
}

static int
fal_opennsl_update_forward_fec(struct fal_opennsl_l3_nh *nh)
{
	return fal_opennsl_add_update_forward_fec(
		nh, nh->neigh->ifindex, &nh->neigh->ipaddr,
		OPENNSL_L3_WITH_ID | OPENNSL_L3_REPLACE);
}

/*
 * Create an Egress ECMP object and add nexthops to it
 */
static int
fal_opennsl_create_ecmp_fec_for_nhs(uint32_t nh_count,
				struct fal_opennsl_l3_nh **nhs,
				opennsl_if_t *ecmp_fec)
{
	opennsl_l3_egress_ecmp_t ecmp_info;
	opennsl_if_t *ecmp_members;
	int unit = 0;
	uint32_t i;
	int rv;

	opennsl_l3_egress_ecmp_t_init(&ecmp_info);
	ecmp_info.max_paths = nh_count;

	ecmp_members = malloc(nh_count * sizeof(*ecmp_members));
	if (!ecmp_members)
		return -ENOMEM;

	for (i = 0; i < nh_count; i++)
		ecmp_members[i] = nhs[i]->fec_id;

	rv = opennsl_l3_egress_ecmp_create(unit, &ecmp_info, nh_count,
				       ecmp_members);
	free(ecmp_members);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: egress ECMP create failed: %s\n",
		      __func__, opennsl_errmsg(rv));
		return -ENOSPC;
	}

	*ecmp_fec = ecmp_info.ecmp_intf;
	return 0;
}

/*
 * Create new next hop members
 *
 * Create new next hop members and add them to a next-hop-group object.
 */
int fal_plugin_ip_new_next_hops(uint32_t nh_count,
				const uint32_t *attr_count,
				const struct fal_attribute_t **attr_list,
				fal_object_t *obj_list)
{
	struct fal_opennsl_l3_nh_group *nhg = NULL;
	uint32_t nh_idx;
	uint32_t i;
	int rv = 0;
	uint32_t *ifindices = NULL;
	const struct fal_ip_address_t **ipaddrs = NULL;

	if (!l3_support)
		return 0;

	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		const struct fal_attribute_t *nh_attr_list = attr_list[nh_idx];

		for (i = 0; i < attr_count[nh_idx]; i++) {
			if (nh_attr_list[i].id ==
			    FAL_NEXT_HOP_ATTR_NEXT_HOP_GROUP) {
				struct fal_opennsl_l3_nh_group *new_nhg =
					(struct fal_opennsl_l3_nh_group *)
					nh_attr_list[i].value.u64;
				if (nhg && new_nhg != nhg) {
					ERROR(
						"%s: Multiple next-hop-groups in one bulk next-hop message not supported\n",
						__func__);
					return -EOPNOTSUPP;
				}
				nhg = new_nhg;
			}
			break;
		}
	}

	if (!nhg) {
		ERROR("%s: Missing next hop group object\n", __func__);
		return -EINVAL;
	}

	if (nhg->nh_count) {
		ERROR(
			"%s: adding members to next-hop-group with existing members not supported\n",
			__func__);
		return -EINVAL;
	}

	INFO("%s: nhg %p nh_count %u ...\n", __func__, nhg, nh_count);

	nhg->nhs = calloc(nh_count, sizeof(*nhg->nhs));
	if (!nhg->nhs) {
		ERROR("%s: out of memory for nh count %d\n", __func__,
		      nh_count);
		return -ENOMEM;
	}
	nhg->nh_count = nh_count;
	ifindices = calloc(nh_count, sizeof(*ifindices));
	ipaddrs = calloc(nh_count, sizeof(*ipaddrs));
	if (!ifindices || !ipaddrs) {
		rv = -ENOMEM;
		goto free_nhg_nhs_and_tmps;
	}

	rv = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (rv) {
		ERROR("unable to acquire L3 lock\n");
		goto free_nhg_nhs_and_tmps;
	}

	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		const struct fal_attribute_t *nh_attr_list = attr_list[nh_idx];

		for (i = 0; i < attr_count[nh_idx]; i++) {
			switch (nh_attr_list[i].id) {
			case FAL_NEXT_HOP_ATTR_NEXT_HOP_GROUP:
				break;
			case FAL_NEXT_HOP_ATTR_INTF:
				ifindices[nh_idx] = nh_attr_list[i].value.u32;
				break;
			case FAL_NEXT_HOP_ATTR_IP:
				ipaddrs[nh_idx] = &nh_attr_list[i].value.ipaddr;
				break;
			default:
				INFO("%s: Unhandled attribute %d\n",
				     __func__, nh_attr_list[i].id);
			}
		}
	}

	rv = fal_opennsl_add_forward_fecs(nhg, nh_count, ifindices, ipaddrs,
				      nhg->nhs);
	if (rv < 0)
		goto unlock;

	for (nh_idx = 0; nh_idx < nh_count; nh_idx++)
		obj_list[nh_idx] = (uintptr_t)nhg->nhs[nh_idx];

	/* No need to create Egress_ECMP object if there's just one nexthop */
	if (nh_count == 1)
		nhg->fec_id = nhg->nhs[0]->fec_id;
	else
		rv = fal_opennsl_create_ecmp_fec_for_nhs(nhg->nh_count, nhg->nhs,
						     &nhg->fec_id);

	goto unlock;

unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
free_nhg_nhs_and_tmps:
	free(ifindices);
	free(ipaddrs);
	free(nhg->nhs);
	nhg->nhs = NULL;
	return rv;
}

int fal_plugin_ip_upd_next_hop(fal_object_t obj,
			       const struct fal_attribute_t *attr)
{
	switch (attr->id) {
	default:
		INFO("%s: Unhandled attribute %d\n", __func__, attr->id);
	}

	ERROR("%s: update not supported\n", __func__);

	return 0;
}

/*
 * Delete next hop members
 *
 * Delete next hop members and remove them from their next-hop-group
 * object.
 */
int fal_plugin_ip_del_next_hops(uint32_t nh_count,
				const fal_object_t *obj_list)
{
	struct fal_opennsl_l3_nh_group *nhg = NULL;
	uint32_t nh_idx;
	int unit = 0;
	int rv;

	INFO("%s(%d, ...)\n", __func__, nh_count);

	if (!l3_support)
		return 0;

	rv = pthread_mutex_lock(&fal_opennsl_l3_lock);
	if (rv) {
		ERROR("unable to acquire L3 lock\n");
		return rv;
	}

	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		struct fal_opennsl_l3_nh *nh =
			(struct fal_opennsl_l3_nh *)obj_list[nh_idx];

		if (!nh) {
			ERROR("%s: missing l3 nh\n", __func__);
			rv = -EINVAL;
			goto unlock;
		}
		INFO("%s: nh %p - group %p\n", __func__, nh, nh->nhg);

		if (nh->nhg->nh_count != nh_count) {
			ERROR("%s: partial removal of members not supported\n",
			      __func__);
			rv = -EINVAL;
			goto unlock;
		}

		nhg = nh->nhg;

		/*
		 * Destroy fec that references encap before potentially
		 * destroying neighbour with encap.
		 */
		fal_opennsl_destroy_l3_fec(unit, nh->fec_id);
		fal_opennsl_lookup_l3_nh_unlink_from_neigh(nh);
		free(nh);
	}

	if (nhg && nhg->nh_count > 1) {
		opennsl_l3_egress_ecmp_t ecmp_info;

		opennsl_l3_egress_ecmp_t_init(&ecmp_info);
		ecmp_info.ecmp_intf = nhg->fec_id;
		rv = opennsl_l3_egress_ecmp_destroy(unit, &ecmp_info);
		if (OPENNSL_FAILURE(rv)) {
			ERROR("%s: egress ecmp destroy failed: %s\n",
			      __func__, opennsl_errmsg(rv));
		}
	}

unlock:
	pthread_mutex_unlock(&fal_opennsl_l3_lock);
	return rv;
}


static void ip_prefixlen_to_mask(uint8_t prefixlen, opennsl_ip_t *mask)
{
	*mask = prefixlen == 32 ? 0xffffffff : ~(0xffffffff >> prefixlen);
}

static void ip6_prefixlen_to_mask(uint8_t prefixlen, opennsl_ip6_t *mask)
{
	int i;

	for (i = 0; i < sizeof(*mask); i++) {
		if (i < prefixlen / 8)
			(*mask)[i] = 0xff;
		else if (i == prefixlen / 8)
			(*mask)[i] = ~(0xff >> (prefixlen % 8));
		else
			(*mask)[i] = 0x00;
	}
}

/*
 * Wrapper for adding a route referring to a FEC (or Egress ECMP)
 * object
 */
static int
fal_opennsl_add_route(int unit, unsigned int vrf_id,
		  const struct fal_ip_address_t *ipaddr,
		  uint8_t prefixlen, bool update, opennsl_if_t fec_id)
{
	opennsl_l3_route_t l3r;

	opennsl_l3_route_t_init(&l3r);

	l3r.l3a_vrf = vrf_id;
	l3r.l3a_intf = fec_id;
	if (update)
		l3r.l3a_flags |= OPENNSL_L3_REPLACE;

	switch (ipaddr->addr_family) {
	case FAL_IP_ADDR_FAMILY_IPV4:
		l3r.l3a_subnet = ntohl(ipaddr->addr.ip4);
		ip_prefixlen_to_mask(prefixlen, &l3r.l3a_ip_mask);
		break;
	case FAL_IP_ADDR_FAMILY_IPV6:
		memcpy(&l3r.l3a_ip6_net, &ipaddr->addr.ip6,
		       sizeof(l3r.l3a_ip6_net));
		ip6_prefixlen_to_mask(prefixlen, &l3r.l3a_ip6_mask);
		l3r.l3a_flags |= OPENNSL_L3_IP6;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return opennsl_l3_route_add(unit, &l3r);
}

/*
 * Wrapper for deleting a route
 */
static int
fal_opennsl_del_route(int unit, unsigned int vrf_id,
		  const struct fal_ip_address_t *ipaddr,
		  uint8_t prefixlen)
{
	opennsl_l3_route_t l3r;

	opennsl_l3_route_t_init(&l3r);

	l3r.l3a_vrf = vrf_id;

	switch (ipaddr->addr_family) {
	case FAL_IP_ADDR_FAMILY_IPV4:
		l3r.l3a_subnet = ntohl(ipaddr->addr.ip4);
		ip_prefixlen_to_mask(prefixlen, &l3r.l3a_ip_mask);
		break;
	case FAL_IP_ADDR_FAMILY_IPV6:
		memcpy(&l3r.l3a_ip6_net, &ipaddr->addr.ip6,
		       sizeof(l3r.l3a_ip6_net));
		ip6_prefixlen_to_mask(prefixlen, &l3r.l3a_ip6_mask);
		l3r.l3a_flags |= OPENNSL_L3_IP6;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return opennsl_l3_route_delete(unit, &l3r);
}

/*
 * Is the route interesting to us for creates/updates/deletes?
 */
static bool
fal_opennsl_route_is_interesting(struct fal_ip_address_t *ipaddr,
			     uint8_t prefixlen,
			     uint32_t tableid)
{
	/* Ignore PBR table updates - nothing we can do with them */
	if (tableid != RT_TABLE_MAIN)
		return false;

	if (ipaddr->addr_family == FAL_IP_ADDR_FAMILY_IPV6 &&
	    IN6_IS_ADDR_LINKLOCAL(&ipaddr->addr.addr6))
		return false;

	return true;
}

/*
 * Create a new route
 */
int fal_plugin_ip_new_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	enum fal_packet_action_t action = FAL_PACKET_ACTION_FORWARD;
	struct fal_opennsl_l3_nh_group *nhg = NULL;
	char buf[FAL_PCM_IP_PFX_LEN];
	opennsl_if_t fec_id;
	int unit = 0;
	uint32_t i;
	int rv;

	INFO("%s(vrf:%d %s table:%d, attr_count %d, ...)\n",
	     __func__, vrf_id,
	     fal_opennsl_ip_pfx2a(buf, sizeof(buf), ipaddr, prefixlen), tableid,
	     attr_count);

	if (!l3_support)
		return 0;

	if (!fal_opennsl_route_is_interesting(ipaddr, prefixlen, tableid))
		return 0;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP:
			nhg = (struct fal_opennsl_l3_nh_group *)
				attr_list[i].value.u64;
			INFO("%s: using nhg %p\n", __func__, nhg);
			break;
		case FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION:
			action = attr_list[i].value.u32;
			INFO("%s: action %d\n", __func__, action);
			break;
		}
	}

	if (action == FAL_PACKET_ACTION_FORWARD) {
		if (!nhg) {
			ERROR("%s: missing next-hop-group object\n", __func__);
			return -EINVAL;
		}
		fec_id = nhg->fec_id;
	} else {
		rv = fal_opennsl_find_special_fec(unit, action, &fec_id);
		if (rv < 0)
			return rv;
	}

	INFO("%s: fec 0x%x\n", __func__, fec_id);
	rv = fal_opennsl_add_route(unit, vrf_id, ipaddr, prefixlen, false, fec_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("add route failed: %s\n",
		      opennsl_errmsg(rv));
		return -ENOSPC;
	}

	return 0;
}

/*
 * Update a new route
 */
int fal_plugin_ip_upd_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    struct fal_attribute_t *attr)
{
	enum fal_packet_action_t action = FAL_PACKET_ACTION_FORWARD;
	struct fal_opennsl_l3_nh_group *nhg = NULL;
	char buf[FAL_PCM_IP_PFX_LEN];
	opennsl_if_t fec_id;
	int unit = 0;
	int rv;

	INFO("%s(vrf:%d %s table:%d, ...)\n",
	     __func__, vrf_id,
	     fal_opennsl_ip_pfx2a(buf, sizeof(buf), ipaddr, prefixlen), tableid);

	if (!l3_support)
		return 0;

	if (!fal_opennsl_route_is_interesting(ipaddr, prefixlen, tableid))
		return 0;

	switch (attr->id) {
	case FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP:
		nhg = (struct fal_opennsl_l3_nh_group *)attr->value.u64;
		INFO("%s: using nhg %p\n", __func__, nhg);
		fec_id = nhg->fec_id;
		break;
	case FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION:
		action = attr->value.u32;
		INFO("%s: action %d\n", __func__, action);
		if (action == FAL_PACKET_ACTION_FORWARD)
			/* nothing to do */
			return 0;
		rv = fal_opennsl_find_special_fec(unit, action, &fec_id);
		if (rv < 0)
			return rv;
		break;
	default:
		return 0;
	}

	INFO("%s: fec 0x%x\n", __func__, fec_id);
	rv = fal_opennsl_add_route(unit, vrf_id, ipaddr, prefixlen, true, fec_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("add route failed: %s\n",
		      opennsl_errmsg(rv));
		return -ENOSPC;
	}

	return 0;
}

/*
 * Delete a new route
 */
int fal_plugin_ip_del_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid)
{
	char buf[FAL_PCM_IP_PFX_LEN];
	int unit = 0;
	int rv;

	INFO("%s(vrf:%d %s table:%d)\n",
	     __func__, vrf_id,
	     fal_opennsl_ip_pfx2a(buf, sizeof(buf), ipaddr, prefixlen), tableid);

	if (!l3_support)
		return 0;

	if (!fal_opennsl_route_is_interesting(ipaddr, prefixlen, tableid))
		return 0;

	rv = fal_opennsl_del_route(unit, vrf_id, ipaddr, prefixlen);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("del route failed: %s\n",
		      opennsl_errmsg(rv));
		return -ENOSPC;
	}

	return 0;
}

static int
fal_opennsl_mtu_check_enable(int unit, opennsl_forwarding_type_t header_code)
{
	opennsl_switch_control_info_t mtu_enable_info;
	opennsl_switch_control_key_t mtu_enable_type;

	/*
	 * Enable link layer MTU filtering which corresponds to the
	 * EPNI block in the DPP architecture.
	 */
	mtu_enable_type.type = opennslSwitchLinkLayerMtuFilter;
	mtu_enable_type.index = header_code;
	mtu_enable_info.value = true;

	return opennsl_switch_control_indexed_set(unit, mtu_enable_type,
					      mtu_enable_info);
}


/*
 * Create FECs corresponding to well-known FAL packet action values
 */
static int fal_opennsl_create_special_fecs(void)
{
	struct fal_opennsl_l3_fec_param l3_black_hole_fec = { 0 };
	struct fal_opennsl_l3_fec_param l3_trap_fec = { 0 };
	int unit = 0;
	int rv;

	l3_black_hole_fec.out_gport = OPENNSL_GPORT_BLACK_HOLE;

	rv = fal_opennsl_create_l3_fec(unit, 0, &l3_black_hole_fec,
				   &fal_opennsl_l3_black_hole_fec_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("special black hole fec create failed: %s\n",
		      opennsl_errmsg(rv));
		return rv;
	}

	OPENNSL_GPORT_TRAP_SET(l3_trap_fec.out_gport, fal_opennsl_l3_trap_id,
			   FAL_OPENNSL_RX_TRAP_STRENGTH_L3_PUNT, 0);

	rv = fal_opennsl_create_l3_fec(unit, 0, &l3_trap_fec,
				   &fal_opennsl_l3_trap_fec_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("special trap fec create failed: %s\n",
		      opennsl_errmsg(rv));
		return rv;
	}

	return 0;
}

/*
 * Set IP ICMP redirect action
 */
int fal_opennsl_set_ip_icmp_redirect(enum fal_packet_action_t action)
{
	struct fal_opennsl_rx_trap_type_setup trap_setup;
	int ret = OPENNSL_E_NONE;

	trap_setup.type = opennslRxTrapIcmpRedirect;
	trap_setup.str = "opennslRxTrapIcmpRedirect";

	switch (action) {
	case FAL_PACKET_ACTION_FORWARD:
		ret = fal_opennsl_rx_trap_unset(&trap_setup);
		break;
	case FAL_PACKET_ACTION_TRAP:
		trap_setup.punt = true;
		trap_setup.strength =
			FAL_OPENNSL_RX_TRAP_STRENGTH_L3_EXCEPT_PUNT;
		ret = fal_opennsl_rx_trap_set(&trap_setup);
		break;
	case FAL_PACKET_ACTION_DROP:
		ret = OPENNSL_E_PARAM;
		break;
	}
	if (OPENNSL_FAILURE(ret)) {
		ERROR("%s: failed to set action %d for %s - %s\n",
		      __func__, action, trap_setup.str,
		      opennsl_errmsg(ret));
	}
	return ret;
}

/*
 * Seemingly duplicate macros defined for later support for per-type
 * counters.
 */
#define RX_TRAP_ARP_PUNT(val) \
	{ .type = val, .str = #val, .punt = true, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_EXCEPT_PUNT }
#define RX_TRAP_L3_PUNT(val) \
	{ .type = val, .str = #val, .punt = true, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_EXCEPT_PUNT }
#define RX_TRAP_IPV4_BAD_HEADER(val) \
	{ .type = val, .str = #val, .port = OPENNSL_GPORT_BLACK_HOLE, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_DROP  }
#define RX_TRAP_IPV4_BAD_ADDR(val) \
	{ .type = val, .str = #val, .port = OPENNSL_GPORT_BLACK_HOLE, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_DROP }
#define RX_TRAP_IPV4_EXCEPT_PUNT(val) \
	{ .type = val, .str = #val, .punt = true, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_EXCEPT_PUNT }
#define RX_TRAP_IPV6_BAD_HEADER(val) \
	{ .type = val, .str = #val, .port = OPENNSL_GPORT_BLACK_HOLE, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_DROP }
#define RX_TRAP_IPV6_BAD_ADDR(val) \
	{ .type = val, .str = #val, .port = OPENNSL_GPORT_BLACK_HOLE, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_DROP }
#define RX_TRAP_IPV6_EXCEPT_PUNT(val) \
	{ .type = val, .str = #val, .punt = true, \
	  .strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_EXCEPT_PUNT }

static const struct fal_opennsl_rx_trap_type_setup rx_trap_type_setup[] = {
	/* ARP */

	/* Om nom nom */
	RX_TRAP_ARP_PUNT(opennslRxTrapArp),
	RX_TRAP_ARP_PUNT(opennslRxTrapArpReply),

	/* L3 */

	/* Need unknown L3, e.g. for IS-IS */
	RX_TRAP_L3_PUNT(opennslRxTrapMyMacAndUnknownL3),
	RX_TRAP_L3_PUNT(opennslRxTrapIcmpRedirect),

	/* IPv4 */

	/*
	 * These are all header errors, which we need to count but not
	 * generate an ICMP.
	 */
	RX_TRAP_IPV4_BAD_HEADER(opennslRxTrapIpv4VersionError),
	RX_TRAP_IPV4_BAD_HEADER(opennslRxTrapIpv4ChecksumError),
	RX_TRAP_IPV4_BAD_HEADER(opennslRxTrapIpv4HeaderLengthError),
	RX_TRAP_IPV4_BAD_HEADER(opennslRxTrapIpv4TotalLengthError),
	/*
	 * Need to generate ICMP so these need to be punted to
	 * software dataplane.
	 */
	RX_TRAP_IPV4_EXCEPT_PUNT(opennslRxTrapIpv4Ttl0),
	RX_TRAP_IPV4_EXCEPT_PUNT(opennslRxTrapIpv4Ttl1),
	/* For router-alert packets, e.g. for RSVP-TE */
	RX_TRAP_IPV4_EXCEPT_PUNT(opennslRxTrapIpv4HasOptions),
	/* For DHCP packets */
	RX_TRAP_IPV4_EXCEPT_PUNT(opennslRxTrapIpv4DipZero),

	/* IPv6 */

	/*
	 * These are all header errors, which we need to count but not
	 * generate an ICMP.
	 */
	RX_TRAP_IPV6_BAD_HEADER(opennslRxTrapIpv6VersionError),
	RX_TRAP_IPV6_BAD_ADDR(opennslRxTrapIpv6UnspecifiedDestination),
	/* Note: either source or dest is loopback address */
	RX_TRAP_IPV6_BAD_ADDR(opennslRxTrapIpv6LoopbackAddress),
	RX_TRAP_IPV6_BAD_ADDR(opennslRxTrapIpv6MulticastSource),
	RX_TRAP_IPV6_BAD_ADDR(opennslRxTrapIpv6UnspecifiedSource),
	RX_TRAP_IPV6_BAD_ADDR(opennslRxTrapIpv6Ipv4CompatibleDestination),
	RX_TRAP_IPV6_BAD_ADDR(opennslRxTrapIpv6Ipv4MappedDestination),
	/*
	 * Need to generate ICMP so these need to be punted to
	 * software dataplane.
	 */
	RX_TRAP_IPV6_EXCEPT_PUNT(opennslRxTrapIpv6HopCount0),
	RX_TRAP_IPV6_EXCEPT_PUNT(opennslRxTrapIpv6HopCount1),
	/*
	 * Need to punt these as they cannot be forwarded and only
	 * software dataplane has information to validate scope.
	 */
	RX_TRAP_IPV6_EXCEPT_PUNT(opennslRxTrapIpv6LocalLinkDestination),
	RX_TRAP_IPV6_EXCEPT_PUNT(opennslRxTrapIpv6LocalLinkSource),
};

#undef RX_TRAP_ARP_PUNT
#undef RX_TRAP_L3_PUNT
#undef RX_TRAP_IPV4_BAD_HEADER
#undef RX_TRAP_IPV4_BAD_ADDR
#undef RX_TRAP_IPV4_EXCEPT_PUNT
#undef RX_TRAP_IPV6_BAD_HEADER
#undef RX_TRAP_IPV6_BAD_ADDR
#undef RX_TRAP_IPV6_EXCEPT_PUNT

/*
 * Intialise L3 global state
 */
int fal_opennsl_l3_init(void)
{
	opennsl_rx_trap_config_t rx_trap_config;
	int unit = 0;
	int rv;
	int i;

	pthread_mutex_init(&fal_opennsl_l3_lock, NULL);

	for (i = 0; i < ARRAY_SIZE(rx_trap_type_setup); i++) {
		rv = fal_opennsl_rx_trap_set(&rx_trap_type_setup[i]);
		if (OPENNSL_FAILURE(rv)) {
			ERROR("%s: opennsl_rx_trap_set failed for %s - %s\n",
			      __func__, rx_trap_type_setup[i].str,
			      opennsl_errmsg(rv));
			continue;
		}
	}

	rv = opennsl_rx_trap_type_create(unit, 0, opennslRxTrapUserDefine,
				     &fal_opennsl_l3_trap_id);
	if (OPENNSL_FAILURE(rv)) {
		ERROR(
			"%s: opennsl_rx_trap_type_create opennslRxTrapUserDefine failed - %s\n",
			__func__, opennsl_errmsg(rv));
		return rv;
	}

	opennsl_rx_trap_config_t_init(&rx_trap_config);
	rx_trap_config.flags |= OPENNSL_RX_TRAP_UPDATE_DEST;
	rx_trap_config.trap_strength = FAL_OPENNSL_RX_TRAP_STRENGTH_L3_PUNT;
	rx_trap_config.dest_port = fal_opennsl_get_punt_port();
	rv = opennsl_rx_trap_set(unit, fal_opennsl_l3_trap_id, &rx_trap_config);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: opennsl_rx_trap_set opennslRxTrapUserDefine failed - %s\n",
		      __func__, opennsl_errmsg(rv));
		return rv;
	}

	rv = fal_opennsl_mtu_check_enable(unit, opennslForwardingTypeL2);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: fal_opennsl_mtu_check_enable opennslForwardingTypeL2 failed - %s\n",
		      __func__, opennsl_errmsg(rv));
		return rv;
	}

	rv = fal_opennsl_mtu_check_enable(unit, opennslForwardingTypeIp4Ucast);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: fal_opennsl_mtu_check_enable opennslForwardingTypeIp4Ucast failed - %s\n",
		      __func__, opennsl_errmsg(rv));
		return rv;
	}

	rv = fal_opennsl_mtu_check_enable(unit, opennslForwardingTypeIp4Mcast);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: fal_opennsl_mtu_check_enable opennslForwardingTypeIp4Mcast failed - %s\n",
		      __func__, opennsl_errmsg(rv));
		return rv;
	}

	rv = fal_opennsl_mtu_check_enable(unit, opennslForwardingTypeIp6Ucast);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("%s: fal_opennsl_mtu_check_enable opennslForwardingTypeIp6Ucast failed - %s\n",
		      __func__, opennsl_errmsg(rv));
		return rv;
	}

	if (fal_opennsl_chip_cfg[unit]->cfg_l3_punt_too_big) {
		rv = fal_opennsl_chip_cfg[unit]->cfg_l3_punt_too_big(unit);
		if (OPENNSL_FAILURE(rv))
			return rv;
	}

	rv = fal_opennsl_create_special_fecs();
	if (OPENNSL_FAILURE(rv))
		return rv;

	rv = opennsl_l2_addr_register(unit, fal_opennsl_l3_neigh_l2_addr_cb, NULL);
	if (rv != OPENNSL_E_NONE) {
		ERROR("%s: Failed to initialize l2 address handler: %s\n",
		      __func__, opennsl_errmsg(rv));
		return rv;
	}

	return 0;
}
