/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.
 * All rights reserved.
 */
/*-
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <bsd/sys/tree.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/neighbour.h>

#include <opennsl/types.h>
#include <opennsl/error.h>
#include <opennsl/port.h>
#include <opennsl/stg.h>
#include <opennsl/vlan.h>
#include <opennsl/l2.h>

/* ixgbe sbp API is still experimental */
#define ALLOW_EXPERIMENTAL_API 1
#include <rte_ether.h>
#include <rte_pmd_ixgbe.h>

#include <fal_plugin.h>
#include <json_writer.h>
#include <bridge_flags.h>
#include <bridge_vlan_set.h>

#include "fal_opennsl.h"
#include "fal_opennsl_debug.h"

#define UNUSED(x) (void)(x)

#define FOR_ALL_UNITS(unit) for (unit = 0; unit < fal_opennsl_ndevs; unit++)

/* Needed for RB_* */
#define __unused __attribute__((unused))

struct fal_opennsl_vlan_sync_data {
	int unit;
	opennsl_port_t port;
	struct bridge_vlan_set *vlans;
	struct bridge_vlan_set *untagged_vlans;
};

struct fal_opennsl_l2_intf {
	uint32_t ifindex;
	char *kind;
	uint32_t ifi_type;

	RB_ENTRY(fal_opennsl_l2_intf) ifi_link;
};

RB_HEAD(fal_opennsl_l2_intf_tree, fal_opennsl_l2_intf);
static struct fal_opennsl_l2_intf_tree fal_opennsl_l2_intf_tree;

static int fal_opennsl_l2_intf_cmp(const struct fal_opennsl_l2_intf *if1,
			       const struct fal_opennsl_l2_intf *if2)
{
	return if1->ifindex - if2->ifindex;
}

/* Generate internal functions and make them static. */
RB_GENERATE_STATIC(fal_opennsl_l2_intf_tree, fal_opennsl_l2_intf, ifi_link,
		   fal_opennsl_l2_intf_cmp)

static int
fal_opennsl_l2_intf_create(uint32_t ifindex, const char *kind,
		       uint32_t ifi_type,
		       struct fal_opennsl_l2_intf **intf_ret)
{
	struct fal_opennsl_l2_intf *intf;
	struct fal_opennsl_l2_intf *old;
	int ret;

	intf = calloc(1, sizeof(*intf));
	if (!intf)
		return -ENOMEM;

	intf->ifindex = ifindex;
	if (kind) {
		intf->kind = strdup(kind);
		if (!intf->kind) {
			ret = -ENOMEM;
			goto error;
		}
	}
	intf->ifi_type = ifi_type;

	old = RB_INSERT(fal_opennsl_l2_intf_tree, &fal_opennsl_l2_intf_tree,
			intf);
	if (old) {
		ERROR("L2 intf already exists for ifindex %d\n",
		      old->ifindex);
		free(old->kind);
		free(old);
	}

	*intf_ret = intf;
	return 0;

error:
	free(intf->kind);
	free(intf);
	return ret;
}

static int
fal_opennsl_l2_intf_lookup(uint32_t ifindex,
		       struct fal_opennsl_l2_intf **intf)
{
	struct fal_opennsl_l2_intf k = {
		.ifindex = ifindex,
	};

	*intf = RB_FIND(fal_opennsl_l2_intf_tree, &fal_opennsl_l2_intf_tree,
			&k);
	return *intf ? 0 : -ENOENT;
}

static int
fal_opennsl_l2_intf_delete(uint32_t ifindex)
{
	struct fal_opennsl_l2_intf *intf;
	int ret;

	ret = fal_opennsl_l2_intf_lookup(ifindex, &intf);
	if (ret < 0) {
		INFO("No L2 interface for interface %d\n", ifindex);
		return ret;
	}

	RB_REMOVE(fal_opennsl_l2_intf_tree, &fal_opennsl_l2_intf_tree, intf);
	free(intf->kind);
	free(intf);

	return 0;
}

static void
fal_opennsl_add_cpu_to_vlan(int unit, uint16_t vlan)
{
	int rv;
	int cpu_count;
	opennsl_port_t port;
	opennsl_pbmp_t pbmp, upbmp;

	port = fal_opennsl_get_backplane_port();
	/* No backplane port, add the first CPU port */
	if (port == 0) {
		opennsl_port_config_t pcfg;

		rv = opennsl_port_config_get(unit, &pcfg);
		if (rv != OPENNSL_E_NONE) {
			ERROR("Failed to get port configuration. Error %s\n", opennsl_errmsg(rv));
			return;
		}
		OPENNSL_PBMP_COUNT(pcfg.cpu, cpu_count);
		if (cpu_count > 1) {
			OPENNSL_PBMP_ITER(pcfg.cpu, port) {
				// break at the first port
				break;
			}
		}
	}

	rv = opennsl_vlan_port_get(unit, vlan, &pbmp, &upbmp);
	if (rv != OPENNSL_E_NONE) {
		ERROR("Failed to get port members for VLAN %d. Error %s\n",
		      vlan, opennsl_errmsg(rv));
		return;
	}
	if (!OPENNSL_PBMP_MEMBER(pbmp, port)) {
		OPENNSL_PBMP_CLEAR(pbmp);
		OPENNSL_PBMP_PORT_SET(pbmp, port);
		OPENNSL_PBMP_CLEAR(upbmp);
		if (!fal_opennsl_chip_cfg[unit]->vlan_insert)
			OPENNSL_PBMP_PORT_SET(upbmp, port);


		rv = opennsl_vlan_port_add(unit, vlan, pbmp, upbmp);
		if (rv != OPENNSL_E_NONE) {
			ERROR("Failed to add CPU/backplane port to VLAN %d: %s\n",
			      vlan, opennsl_errmsg(rv));
			return;
		}
		OPENNSL_PBMP_COUNT(pbmp, cpu_count);
		INFO("%d CPU ports added to VLAN %d.\n", cpu_count, vlan);
	}
}

int
fal_opennsl_create_vlan(int unit, uint16_t vlan)
{
	int rv = opennsl_vlan_create(unit, vlan);
	if (rv != OPENNSL_E_NONE && rv != OPENNSL_E_EXISTS) {
		ERROR("%s: Failed to add vlan: %s\n", __func__, opennsl_errmsg(rv));
		return rv;
	}
	fal_opennsl_add_cpu_to_vlan(unit, vlan);

	if (fal_opennsl_chip_cfg[unit]->cfg_per_vlan_l2_learn_cpu_notif)
		rv = fal_opennsl_chip_cfg[unit]->cfg_per_vlan_l2_learn_cpu_notif(
			unit, vlan);
	else
		rv = OPENNSL_E_NONE;

	if (fal_opennsl_chip_cfg[unit]->alloc_vlan_stats)
		rv = fal_opennsl_chip_cfg[unit]->alloc_vlan_stats(unit, vlan);

	return rv;
}

int
fal_opennsl_vlan_get_ucast_flood_group(int unit, uint32_t vlan,
				   opennsl_multicast_t *ucast_flood_group)
{
	/* Assumes multicast group == vlan */
	*ucast_flood_group = vlan;
	return OPENNSL_E_NONE;
}


#ifdef DEBUG_BUILD
static void
fal_opennsl_print_pbmp(int unit, opennsl_pbmp_t pbmp)
{
	opennsl_port_t port;
	OPENNSL_PBMP_ITER(pbmp, port) {
		INFO("    %d:%d\n", unit, port);
	}
}

static int
fal_opennsl_print_vlan_data(int unit)
{
	opennsl_vlan_data_t *list;
	int count;
	OPENNSL_IF_ERROR_RETURN(opennsl_vlan_list(unit, &list, &count));
	opennsl_vlan_data_t *iter = list;
	for (int i = 0; i < count; i++) {
		INFO("Tagged Ports in VLAN %d\n", iter->vlan_tag);
		fal_opennsl_print_pbmp(unit, iter->port_bitmap);
		INFO("Untagged Ports in VLAN %d\n", iter->vlan_tag);
		fal_opennsl_print_pbmp(unit, iter->ut_port_bitmap);
		iter++;
	}
	opennsl_vlan_list_destroy(unit, list, count);
	return OPENNSL_E_NONE;
}
#else
static int
fal_opennsl_print_vlan_data(int unit)
{
	return 0;
}
#endif

static void
fal_opennsl_add_vlan_cb(uint16_t vlan, void *data)
{
	struct fal_opennsl_vlan_sync_data *sync_data = (struct fal_opennsl_vlan_sync_data *) data;
	opennsl_pbmp_t pbmp, upbmp;
	int rv;

	OPENNSL_PBMP_CLEAR(pbmp);
	OPENNSL_PBMP_CLEAR(upbmp);
	OPENNSL_PBMP_PORT_ADD(pbmp, sync_data->port);

	if (bridge_vlan_set_is_member(sync_data->untagged_vlans, vlan))
		OPENNSL_PBMP_PORT_ADD(upbmp, sync_data->port);

	rv = fal_opennsl_create_vlan(sync_data->unit, vlan);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to create VLAN %d\n", vlan);
		return;
	}

	INFO("Adding port %d:%d to vlan %d\n", sync_data->unit, sync_data->port, vlan);
	rv = opennsl_vlan_port_add(sync_data->unit, vlan, pbmp, upbmp);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to add port %d:%d to vlan %d: %s\n",
			sync_data->unit, sync_data->port, vlan, opennsl_errmsg(rv));
		return;
	}
	bridge_vlan_set_add(sync_data->vlans, vlan);
	fal_opennsl_print_vlan_data(sync_data->unit);
}

static void
fal_opennsl_remove_vlan_cb(uint16_t vlan, void *data)
{
	struct fal_opennsl_vlan_sync_data *sync_data = (struct fal_opennsl_vlan_sync_data *) data;
	opennsl_pbmp_t pbmp;

	OPENNSL_PBMP_CLEAR(pbmp);
	OPENNSL_PBMP_PORT_ADD(pbmp, sync_data->port);

	INFO("Removing port %d:%d from vlan %d\n", sync_data->unit, sync_data->port, vlan);
	int rv = opennsl_vlan_port_remove(sync_data->unit, vlan, pbmp);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to remove port %d:%d from vlan %d: %s\n",
			sync_data->unit, sync_data->port, vlan, opennsl_errmsg(rv));
		return;
	}
	bridge_vlan_set_remove(sync_data->vlans, vlan);
	fal_opennsl_print_vlan_data(sync_data->unit);
}

static void
fal_opennsl_add_untagged_vlan_cb(uint16_t vlan, void *data)
{
	struct fal_opennsl_vlan_sync_data *sync_data = (struct fal_opennsl_vlan_sync_data *) data;
	opennsl_pbmp_t pbmp, upbmp;

	OPENNSL_PBMP_CLEAR(pbmp);
	OPENNSL_PBMP_CLEAR(upbmp);
	OPENNSL_PBMP_PORT_ADD(pbmp, sync_data->port);
	OPENNSL_PBMP_PORT_ADD(upbmp, sync_data->port);

	if (OPENNSL_FAILURE(fal_opennsl_create_vlan(sync_data->unit, vlan))) {
		ERROR("Failed to create VLAN %d\n", vlan);
		return;
	}

	INFO("Adding port %d:%d to untagged egress vlan %d\n",
	     sync_data->unit, sync_data->port, vlan);
	int rv = opennsl_vlan_port_add(sync_data->unit, vlan, pbmp, upbmp);
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to add port %d:%d to untagged vlan %d: %s\n",
			sync_data->unit, sync_data->port, vlan, opennsl_errmsg(rv));
		return;
	}
	bridge_vlan_set_add(sync_data->untagged_vlans, vlan);
	fal_opennsl_print_vlan_data(sync_data->unit);
}

static void
fal_opennsl_remove_untagged_vlan_cb(uint16_t vlan, void *data)
{
	struct fal_opennsl_vlan_sync_data *sync_data = (struct fal_opennsl_vlan_sync_data *) data;
	opennsl_pbmp_t pbmp, upbmp;
	int rv;

	OPENNSL_PBMP_CLEAR(pbmp);
	OPENNSL_PBMP_CLEAR(upbmp);

	INFO("Removing port %d:%d from untagged egress vlan %d\n",
	     sync_data->unit, sync_data->port, vlan);

	if (bridge_vlan_set_is_member(sync_data->vlans, vlan)) {
		OPENNSL_PBMP_PORT_ADD(pbmp, sync_data->port);
		rv = opennsl_vlan_port_add(sync_data->unit, vlan, pbmp, upbmp);
	} else {
		rv = opennsl_vlan_port_remove(sync_data->unit, vlan, pbmp);
	}
	if (OPENNSL_FAILURE(rv)) {
		ERROR("Failed to remove port %d:%d to untagged vlan %d: %s\n",
			sync_data->unit, sync_data->port, vlan, opennsl_errmsg(rv));
		return;
	}
	bridge_vlan_set_remove(sync_data->untagged_vlans, vlan);
	fal_opennsl_print_vlan_data(sync_data->unit);
}

static void fal_opennsl_update_port_state(unsigned int child_ifindex, uint8_t state)
{
	int unit;
	opennsl_port_t port;
	struct opennsl_port *bport = NULL;

	int rv = fal_opennsl_lookup_port_info(child_ifindex, &unit, &port, &bport);
	if (rv < 0) {
		/* Not an OPENNSL port skip. */
		return;
	}

	switch (state) {
	case STP_IFSTATE_DISABLED:
		INFO("Port %d: STP state disable %d(%d)\n", port, state,
			 OPENNSL_STG_STP_DISABLE);
		opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_DISABLE);
		break;
	case STP_IFSTATE_LISTENING:
		INFO("Port %d: STP state listen %d(%d)\n", port, state,
			 OPENNSL_STG_STP_LISTEN);
		opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_LISTEN);
		break;
	case STP_IFSTATE_LEARNING:
		INFO("Port %d: STP state learn %d(%d)\n", port, state,
			 OPENNSL_STG_STP_LEARN);
		opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_LEARN);
		break;
	case STP_IFSTATE_FORWARDING:
		INFO("Port %d: STP state forward %d(%d)\n", port, state,
			 OPENNSL_STG_STP_FORWARD);
		opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_FORWARD);
		break;
	case STP_IFSTATE_BLOCKING:
		INFO("Port %d: STP state block %d(%d)\n", port, state,
			 OPENNSL_STG_STP_BLOCK);
		opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_BLOCK);
		break;
	}
}

static void fal_opennsl_update_port_pvid(unsigned int child_ifindex,
				     uint16_t pvid)
{
	int unit;
	opennsl_port_t port;
	struct opennsl_port *bport = NULL;
	int rv = fal_opennsl_lookup_port_info(child_ifindex, &unit, &port, &bport);

	if (rv < 0) {
		/* Not an OPENNSL port skip. */
		return;
	}

	INFO("Setting port %d:%d pvid to %d\n", unit, port, pvid);
	if (OPENNSL_FAILURE(opennsl_port_untagged_vlan_set(unit, port, pvid))) {
		ERROR("Failed to set pvid for port %d:%d\n", unit, port);
		return;
	}
	fal_opennsl_pmd_port_set_pvid(bport, pvid);
}

static void fal_opennsl_update_port_untagged_vlans(unsigned int child_ifindex,
					       struct bridge_vlan_set *untagged_vlans)
{
	int unit;
	opennsl_port_t port;
	struct opennsl_port *bport = NULL;
	int rv = fal_opennsl_lookup_port_info(child_ifindex, &unit, &port, &bport);

	if (rv < 0) {
		/* Not an OPENNSL port skip. */
		return;
	}

	/* Synchronize VLAN sets */
	struct bridge_vlan_set *old_vlans = fal_opennsl_pmd_port_get_vlans(bport);
	struct bridge_vlan_set *old_untagged_vlans = fal_opennsl_pmd_port_get_untagged_vlans(bport);
	struct fal_opennsl_vlan_sync_data sync_data = {
		.unit = unit,
		.port = port,
		.vlans = old_vlans,
		.untagged_vlans = old_untagged_vlans
	};

	bridge_vlan_set_synchronize(old_untagged_vlans, untagged_vlans,
				    fal_opennsl_add_untagged_vlan_cb, fal_opennsl_remove_untagged_vlan_cb,
				    &sync_data);
}

static void fal_opennsl_update_port_tagged_vlans(unsigned int child_ifindex,
					     struct bridge_vlan_set *vlans)
{
	int unit;
	opennsl_port_t port;
	struct opennsl_port *bport = NULL;
	int rv = fal_opennsl_lookup_port_info(child_ifindex, &unit, &port, &bport);

	if (rv < 0) {
		/* Not an OPENNSL port skip. */
		return;
	}

	/* Synchronize VLAN sets */
	struct bridge_vlan_set *old_vlans = fal_opennsl_pmd_port_get_vlans(bport);
	struct bridge_vlan_set *old_untagged_vlans = fal_opennsl_pmd_port_get_untagged_vlans(bport);
	struct fal_opennsl_vlan_sync_data sync_data = {
		.unit = unit,
		.port = port,
		.vlans = old_vlans,
		.untagged_vlans = old_untagged_vlans
	};

	bridge_vlan_set_synchronize(old_vlans, vlans,
				    fal_opennsl_add_vlan_cb, fal_opennsl_remove_vlan_cb,
				    &sync_data);
}

static void process_attribute(unsigned int child_ifindex,
                              const struct fal_attribute_t *attr)
{
	switch (attr->id) {
	case FAL_BRIDGE_PORT_ATTR_STATE:
		fal_opennsl_update_port_state(child_ifindex, attr->value.u8);
		break;
	case FAL_BRIDGE_PORT_ATTR_PORT_VLAN_ID:
		fal_opennsl_update_port_pvid(child_ifindex, attr->value.u16);
		break;
	case FAL_BRIDGE_PORT_ATTR_UNTAGGED_VLANS:
		fal_opennsl_update_port_untagged_vlans(child_ifindex,
				   (struct bridge_vlan_set *) attr->value.ptr);
		break;
	case FAL_BRIDGE_PORT_ATTR_TAGGED_VLANS:
		fal_opennsl_update_port_tagged_vlans(child_ifindex,
				(struct bridge_vlan_set *) attr->value.ptr);
		break;
	}
}

void fal_plugin_br_new_port(unsigned int bridge_ifindex,
			    unsigned int child_ifindex,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	unsigned int i;
	UNUSED(bridge_ifindex);

	for (i = 0; i < attr_count; i++) {
		const struct fal_attribute_t *attr = &attr_list[i];

		process_attribute(child_ifindex, attr);
	}
}

void fal_plugin_br_upd_port(unsigned int child_ifindex,
			    struct fal_attribute_t *attr)
{
	process_attribute(child_ifindex, attr);
}

void fal_plugin_br_del_port(unsigned int bridge_ifindex, unsigned int child_ifindex)
{
	UNUSED(bridge_ifindex);
	UNUSED(child_ifindex);
}

static int
fal_opennsl_add_update_l2_addr(int unit, uint16_t vlanid,
			   const struct rte_ether_addr *dst,
			   opennsl_gport_t port, bool update)
{
	opennsl_l2_addr_t l2_addr;
	opennsl_mac_t opennsl_mac;

	memcpy(&opennsl_mac, dst, sizeof(opennsl_mac));
	opennsl_l2_addr_t_init(&l2_addr, opennsl_mac, vlanid);
	l2_addr.port = port;
	l2_addr.flags |= OPENNSL_L2_STATIC;

	return opennsl_l2_addr_add(unit, &l2_addr);
}

static int
fal_opennsl_delete_l2_addr(int unit, uint16_t vlanid,
		       const struct rte_ether_addr *dst)
{
	opennsl_mac_t opennsl_mac;

	memcpy(&opennsl_mac, dst, sizeof(opennsl_mac));
	return opennsl_l2_addr_delete(unit, opennsl_mac, vlanid);
}

int
fal_opennsl_lookup_l2_addr(int unit, uint16_t vlanid,
		       const struct rte_ether_addr *dst,
		       opennsl_gport_t *port, bool *is_static)
{
	opennsl_l2_addr_t l2_addr;
	opennsl_mac_t opennsl_mac;
	int rv;

	memcpy(&opennsl_mac, dst, sizeof(opennsl_mac));

	rv = opennsl_l2_addr_get(unit, opennsl_mac, vlanid, &l2_addr);
	if (rv == OPENNSL_E_NONE) {
		*port = l2_addr.port;
		*is_static = l2_addr.flags & OPENNSL_L2_STATIC;
	}
	return rv;
}

void fal_plugin_br_new_neigh(unsigned int child_ifindex, uint16_t vlanid,
			     const struct rte_ether_addr *dst,
			     uint32_t attr_count,
			     const struct fal_attribute_t *attr_list)
{
	char addrstr[RTE_ETHER_ADDR_FMT_SIZE];
	uint16_t state = 0;
	opennsl_gport_t gport;
	int unit;
	int rv;
	int i;

	rte_ether_format_addr(addrstr, RTE_ETHER_ADDR_FMT_SIZE, dst);
	INFO("%s(child_ifindex %u, vlanid %hu, ethaddr %s)\n",
	     __func__, child_ifindex, vlanid, addrstr);

	if (vlanid == 0) {
		INFO("%s fdb add with no vlan ignored\n",
		     __func__);
		return;
	}

	rv = fal_opennsl_lookup_port_sysport(child_ifindex, &gport);
	if (rv < 0) {
		/* TODO: add trap/CPU entry for {vlanid, mac} */
		return;
	}

	for (i = 0; i < attr_count; i++) {
		const struct fal_attribute_t *attr = &attr_list[i];

		if (attr->id == FAL_BRIDGE_NEIGH_ATTR_STATE)
			state = attr->value.u16;
	}

	if (!(state & NUD_NOARP)) {
		INFO("%s Ignore new fdb as not static 0x%x\n",
			 __func__, state);
		return;
	}

	FOR_ALL_UNITS(unit) {
		rv = fal_opennsl_add_update_l2_addr(unit, vlanid, dst, gport, false);
		if (OPENNSL_FAILURE(rv)) {
			ERROR("Fdb %s add vlan %hu, unit %d port 0x%x failed: %s\n",
			      addrstr, vlanid, unit, gport, opennsl_errmsg(rv));
		} else
			INFO("Mac %s unit %d port 0x%x added",
			     addrstr, unit, gport);
	}
}

void fal_plugin_br_upd_neigh(unsigned int child_ifindex, uint16_t vlanid,
			     const struct rte_ether_addr *dst,
			     struct fal_attribute_t *attr)
{
	char addrstr[RTE_ETHER_ADDR_FMT_SIZE];
	uint16_t state = 0;
	opennsl_gport_t gport;
	bool is_static;
	int unit;
	int rv;

	rte_ether_format_addr(addrstr, RTE_ETHER_ADDR_FMT_SIZE, dst);
	INFO("%s(child_ifindex %u, vlanid %hu, ethaddr %s)\n",
	     __func__, child_ifindex, vlanid, addrstr);

	if (vlanid == 0) {
		INFO("%s fdb update with no vlan ignored\n",
		     __func__);
		return;
	}

	rv = fal_opennsl_lookup_port_sysport(child_ifindex, &gport);
	if (rv < 0) {
		/* TODO: add trap/CPU entry for {vlanid, mac} */
		return;
	}
	if (attr->id == FAL_BRIDGE_NEIGH_ATTR_STATE) {
		state = attr->value.u16;
	} else {
		INFO("%s Ignore fdb update, state not changed\n",
		     __func__);
		return;
	}
	/* If state changes to Static only then add,
	 * else we rely on switch learning on its own
	 */
	if (!(state & NUD_NOARP)) {
		FOR_ALL_UNITS(unit) {
			rv = fal_opennsl_lookup_l2_addr(unit, vlanid, dst, &gport,
						    &is_static);
			if (OPENNSL_FAILURE(rv)) {
				INFO("%s:MacEntry %s: %s",
				     __func__, addrstr, opennsl_errmsg(rv));
				continue;
			}
			if (!is_static) {
				INFO("MacEntry %s switch state not static",
				     addrstr);
				continue;
			}
			rv = fal_opennsl_delete_l2_addr(unit, vlanid, dst);
			if (OPENNSL_FAILURE(rv)) {
				ERROR("Mac %s unit %d port 0x%x delete failed: %s",
				      addrstr, unit, gport, opennsl_errmsg(rv));
			} else {
				INFO("Mac %s unit %d port 0x%x deleted",
				     addrstr, unit, gport);
			}
		}
		return;
	}

	FOR_ALL_UNITS(unit) {
		rv = fal_opennsl_add_update_l2_addr(unit, vlanid, dst, gport, true);
		if (OPENNSL_FAILURE(rv)) {
			ERROR("Fdb %s upd vlan %hu, unit %d, port 0x%x failed: %s\n",
			      addrstr, vlanid, unit, gport, opennsl_errmsg(rv));
		}
	}
}

void fal_plugin_br_del_neigh(unsigned int child_ifindex, uint16_t vlanid,
			     const struct rte_ether_addr *dst)
{
	char addrstr[RTE_ETHER_ADDR_FMT_SIZE];
	opennsl_gport_t gport;
	bool is_static;
	int unit;
	int rv;

	rte_ether_format_addr(addrstr, RTE_ETHER_ADDR_FMT_SIZE, dst);
	INFO("%s(child_ifindex %u, vlanid %hu, ethaddr %s)\n",
	     __func__, child_ifindex, vlanid, addrstr);

	if (vlanid == 0) {
		INFO("%s fdb delete with no vlan ignored\n",
		     __func__);
		return;
	}

	rv = fal_opennsl_lookup_port_sysport(child_ifindex, &gport);
	if (rv < 0) {
		/* TODO: delete trap/CPU entry for {vlanid, mac} */
		return;
	}

	FOR_ALL_UNITS(unit) {
		rv = fal_opennsl_lookup_l2_addr(unit, vlanid, dst, &gport, &is_static);
		if (OPENNSL_FAILURE(rv)) {
			INFO("%s:unit %d MacEntry %s: %s",
			     __func__, unit, addrstr, opennsl_errmsg(rv));
			continue;
		}
		if (!is_static) {
			INFO("MacEntry %s unit %d switch state not static",
			     addrstr, unit);
			continue;
		}
		rv = fal_opennsl_delete_l2_addr(unit, vlanid, dst);
		if (OPENNSL_FAILURE(rv)) {
			ERROR("Mac %s unit %d port 0x%x delete failed: %s",
			      addrstr, unit, gport, opennsl_errmsg(rv));
		} else {
			INFO("Mac %s unit %d port 0x%x deleted",
			     addrstr, unit, gport);
		}
	}
}

static int fal_plugin_opennsl_fdb_entry(int unit, opennsl_l2_addr_t *l2e, void *ud)
{
	json_writer_t *wr = ud;
	char namebuf[64];
	char macstr[32];

	jsonw_start_object(wr);
	snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x",
		 l2e->mac[0], l2e->mac[1], l2e->mac[2],
		 l2e->mac[3], l2e->mac[4], l2e->mac[5]);
	jsonw_string_field(wr, "mac", macstr);
	jsonw_string_field(wr, "port",
			   fal_opennsl_get_gport_name(unit, l2e->port, namebuf,
						  sizeof(namebuf)));
	jsonw_bool_field(wr, "static", l2e->flags & OPENNSL_L2_STATIC);
	jsonw_end_object(wr);

	return OPENNSL_E_NONE;
}

void fal_plugin_opennsl_fdb(FILE *f, int argc, char **argv)
{
	json_writer_t *wr;
	int vlan;
	int rv;

	if (argc != 2) {
		fprintf(f, "Usage: fal plugin opennsl fdb <vlan>\n");
		return;
	}
	vlan = atoi(argv[1]);

	wr = jsonw_new(f);
	if (!wr) {
		fprintf(f, "Could not allocate json writer\n");
		return;
	}

	jsonw_pretty(wr, true);
	jsonw_name(wr, "fdb");
	jsonw_start_object(wr);
	jsonw_start_array(wr);

	rv = opennsl_l2_traverse(0, fal_plugin_opennsl_fdb_entry, wr);

	jsonw_end_array(wr);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	if (OPENNSL_FAILURE(rv)) {
		fprintf(f,
			"Unable to get list of MAC addresses for unit 0, vlan %d: %s\n",
			vlan, opennsl_errmsg(rv));
		return;
	}
}

#define MAX_ETHER_PROTO 0xFFFF

static void fal_opennsl_enable_rx_framer(unsigned int if_index, bool enable)
{
	uint16_t dpdk_port;
	int unit;
	int rv;

	rv = fal_port_byifindex(if_index, &dpdk_port);
	if (rv < 0)
		return; /* Not a DPDK port */

	if (dpdk_port != fal_opennsl_get_backplane_dpdk_port())
		return; /* Not a backplane port */

	unit = 0; /* TBD fal_opennsl_get_backplane_unit() or similar */

	if (l2_hw_hdr_rx_enable(enable, dpdk_port, false, MAX_ETHER_PROTO,
				fal_opennsl_chip_cfg[unit]->rx_backplane_framer)) {
		INFO("%sabled framer on port %d\n",
		     enable ? "En" : "Dis", dpdk_port);
	} else {
		ERROR("Failed to %sable framer on dpdk port %d\n",
		      enable ? "en" : "dis", dpdk_port);
	}
	/* program driver to always punt packets regardless of errors */
	if (rte_pmd_ixgbe_upd_fctrl_sbp(dpdk_port, enable)) {
		ERROR("Failed %hu %sable ixgbe sbp\n", dpdk_port,
		      enable ? "en" : "dis");
	} else {
		INFO("Bkplane %hu %sable ixgbe sbp\n", dpdk_port,
		     enable ? "en" : "dis");
	}
}

void fal_plugin_l2_new_port(unsigned int if_index,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	struct fal_opennsl_l2_intf *intf;
	const char *kind = NULL;
	uint32_t ifi_type = 0;
	uint32_t i;
	int ret;

	INFO("%s(if_index %d, attr_count %d, ...)\n",
	     __func__, if_index, attr_count);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_PORT_ATTR_KIND:
			kind = attr_list[i].value.ptr;
			break;
		case FAL_PORT_ATTR_IFI_TYPE:
			ifi_type = attr_list[i].value.u32;
			break;
		case FAL_PORT_ATTR_DPDK_PORT:
		case FAL_PORT_ATTR_HW_SWITCH_MODE:
		case FAL_PORT_ATTR_IFI_FLAGS:
			/* not used */
			break;
		}
	}

	ret = fal_opennsl_l2_intf_create(if_index, kind, ifi_type, &intf);
	if (ret < 0) {
		ERROR("%s: L2 intf create for %d failed: %s\n",
		      __func__, if_index, strerror(-ret));
		return;
	}
}

int fal_plugin_l2_upd_port(unsigned int if_index, struct fal_attribute_t *attr)
{
	int rc = 0;

	INFO("%s(if_index %d, { id %d, ... })\n",
	     __func__, if_index, attr->id);

	switch (attr->id) {
	case FAL_PORT_ATTR_DPDK_PORT:
	case FAL_PORT_ATTR_KIND:
	case FAL_PORT_ATTR_PARENT_IFINDEX:
	case FAL_PORT_ATTR_IFI_TYPE:
		/* cannot happen */
		break;
	case FAL_PORT_ATTR_HW_SWITCH_MODE:
		break;
	case FAL_PORT_ATTR_IFI_FLAGS:
		if (attr->value.u32 & IFF_UP)
			fal_opennsl_enable_rx_framer(if_index, true);
		else
			fal_opennsl_enable_rx_framer(if_index, false);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

void fal_plugin_l2_del_port(unsigned int if_index)
{
	struct fal_opennsl_l2_intf *intf;
	int ret;

	INFO("%s(if_index %d)\n", __func__, if_index);

	ret = fal_opennsl_l2_intf_lookup(if_index, &intf);
	if (ret < 0) {
		ERROR("No L2 interface for interface %d\n", if_index);
		return;
	}
	fal_opennsl_l2_intf_delete(if_index);
}

int fal_plugin_vlan_get_stats(uint16_t vlan, uint32_t num_cntrs,
			      const enum fal_vlan_stat_type *cntr_ids,
			      uint64_t *cntrs)
{
	int rv = 0;
	int unit = 0;

	if (fal_opennsl_chip_cfg[unit]->get_vlan_stats)
		rv = fal_opennsl_chip_cfg[unit]->get_vlan_stats(unit, vlan,
							    num_cntrs,
							    cntr_ids, cntrs);

	return rv;
}

int fal_plugin_vlan_clear_stats(uint16_t vlan, uint32_t num_cntrs,
				const enum fal_vlan_stat_type *cntr_ids)
{
	int rv = 0;
	int unit = 0;

	if (fal_opennsl_chip_cfg[unit]->clear_vlan_stats)
		rv = fal_opennsl_chip_cfg[unit]->clear_vlan_stats(unit, vlan,
							      num_cntrs,
							      cntr_ids);
	return rv;
}
