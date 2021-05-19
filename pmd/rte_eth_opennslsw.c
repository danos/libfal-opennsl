/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright(c) 2016 Brocade Communications Systems
 * Adapted from DPDK ring PMD licensed as below:
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 */
/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This driver uses the OPENNSL SDK API for pkt TX and RX. We may want
 * to work with Broadcom in the future to implement a PMD that does
 * not go through this abstraction but talks directly to the hardware
 * as the KNET driver for linux does. There is not enough information
 * available to do this for the PoC.
 */

#include "../fal_opennsl_debug.h"

#include "rte_eth_opennslsw.h"
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_bus_vdev.h>

#include <opennsl/types.h>
#include <opennsl/error.h>
#include <opennsl/pkt.h>
#include <opennsl/tx.h>
#include <opennsl/port.h>
#include <opennsl/link.h>
#include <opennsl/stg.h>
#include <opennsl/stat.h>


#include <bridge_vlan_set.h>
#include "../fal_opennsl.h"
#include <vyatta_swport.h>
#include <fal_plugin.h>

#define ETH_OPENNSL_NAME_ARG "name"
#define ETH_OPENNSL_UNIT_ARG "unit"
#define ETH_OPENNSL_PORT_ARG "port"
#define ETH_OPENNSL_BPORT_ARG "bport"

#define OPENNSL_PMD_MAX_RX_QUEUE 1
#define OPENNSL_PMD_MAX_TX_QUEUE 1

struct opennsl_rx_queue {
	struct rte_ring *rx_ring;
	struct opennsl_port *port;
	rte_atomic64_t rx_pkts;
};

struct opennsl_tx_queue {
	struct opennsl_port *port;
	rte_atomic64_t tx_pkts;
	rte_atomic64_t err_pkts;
};

struct opennsl_port {
	uint16_t        port_id;
	char            *name;
	unsigned        numa_node;
	int             unit;
	opennsl_port_t      port;
	/* of type SYSTEM_PORT so has stack-wide significance */
	opennsl_gport_t     sysport;

	/* Only used in master thread no locking */
	struct bridge_vlan_set *vlans;
	struct bridge_vlan_set *untagged_vlans;

	uint16_t		pvid;
	void            *sw_port;

	struct rte_ether_addr address;
};

#ifndef ETH_LINK_DOWN
#define ETH_LINK_DOWN 0
#endif
#ifndef ETH_LINK_UP
#define ETH_LINK_UP 1
#endif

int fal_opennsl_port_to_dpdk_port(int unit, opennsl_port_t port, uint16_t *dpdk_port)
{
	struct opennsl_port *bport = fal_opennsl_lookup_port(unit, port);

	if (!bport)
		return -ENOENT;

	*dpdk_port = bport->port_id;
	return 0;
}

static int
convert_mbuf_to_pkt(int unit, opennsl_pkt_t *dest, struct rte_mbuf *src)
{
	//TODO: mbuf chains to pkt chains.
	//TODO: zerocopy conversions, copying is easier for demo
	int pkt_sz = rte_pktmbuf_data_len(src);
	if (src->nb_segs > 1) {
		INFO("Mbuf segs %d\n", src->nb_segs);
	}
	int sz = opennsl_pkt_memcpy(dest, 0,
		rte_pktmbuf_mtod(src, void *),
		pkt_sz);
	if (!sz) {
		ERROR("No bytes copied");
		return OPENNSL_E_MEMORY;
	}
	dest->call_back = NULL;
	dest->blk_count = 1;
	dest->unit      = unit;
	return OPENNSL_E_NONE;
}

static int opennsl_cmic_tx(int unit, opennsl_port_t port,
		       struct rte_mbuf *mbuf)
{
	int rv;
	opennsl_pkt_t *pkt = NULL;

	rv = opennsl_pkt_alloc(unit,
						   rte_pktmbuf_data_len(mbuf),
			       OPENNSL_TX_CRC_APPEND, &pkt);
	if (OPENNSL_FAILURE(rv)) {
		opennsl_stats.tx_drops[TxDropAllocFail]++;
		return rv;
	}
	rv = convert_mbuf_to_pkt(unit, pkt, mbuf);
	if (OPENNSL_FAILURE(rv)) {
		opennsl_stats.tx_drops[TxDropConvertFail]++;
		goto error;
	}
	OPENNSL_PBMP_PORT_SET(pkt->tx_pbmp, port);
	OPENNSL_PBMP_PORT_SET(pkt->tx_upbmp, port);
	rv = opennsl_tx(unit, pkt, NULL);
	if (OPENNSL_FAILURE(rv)) {
		opennsl_stats.tx_drops[TxDropTxFail]++;
		goto error;
	}

error:
	opennsl_pkt_free(unit, pkt);
	return rv;
}

static uint16_t
opennsl_cmic_tx_burst(void *fal_ctx, uint16_t bp __rte_unused,
		  uint16_t qid __rte_unused, struct rte_mbuf **bufs,
		  uint16_t nb_bufs)
{
	struct opennsl_port *port = fal_ctx;
	struct rte_mbuf *mbuf = NULL;
	int rv, i;

	for (i = 0; i < nb_bufs; i++) {
		mbuf = bufs[i];
		int mbuf_len = rte_pktmbuf_data_len(mbuf);
		if (mbuf_len == 0) {
			continue;
		}

		rv = opennsl_cmic_tx(port->unit, port->port, mbuf);
		if (rv != OPENNSL_E_NONE)
			break;

		opennsl_stats.tx_pkts++;
		opennsl_stats.tx_bytes += mbuf_len;
		rte_pktmbuf_free(mbuf);
	}
	return i;
}

static uint16_t
opennsl_bp_tx_burst(void *fal_ctx, uint16_t bp,
		uint16_t qid __rte_unused, struct rte_mbuf **bufs,
		uint16_t nb_bufs)
{
	int i;
	uint32_t bytes_to_send = 0, bytes_remaining = 0;
	uint16_t tx_pkts;

	for (i = 0; i < nb_bufs; i++) {
		bytes_to_send += rte_pktmbuf_data_len(bufs[i]);
	}
	tx_pkts = fal_tx_pkt_burst(bp, bufs, nb_bufs);
	opennsl_stats.bp_tx_pkts += tx_pkts;
	for (i = tx_pkts; i < nb_bufs; i++) {
		bytes_remaining += rte_pktmbuf_data_len(bufs[i]);
	}
	opennsl_stats.bp_tx_bytes += bytes_to_send - bytes_remaining;
	return tx_pkts;
}

static const char *
fal_opennsl_get_phy_type(opennsl_port_medium_t medium)
{
	switch (medium) {
	case OPENNSL_PORT_MEDIUM_NONE:
		return "none";
	case OPENNSL_PORT_MEDIUM_COPPER:
		return "copper";
	case OPENNSL_PORT_MEDIUM_FIBER:
		return "fiber";
	default:
		return "";
	}
}

static char *
fal_opennsl_port_name(struct opennsl_port *port)
{
	return opennsl_port_name(port->unit, port->port);
}

opennsl_port_t
fal_opennsl_pmd_port_get_port(struct opennsl_port *port)
{
	return port->port;
}

int
fal_opennsl_pmd_port_get_unit(struct opennsl_port *port)
{
	return port->unit;
}

opennsl_gport_t fal_opennsl_pmd_port_get_sysport(struct opennsl_port *port)
{
	return port->sysport;
}

/*
 * The opennsl and dpdk APIs can vary independently.
 * these functions allow the mapping of the
 * link state values, even though today they are
 * equivalent.
 */
uint32_t
fal_opennsl_port_opennsl_to_dpdk_speed(struct opennsl_port *port, int speed)
{
	DEBUG("OPENNSL(%s) link speed %d\n",
		fal_opennsl_port_name(port), speed);
	return speed;
}

uint16_t
fal_opennsl_port_opennsl_to_dpdk_duplex(struct opennsl_port *port, int duplex)
{
	DEBUG("OPENNSL(%s) link duplex %d\n",
		fal_opennsl_port_name(port), duplex);
	switch (duplex) {
	case OPENNSL_PORT_DUPLEX_FULL:
		return ETH_LINK_FULL_DUPLEX;
	default:
		return ETH_LINK_HALF_DUPLEX;
	}
}

static int fal_opennsl_dpdk_to_opennsl_duplex_speed(uint32_t dpdk_speeds, int *duplex)
{
	*duplex = OPENNSL_PORT_DUPLEX_FULL;

	if (dpdk_speeds & ETH_LINK_SPEED_100G)
		return ETH_SPEED_NUM_100G;
	else if (dpdk_speeds & ETH_LINK_SPEED_56G)
		return ETH_SPEED_NUM_56G;
	else if (dpdk_speeds & ETH_LINK_SPEED_50G)
		return ETH_SPEED_NUM_50G;
	else if (dpdk_speeds & ETH_LINK_SPEED_40G)
		return ETH_SPEED_NUM_40G;
	else if (dpdk_speeds & ETH_LINK_SPEED_25G)
		return ETH_SPEED_NUM_25G;
	else if (dpdk_speeds & ETH_LINK_SPEED_20G)
		return ETH_SPEED_NUM_20G;
	else if (dpdk_speeds & ETH_LINK_SPEED_10G)
		return ETH_SPEED_NUM_10G;
	else if (dpdk_speeds & ETH_LINK_SPEED_2_5G)
		return ETH_SPEED_NUM_2_5G;
	else if (dpdk_speeds & ETH_LINK_SPEED_1G)
		return ETH_SPEED_NUM_1G;
	else if (dpdk_speeds & ETH_LINK_SPEED_100M)
		return ETH_SPEED_NUM_100M;
	else if (dpdk_speeds & ETH_LINK_SPEED_100M_HD) {
		*duplex = OPENNSL_PORT_DUPLEX_HALF;
		return ETH_SPEED_NUM_100M;
	} else if (dpdk_speeds & ETH_LINK_SPEED_10M)
		return ETH_SPEED_NUM_10M;
	else if (dpdk_speeds & ETH_LINK_SPEED_10M_HD) {
		*duplex = OPENNSL_PORT_DUPLEX_HALF;
		return ETH_SPEED_NUM_10M;
	} else {
		INFO("Unsupported speed: 0x%x\n",
		     dpdk_speeds);
		/* in OPENNSL SDK 0 indicates set speed to max */
		return 0;
	}
}

static int
eth_link_update(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct rte_eth_link link, old;

	struct opennsl_port *bport = sw_port_fal_priv_from_dev(dev);
	int unit = bport->unit;
	opennsl_port_t port = bport->port;

	memset(&old, 0, sizeof(old));
	fal_opennsl_pmd_port_read_link(bport, &old);

	opennsl_port_info_t info;
	opennsl_port_info_t_init(&info);
	info.action_mask = OPENNSL_PORT_ATTR_SPEED_MASK |
		OPENNSL_PORT_ATTR_AUTONEG_MASK |
		OPENNSL_PORT_ATTR_DUPLEX_MASK |
		OPENNSL_PORT_ATTR_LINKSTAT_MASK;

	int link_check = opennsl_port_selective_get(unit, port, &info);
	if (link_check == OPENNSL_E_NONE) {
		DEBUG("OPENNSL(%s) link {speed: %d, duplex: %d, linkstatus: %d, autoneg %d}\n",
			  fal_opennsl_port_name(bport), info.speed, info.duplex, info.linkstatus,
			  info.autoneg);
		link.link_speed = fal_opennsl_port_opennsl_to_dpdk_speed(bport, info.speed);
		link.link_duplex = fal_opennsl_port_opennsl_to_dpdk_duplex(bport, info.duplex);
		link.link_status = fal_opennsl_port_opennsl_to_dpdk_status(bport, info.linkstatus);
	} else {
		link.link_speed = 0;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_status = ETH_LINK_DOWN;
	}

	sw_port_fal_report_link(bport->sw_port, &link);
	if (old.link_status == link.link_status)
		return -1;

	return 0;
}

static int
eth_dev_set_link(struct rte_eth_dev *dev, int state)
{
	struct opennsl_port *port = sw_port_fal_priv_from_dev(dev);
	opennsl_port_info_t info;

	opennsl_port_info_t_init(&info);
	info.action_mask = OPENNSL_PORT_ATTR_ENABLE_MASK |
			   OPENNSL_PORT_ATTR_MEDIUM_MASK;
	opennsl_port_selective_get(port->unit, port->port, &info);

	DEBUG(
		"OPENNSL(%s) setting phy state to \"%s\" was \"%s\" on \"%s\" phy\n",
		fal_opennsl_port_name(port),
		state ? "on" : "off",
		info.enable ? "on" : "off",
		fal_opennsl_get_phy_type(info.medium));

	opennsl_port_info_t_init(&info);
	info.enable = state;
	info.action_mask = OPENNSL_PORT_ATTR_ENABLE_MASK;
	opennsl_port_selective_set(port->unit, port->port, &info);

	fal_opennsl_port_updown(port->unit, port->port,
			    state == ETH_LINK_UP);

	return 0;
}

static int
eth_dev_set_link_down(struct rte_eth_dev *dev)
{
	return eth_dev_set_link(dev, ETH_LINK_DOWN);
}

static int
eth_dev_set_link_up(struct rte_eth_dev *dev)
{
	int ret = eth_dev_set_link(dev, ETH_LINK_UP);

	/* check if the link is up immediately */
	if (ret >= 0)
		eth_link_update(dev, 0);

	return ret;
}

uint16_t
fal_opennsl_port_opennsl_to_dpdk_status(struct opennsl_port *port, int linkstatus)
{
	DEBUG("OPENNSL(%s) link status %d\n",
		fal_opennsl_port_name(port), linkstatus);
	switch (linkstatus) {
	case OPENNSL_PORT_LINK_STATUS_UP:
		return 1;
	default:
		return 0;
	}
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	struct opennsl_port *bport = sw_port_fal_priv_from_dev(dev);
	int unit = bport->unit;
	opennsl_port_t port = bport->port;
	opennsl_port_info_t info;

	int rv;
	char *msg = NULL;

#define INIT_CHECK(action, description)			\
	if ((rv = (action)) < 0) {					\
		msg = (description);					\
		goto done;								\
	}

	DEBUG("setting up port %s\n", opennsl_port_name(unit, port));

	INIT_CHECK(
		opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_FORWARD),
		"STP Forwarding");

	INIT_CHECK(opennsl_port_learn_set(unit, port,
			OPENNSL_PORT_LEARN_ARL |
			OPENNSL_PORT_LEARN_FWD),
		"Port learning");

	opennsl_port_info_t_init(&info);

	INIT_CHECK(
		opennsl_port_ability_local_get(unit, port, &info.local_ability),
		"Port ability");

	info.pause_rx = OPENNSL_PORT_ABILITY_PAUSE_RX;
	info.pause_tx = OPENNSL_PORT_ABILITY_PAUSE_TX;
	info.linkscan = OPENNSL_LINKSCAN_MODE_SW;
	info.enable   = 1;

	info.action_mask = (OPENNSL_PORT_ATTR_PAUSE_RX_MASK |
			    OPENNSL_PORT_ATTR_PAUSE_TX_MASK |
			    OPENNSL_PORT_ATTR_LINKSCAN_MASK |
			    OPENNSL_PORT_ATTR_AUTONEG_MASK |
			    OPENNSL_PORT_ATTR_ENABLE_MASK |
			    OPENNSL_PORT_ATTR_LOCAL_ADVERT_MASK);
	info.action_mask2 = OPENNSL_PORT_ATTR2_PORT_ABILITY;

	if (dev->data->dev_conf.link_speeds == ETH_LINK_SPEED_AUTONEG) {
		info.autoneg = true;
	} else {
		info.action_mask |= OPENNSL_PORT_ATTR_SPEED_MASK |
			OPENNSL_PORT_ATTR_DUPLEX_MASK;
		info.autoneg = false;
		info.speed = fal_opennsl_dpdk_to_opennsl_duplex_speed(
			dev->data->dev_conf.link_speeds,
			&info.duplex);
	}

	INIT_CHECK(opennsl_port_selective_set(unit, port, &info),
			   "Port settings");

	eth_dev_set_link_up(dev);
	return 0;

done:
	ERROR("port %s, failed to initialize: %s\n",
		  opennsl_port_name(unit, port), msg);
	return -1;
}

static int
eth_dev_stop(struct rte_eth_dev *dev)
{
	struct opennsl_port *bport = sw_port_fal_priv_from_dev(dev);
	int unit = bport->unit;
	opennsl_port_t port = bport->port;
	opennsl_port_info_t info;

	int rv;
	char *msg = NULL;

#define INIT_CHECK(action, description)			\
	if ((rv = (action)) < 0) {					\
		msg = (description);					\
		goto done;								\
	}

	eth_dev_set_link_down(dev);
	INIT_CHECK(opennsl_stg_stp_set(unit, 1, port, OPENNSL_STG_STP_DISABLE),
			   "STP Disabled");

	opennsl_port_info_t_init(&info);
	info.enable = 0;
	info.action_mask |=  OPENNSL_PORT_ATTR_ENABLE_MASK;
	INIT_CHECK(opennsl_port_selective_set(unit, port, &info),
			   "Port settings");

	return 0;
done:
	ERROR("port %s, failed to initialize: %s\n",
		  opennsl_port_name(unit, port), msg);
	return -EINVAL;
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	/* Get these stats from HW */
	opennsl_stat_val_t opennsl_stats[] = {opennsl_spl_snmpEtherStatsRXNoErrors,
					  opennsl_spl_snmpEtherStatsTXNoErrors,
					  opennsl_spl_snmpIfInOctets,
					  opennsl_spl_snmpIfOutOctets,
					  opennsl_spl_snmpIfInErrors,
					  opennsl_spl_snmpIfOutErrors};
	uint64_t vals[ARRAY_SIZE(opennsl_stats)] = { 0 };
	struct opennsl_port *port =  sw_port_fal_priv_from_dev(dev);
	int rc;

	rc = opennsl_stat_multi_get(port->unit, port->port,
								ARRAY_SIZE(opennsl_stats),
								opennsl_stats, vals);
	if (rc)
		ERROR("Cannot get stats for port %d\n", port->port);

	stats->ipackets = vals[0];
	stats->opackets = vals[1];
	stats->ibytes = vals[2];
	stats->obytes = vals[3];
	stats->ierrors = vals[4];
	stats->oerrors = vals[5];

	return 0;
}

static int
eth_stats_reset(struct rte_eth_dev *dev)
{
	return 0;
}

static void
eth_mac_addr_remove(struct rte_eth_dev *dev __rte_unused,
	uint32_t index __rte_unused)
{
}

static int
eth_mac_addr_add(struct rte_eth_dev *dev __rte_unused,
	struct rte_ether_addr *mac_addr __rte_unused,
	uint32_t index __rte_unused,
	uint32_t vmdq __rte_unused)
{
	return 0;
}

static int
eth_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	uint32_t max_frame = mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
	struct opennsl_port *bport = sw_port_fal_priv_from_dev(dev);
	int unit = bport->unit;
	opennsl_port_t port = bport->port;

	/* Set MRU */
	if (opennsl_port_frame_max_set(unit, port, max_frame) != OPENNSL_E_NONE) {
		ERROR("OPENNSL(%s) failed to set mru %d\n",
		      fal_opennsl_port_name(bport), mtu);
		return -EINVAL;
	}

	/*
	 * MTU and MRU are slightly conflated in DPDK (as can be seen
	 * by the naming of the API) and dataplane really sets MRU to
	 * be the same as MTU. On an interface being used with a
	 * software dataplane only the MTU doesn't matter to the
	 * driver as it is enforced in the software forwarding path,
	 * but with hardware switching it does matter and does need to
	 * know. So also set the link-layer MTU here.
	 */
	opennsl_error_t rv = opennsl_port_l3_encapsulated_mtu_set(unit, port, max_frame);
	if (rv != OPENNSL_E_NONE && rv != OPENNSL_E_UNAVAIL) {
		ERROR("OPENNSL(%s) failed to set mtu %d\n",
			  fal_opennsl_port_name(bport), mtu);
		return -EINVAL;
	}
	return 0;
}

static int
eth_dev_infos_get(struct rte_eth_dev *dev,
		  struct rte_eth_dev_info *dev_info)
{
	struct opennsl_port *bport = sw_port_fal_priv_from_dev(dev);
	int unit = bport->unit;
	opennsl_port_t port = bport->port;
	opennsl_port_ability_t ability_mask = { 0 };
	int rv;
	unsigned int i;
	struct ability_mapping {
		uint64_t bcm_ability;
		uint64_t dpdk_capa;
	} ability_mappings[] = {
		{ OPENNSL_PORT_ABILITY_10MB, ETH_LINK_SPEED_10M },
		{ OPENNSL_PORT_ABILITY_100MB, ETH_LINK_SPEED_100M },
		{ OPENNSL_PORT_ABILITY_1000MB, ETH_LINK_SPEED_1G },
		{ OPENNSL_PORT_ABILITY_2500MB, ETH_LINK_SPEED_2_5G },
		{ OPENNSL_PORT_ABILITY_5000MB, ETH_LINK_SPEED_5G },
		{ OPENNSL_PORT_ABILITY_10GB, ETH_LINK_SPEED_10G },
		{ OPENNSL_PORT_ABILITY_20GB, ETH_LINK_SPEED_20G },
		{ OPENNSL_PORT_ABILITY_25GB, ETH_LINK_SPEED_25G },
		{ OPENNSL_PORT_ABILITY_40GB, ETH_LINK_SPEED_40G },
		{ OPENNSL_PORT_ABILITY_50GB, ETH_LINK_SPEED_50G },
		{ OPENNSL_PORT_ABILITY_100GB, ETH_LINK_SPEED_100G },
	};
	struct ability_mapping *amp;

	rv = opennsl_port_ability_local_get(unit, port, &ability_mask);
	if (rv != OPENNSL_E_NONE) {
		ERROR("BCM(%s) failed to get port abilities!\n",
		      fal_opennsl_port_name(bport));
		return -ENOTSUP;
	}

	dev_info->speed_capa = 0;
	for (i = 0, amp = ability_mappings;
	     i < ARRAY_SIZE(ability_mappings); i++, amp++) {
		if (ability_mask.speed_full_duplex & amp->bcm_ability)
			dev_info->speed_capa |= amp->dpdk_capa;
	}

	if (ability_mask.speed_half_duplex & OPENNSL_PORT_ABILITY_10MB)
			dev_info->speed_capa |= ETH_LINK_SPEED_10M_HD;
	if (ability_mask.speed_half_duplex & OPENNSL_PORT_ABILITY_100MB)
			dev_info->speed_capa |= ETH_LINK_SPEED_100M_HD;

	return 0;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	uint16_t mtu = dev->data->dev_conf.rxmode.max_rx_pkt_len -
		RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
	return eth_mtu_set(dev, mtu);
}

static const struct eth_dev_ops eth_ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_set_link_up = eth_dev_set_link_up,
	.dev_set_link_down = eth_dev_set_link_down,
	.dev_configure = eth_dev_configure,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
	.mac_addr_remove = eth_mac_addr_remove,
	.mac_addr_add = eth_mac_addr_add,
	.mtu_set = eth_mtu_set,
	.dev_infos_get = eth_dev_infos_get,
};

/*copied from dpdk because rte_memcpy can't expand in this context*/
static inline void random_mac_addr(uint8_t *addr)
{
	uint64_t rand = rte_rand();
	uint8_t *p = (uint8_t*)&rand;

	memcpy(addr, p, RTE_ETHER_ADDR_LEN);
	addr[0] &= ~RTE_ETHER_GROUP_ADDR;       /* clear multicast bit */
	addr[0] |= RTE_ETHER_LOCAL_ADMIN_ADDR;  /* set local assignment bit */
}


static int
fal_opennsl_create_bport(const char *name, int unit, opennsl_port_t lport,
		     opennsl_gport_t sysport, struct opennsl_port **bport)
{
	struct opennsl_port *port = NULL;

	port = rte_zmalloc_socket(name, sizeof(*port), 0, SOCKET_ID_ANY);
	if (port == NULL) {
		rte_errno = ENOMEM;
		goto error;
	}

	port->unit = unit;
	port->port = lport;
	port->sysport = sysport;
	port->vlans = bridge_vlan_set_create();
	if (port->vlans == NULL) {
		rte_errno = ENOMEM;
		goto error;
	}
	port->untagged_vlans = bridge_vlan_set_create();
	if (port->untagged_vlans == NULL) {
		rte_errno = ENOMEM;
		goto error;
	}

	*bport = port;

	return 0;

error:
	free(port->vlans);
	free(port->untagged_vlans);
	rte_free(port);

	return -1;
}

static int fal_opennsl_create_swport(const char *name, int unit, opennsl_port_t port,
				 opennsl_gport_t sysport, struct opennsl_port **bport)
{
	struct sw_port_create_args swport;
	opennsl_port_t bp = fal_opennsl_get_backplane_port();

	memset(&swport, 0, sizeof(swport));

	if (fal_opennsl_create_bport(name, unit, port, sysport, bport)) {
		ERROR("Could not create opennsl_port for %s\n", name);
		goto error;
	}

	swport.hw_unit = unit;
	swport.hw_port = port;
	swport.port_name = name;
	swport.plugin_dev_ops = &eth_ops;
	swport.plugin_private = *bport;
	swport.prep_header_change = fal_prepare_for_header_change;
	swport.prep_header_change_bytes = sizeof(struct rte_ether_hdr);
	swport.rx_queues = SW_P_PMD_MAX_RX_QUEUE;
	swport.flags = SWITCH_PORT_FLAG_INTR_LSC;

	if (fal_opennsl_chip_cfg[unit]->hdr_insert)
		swport.plugin_tx_framer =
				fal_opennsl_chip_cfg[unit]->tx_backplane_framer;

	if (bp) {
		swport.bp_interconnect_port = fal_opennsl_get_backplane_dpdk_port();
		swport.plugin_tx = opennsl_bp_tx_burst;
		/* we support as many as there are cores */
		swport.tx_queues = rte_lcore_count();
	} else {
		swport.flags |= SWITCH_PORT_FLAG_RX_RING_CREATE;
		if (fal_opennsl_chip_cfg[unit]->vlan_insert)
			swport.flags |= SWITCH_PORT_FLAG_TX_FRAMER_VLAN_INSERT;
		swport.plugin_tx = opennsl_cmic_tx_burst;
		/*
		 * It's unclear whether opennsl_tx is thread-safe or not,
		 * so play it safe and only support the one queue.
		 */
		swport.tx_queues = 1;
	}

	if (sw_port_create(&swport)) {
		ERROR("Could not create swport for %s\n", name);
		goto error;
	}
	(*bport)->port_id = swport.dpdk_port_id;
 	(*bport)->sw_port = swport.fal_switch_port;
	return 0;

error:
	rte_free(*bport);
	return -1;
}

/*
 * opennsl_register_rte_eth creates DPDK VDEV representations of
 * the switch ports. It returns an opaque pointer to the port structure
 * it creates as 'bport' so it may be used by the RX callback function.
 * when successful.
 */
int
fal_opennsl_pmd_register_rte_eth(const char *name, int unit, opennsl_port_t port,
			     opennsl_gport_t sysport, struct opennsl_port **bport)
{
	int rv;
	char *msg = NULL;
	char pmd_name[32] = { 0 };
	char args_str[64] = { 0 };

#define INIT_CHECK(action, description)			\
	if ((rv = (action)) < 0) {					\
		msg = (description);					\
		goto done;								\
	}

	INIT_CHECK(
		opennsl_stat_clear(unit, port), "Stat clear");

	/*
	INIT_CHECK(opennsl_port_vlan_member_set(unit, port,
										OPENNSL_PORT_VLAN_MEMBER_INGRESS|
										OPENNSL_PORT_VLAN_MEMBER_EGRESS),
			   "VLAN filtering");
	*/

	snprintf(pmd_name, 32, "net_opennsl%s", name);
	snprintf(args_str, 64, "%s=%s,%s=%d,%s=%d,%s=%p",
			       ETH_OPENNSL_NAME_ARG, name,
			       ETH_OPENNSL_UNIT_ARG, unit,
			       ETH_OPENNSL_PORT_ARG, port,
			       ETH_OPENNSL_BPORT_ARG, bport);

	INIT_CHECK(fal_opennsl_create_swport(name, unit, port, sysport, bport),
			   "SW port create");

	return 0;

done:
	ERROR("port %s, failed to initialize: %s\n",
		  opennsl_port_name(unit, port), msg);
	return rv;

}

/*
 * opennsl_port_enqueue_rx_mbuf is the interface to the pmd for the callback
 * from the Broadcom SDK. The CB function is responsible for converting
 * opennsl_pkt_t to rte_mbuf and passing the resulting bufs.
 */
int
fal_opennsl_pmd_port_enqueue_rx_mbuf(struct opennsl_port *port, struct rte_mbuf **bufs,
								 int nb_bufs)
{
	return sw_port_enqueue_rx_mbuf(port->sw_port, 0, bufs, nb_bufs);
}

uint16_t
fal_opennsl_pmd_port_get_portid(struct opennsl_port *port)
{
	return port->port_id;
}

struct bridge_vlan_set *
fal_opennsl_pmd_port_get_vlans(struct opennsl_port *port)
{
	return port->vlans;
}

struct bridge_vlan_set *
fal_opennsl_pmd_port_get_untagged_vlans(struct opennsl_port *port)
{
	return port->untagged_vlans;
}

int fal_opennsl_pmd_port_set_link(struct opennsl_port *port, struct rte_eth_link *link)
{
	return sw_port_fal_report_link_intr(port->sw_port, link);
}

int fal_opennsl_pmd_port_read_link(struct opennsl_port *port,
							   struct rte_eth_link *link)
{
	return sw_port_fal_get_link(port->sw_port, link);
}

void fal_opennsl_pmd_port_set_pvid(struct opennsl_port *port, uint16_t pvid)
{
	port->pvid = pvid;
	rte_smp_mb();
}

uint16_t fal_opennsl_pmd_port_get_pvid(struct opennsl_port *port)
{
	return port->pvid;
}
