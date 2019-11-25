/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef __FAL_OPENNSL_H__
#define __FAL_OPENNSL_H__

#include <opennsl/rx.h>

#include "pmd/rte_eth_opennslsw.h"
#include <fal_plugin.h>
#include <json_writer.h>

extern int fal_opennsl_ndevs;

enum rx_drop_reasons {
	RxDropMin,
	RxDropHdrParseFail,
	RxDropUnknownIntf,
	RxDropNoMempool,
	RxDropAllocFail,
	RxDropConvertFail,
	RxDropEnqFail,
	RxDropPktTooSmall,
	RxDropPktSizeMismatch,
	RxDropMax
};

enum tx_drop_reasons {
	TxDropMin,
	TxDropAllocFail,
	TxDropConvertFail,
	TxDropPrependFail,
	TxDropTxFail,
	TxDropMax
};

/*
 * Certain mirror commands can be used to recycle the packet. This
 * enum represents the static allocation of such commands to part of
 * the plugin that require them.
 */
enum fal_opennsl_mirror_cmds {
	FAL_OPENNSL_MIRROR_CMD_EG_MTU = 1,
};

enum fal_opennsl_rx_trap_strength {
	FAL_OPENNSL_RX_TRAP_STRENGTH_L3_DROP = 7,
	FAL_OPENNSL_RX_TRAP_STRENGTH_L3_EXCEPT_PUNT = 5,
	FAL_OPENNSL_RX_TRAP_STRENGTH_L3_PUNT = 3,
	FAL_OPENNSL_RX_TRAP_STRENGTH_L2_EG_EXCEPT_PUNT = 1,
};

enum fal_opennsl_switch_control {
	FAL_OPENNSL_SWITCH_CONTROL_ICMP_REDIR_TO_CPU,
};

struct opennsl_port_stats {
	uint64 rx_pkts;
	uint64 tx_pkts;
};

struct opennsl_stats {
	uint64 rx_pkts;
	uint64 rx_bytes;
	uint64 rx_drops[RxDropMax];
	uint64 tx_pkts;
	uint64 tx_bytes;
	uint64 tx_drops[TxDropMax];
	uint64 bp_rx_pkts;
	uint64 bp_rx_bytes;
	uint64 bp_tx_pkts;
	uint64 bp_tx_bytes;
	struct opennsl_port_stats pstats[OPENNSL_PBMP_PORT_MAX];
};

extern struct opennsl_stats opennsl_stats;

enum fal_opennsl_res_type {
	/* L3 Forwarding Equivalence Class - nexthop */
	FAL_OPENNSL_RES_FEC,
	/* L2/L3 multicast */
	FAL_OPENNSL_RES_MCAST,
};

/* flags to vary behaviour by chip */
struct fal_opennsl_chip_cfg {
	bool   crc_trim;     /* always trim CRC in rcvd packet */
	bool   vlan_insert;  /* always insert VLAN in transmitted packet */
	bool   hdr_insert;   /* insert DPP hdrs */

	/*
	 * Configure CPU notifications for L2 learning (including MAC
	 * moves and aging), but switch is free to continue learning
	 * addresses as it likes.
	 */
	int (*cfg_l2_learn_cpu_notif)(int unit);

	/*
	 * Configure per-VLAN CPU notifications for L2 learning
	 * (including MAC moves and aging), but switch is free to
	 * continue learning addresses as it likes.
	 */
	int (*cfg_per_vlan_l2_learn_cpu_notif)(int unit, uint32_t vid);

	/*
	 * Configure ICMP redirect trap on the port, it is then enabled globally
	 */
	int (*cfg_l3_per_port_punt_icmp_redir)(int unit, opennsl_port_t port);

	/*
	 * Configure trapping of packets that exceed the MTU of an L3 intf
	 */
	int (*cfg_l3_punt_too_big)(int unit);

	/*
	 * dump stat db
	 */
	int (*dump_stat_db)(int unit, json_writer_t *wr);

	/*
	 * dump/clear individual counter
	 */
	int (*cntr_cmd)(FILE *f, int argc, char **argv);

        /* allocate stats entries for vlan */
	int (*alloc_vlan_stats)(int unit, uint16_t vlan);

	/* free stats entries for vlan */
	int (*free_vlan_stats)(int unit, uint16_t vlan);

	/*
	 * get vlan statistics
	 */
	int (*get_vlan_stats)(int unit, uint16_t vlan, int num_cntrs,
			      const enum fal_vlan_stat_type *cntr_ids,
			      uint64_t *cntrs);

	/*
	 * clear vlan statistics
	 */
	int (*clear_vlan_stats)(int unit, uint16_t vlan, int num_cntrs,
				const enum fal_vlan_stat_type *cntr_ids);

	/*
	 * Pre-allocation of IDs for various resources
	 *
	 * Implementation for SDK resources is optional, in which case
	 * the fallback is to request that the SDK allocates the
	 * resource.
	 */
	int (*pre_alloc_res)(
		int unit, enum fal_opennsl_res_type type, uint32_t count,
		int *id_array, uint32_t *sdk_flags);
	/*
	 * Free a pre-allocated ID
	 */
	int (*pre_alloc_res_free)(
		int unit, enum fal_opennsl_res_type type, int id);

	/*
	 * Init
	 *
	 * Perform chip-specific per-unit initialisation.
	 */
	int (*init)(int unit);

	/*
	 * Port init
	 *
	 * Perform chip-specific per-port initialisation.
	 */
	int (*port_init)(int unit, opennsl_port_t port);

	/*
	 * configure backplane ports
	 */
	int (*configure_backplane_port)(int unit, opennsl_port_t port);

	/*
	 * backplane receive framer
	 */
	bool (*rx_backplane_framer)(struct rte_mbuf *mbuf, uint16_t *dpdk_port);

	/*
	 * backplane transmit framer
	 */
	int (*tx_backplane_framer)(void *sw_port,
				   void *fal_info, struct rte_mbuf **mbuf);
};

struct fal_opennsl_rx_trap_type_setup {
	opennsl_rx_trap_t type;
	const char *str;
	bool punt;
	opennsl_gport_t port;
	int strength;
};

extern const struct fal_opennsl_chip_cfg **fal_opennsl_chip_cfg;
extern const struct fal_opennsl_chip_cfg fal_opennsl_dpp_chip_cfg;
extern const struct fal_opennsl_chip_cfg fal_opennsl_hr3_chip_cfg;

extern bool l3_support;

int fal_opennsl_map_error_code(opennsl_error_t opennsl_error);

int fal_opennsl_l3_init(void);

void fal_opennsl_port_updown(int unit, opennsl_port_t port, bool up);

struct opennsl_port *fal_opennsl_lookup_port(int unit, int port);

int fal_opennsl_port_to_dpdk_port(int unit, opennsl_port_t port, uint16_t *dpdk_port);

int fal_opennsl_lookup_port_info(int ifindex, int *unit, opennsl_port_t *port,
			     struct opennsl_port **opennslport);

int fal_opennsl_port_to_system_port(int unit, opennsl_port_t port,
				    opennsl_gport_t *sysport);
int fal_opennsl_lookup_port_sysport(int ifindex, opennsl_gport_t *sysport);

void fal_plugin_opennsl_fdb(FILE *f, int argc, char **argv);
void fal_plugin_opennsl_shell_cmd(FILE *f, int argc, char **argv);

int fal_opennsl_lookup_l2_addr(int unit, uint16_t vlanid,
			   const struct ether_addr *dst,
			   opennsl_port_t *port, bool *is_static);

int fal_opennsl_vlan_get_ucast_flood_group(int unit, uint32_t vlan,
				       opennsl_multicast_t *ucast_flood_group);
int fal_opennsl_create_vlan(int unit, uint16_t vlan);

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * currently just a single backplane port.
 * May eventually support multiple backplane ports with
 * partitioning/load sharing
 */
opennsl_port_t fal_opennsl_get_backplane_port(void);

uint16_t fal_opennsl_get_backplane_dpdk_port(void);

bool fal_opennsl_is_backplane_port(opennsl_port_t port);

opennsl_port_t fal_opennsl_get_punt_port(void);

int fal_opennsl_rx_trap_unset(
	const struct fal_opennsl_rx_trap_type_setup *trap_setup);

int fal_opennsl_rx_trap_set(
	const struct fal_opennsl_rx_trap_type_setup *trap_setup);

/*
 * Get a port to be used as a source port from a mirror recycle
 */
opennsl_port_t fal_opennsl_get_dummy_mirror_port(int unit, unsigned int index);

char *fal_opennsl_get_gport_name(int unit, opennsl_port_t gport, char *buf,
			     size_t len);

int fal_opennsl_setup_storm_ctl_stats(int unit);
int fal_opennsl_destroy_storm_ctl_stats(int unit);

static inline int fal_opennsl_pre_alloc_res(
	int unit, enum fal_opennsl_res_type type, uint32_t count,
	int *id_array, uint32_t *sdk_flags)
{
	if (fal_opennsl_chip_cfg[unit]->pre_alloc_res)
		return fal_opennsl_chip_cfg[unit]->pre_alloc_res(
			unit, type, count, id_array,
			sdk_flags);
	else
		return 0;
}

static inline int fal_opennsl_pre_alloc_res_free(
	int unit, enum fal_opennsl_res_type type, int id)
{
	if (fal_opennsl_chip_cfg[unit]->pre_alloc_res_free)
		return fal_opennsl_chip_cfg[unit]->pre_alloc_res_free(
			unit, type, id);
	else
		return 0;
}

#endif
