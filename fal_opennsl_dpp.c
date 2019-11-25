/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * The header definitions in this file are based on the descriptions in
 * - 88470 TM Architecture - 88470_88476-AG207-R and
 * - on-box experiments
 * They do not correspond exactly to the definition in soc/dpp/headers.h
 */

#include <stdbool.h>
#include <opennsl/types.h>
#include <opennsl/error.h>
#include <opennsl/l3.h>
#include <opennsl/multicast.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include "fal_opennsl.h"
#include "fal_opennsl_debug.h"
#include "fal_opennsl_id_mgr.h"


#define DPP_HDR_ITMH_BASE_LEN               (4)
#define DPP_HDR_PTCH_LEN                    (2)
#define DPP_HDR_FTMH_BASE_LEN               (9)
#define DPP_HDR_SYSH1_LEN                   (7)
#define DPP_HDR_SYSH2_LEN                   (3)
#define DPP_HW_CRC_LEN                      (2)

static const uint32_t RSRVED_VLAN_FLOOD_MCAST_GRPS = 4096;

/*
 * Table of FEC IDs for manual allocation
 */
struct fal_opennsl_id_table *fal_opennsl_fec_id_table;

/*
 * Table of multicast IDs for since allocation by SDK isn't supported
 */
struct fal_opennsl_id_table *fal_opennsl_mcast_id_table;

static inline int insert_itmh(struct rte_mbuf *src, opennsl_port_t port)
{
	uint8_t *itmh_base;
	int itmh_size = DPP_HDR_ITMH_BASE_LEN;

	itmh_base = (uint8_t *)rte_pktmbuf_prepend(src, itmh_size);
	if (!itmh_base)
		return -1;

	memset(itmh_base, 0, itmh_size);

	/*
	 * 3 msb of destination of FWD_DEST_INFO, value 001 indicates
	 * that the final 16 bits represent the system port.
	 */
	itmh_base[0] = 1;
	itmh_base[1] = (port >> 8) & 0xff; // high 8 bits of port
	itmh_base[2] = (port & 0xff);      // low 8 bits of port
	itmh_base[3] = 0;
	return itmh_size;
}

static inline int insert_ptch(struct rte_mbuf *src, opennsl_port_t port)
{
	uint8_t *ptch_base;
	int ptch_size = DPP_HDR_PTCH_LEN;

	ptch_base = (uint8_t *)rte_pktmbuf_prepend(src, ptch_size);
	if (!ptch_base)
		return -1;

	memset(ptch_base, 0, ptch_size);

	ptch_base[0] = 0x50;
	ptch_base[1] = 0;
	return ptch_size;
}

static int
extend_mbuf(struct rte_mbuf *mbuf) {
	int min_sz = ETHER_MIN_LEN - ETHER_CRC_LEN;
	int pkt_sz = rte_pktmbuf_data_len(mbuf);
	int sz = pkt_sz > min_sz ? pkt_sz : min_sz;
	if (sz != min_sz)
		return 0;
	sz = min_sz - pkt_sz;
	char *buf = rte_pktmbuf_append(mbuf, sz);
	if (buf == NULL)
		return -1;
	memset(buf, 0, sz);
	return 0;
}

static int fal_opennsl_dpp_insert_hdrs(struct opennsl_port *port,
				       struct rte_mbuf **mbuf)
{
	int size = 0;
	opennsl_port_t bport = fal_opennsl_pmd_port_get_port(port);

	if (fal_opennsl_get_backplane_port() == 0) {	
		if (((*mbuf)->ol_flags & PKT_TX_VLAN_PKT)) {
			if (rte_vlan_insert(mbuf)) {
				ERROR("Failed to insert vlan for packet %p\n", mbuf);
				return -ENOMEM;
			}
		}
		(*mbuf)->ol_flags &= ~PKT_TX_VLAN_PKT;

		if (extend_mbuf(*mbuf) < 0) {
			opennsl_stats.tx_drops[TxDropAllocFail]++;
			return -ENOMEM;
		}
	}

	if ((size = insert_itmh(*mbuf, bport)) < 0) {
		opennsl_stats.tx_drops[TxDropPrependFail]++;
		return -ENOMEM;
	}

	if ((size = insert_ptch(*mbuf, bport)) < 0) {
		opennsl_stats.tx_drops[TxDropPrependFail]++;
		return -ENOMEM;
	}

	opennsl_stats.pstats[bport].tx_pkts++;
	return 0;
}


static int fal_opennsl_insert_hdrs(void *sw_port __rte_unused,
			       void *fal_info,
			       struct rte_mbuf **buf)
{
	struct opennsl_port *bport = fal_info;
	int rc;

	rc = fal_opennsl_dpp_insert_hdrs(bport, buf);
	if (rc < 0)
		return rc;
	return 0;
}

/*
 * FTMH fields.
 * This representation is for software convenience.
 */
struct ftmh_base {
	uint16_t   pkt_size;
	uint16_t   sys_port;
	uint8_t    type;
};

/*
 * Parse the FTMH and System headers
 *
 * Returns length of optional headers present.
 */
static int parse_ftmh_and_sys_header(struct rte_mbuf *mbuf, struct ftmh_base *ftmh,
									 int *trap_code)
{
	uint8_t *internal_base;
	int opt_hdr_len = 0;
	uint8_t *ftmh_base;
	int ext_2;
	int ext_3;
	uint8_t ext_4;

	memset(ftmh, 0, sizeof(struct ftmh_base));
	ftmh_base = rte_pktmbuf_mtod(mbuf, void *);
	ftmh->pkt_size = ((ftmh_base[0] << 6) | ((ftmh_base[1] & 0xFC) >> 2));
	ftmh->sys_port = ((ftmh_base[2] & 0x7F) << 9 |
					  (ftmh_base[3] << 1) |
					  (ftmh_base[4] & 0x80) >> 7);
	ftmh->type = (ftmh_base[6] & 0x06) >> 1;
	internal_base = ftmh_base + DPP_HDR_FTMH_BASE_LEN;
	ext_2 = (internal_base[0] & 0x40) >> 6;
	ext_3 = (internal_base[0] & 0x80) >> 7;
	ext_4 = (internal_base[0] & 0x30) >> 4;

	switch (ext_4) {
	case 1: /* the common case */
		opt_hdr_len += DPP_HDR_SYSH2_LEN;
		break;
	case 2:
		opt_hdr_len += 5;
		break;
	case 3:
		opt_hdr_len += 8;
		break;
	}

	if (ext_4) {
		int trap_info_offset = DPP_HDR_SYSH1_LEN + opt_hdr_len - DPP_HDR_SYSH2_LEN;
		*trap_code = internal_base[trap_info_offset + 2];
	} else {
		*trap_code = -1;
	}

	if (ext_3)
		opt_hdr_len += 3;
	if (ext_2)
		opt_hdr_len += 5;

	return opt_hdr_len;
}

static int fal_bcm_dpp_backplane_rx(struct rte_mbuf *mbuf, uint16_t *dpdk_port)
{
	int hdr_len = DPP_HDR_FTMH_BASE_LEN + DPP_HDR_SYSH1_LEN + DPP_HW_CRC_LEN;
	struct ftmh_base ftmh;
	int trap_code;
	int err;

	if (rte_pktmbuf_data_len(mbuf) < hdr_len - DPP_HW_CRC_LEN) {
		opennsl_stats.rx_drops[RxDropPktTooSmall]++;
		return -1;
	}

	hdr_len += parse_ftmh_and_sys_header(mbuf, &ftmh, &trap_code);

	if (ftmh.pkt_size < hdr_len) {
		opennsl_stats.rx_drops[RxDropPktTooSmall]++;
		return -1;
	}
	ftmh.pkt_size -= hdr_len;

	rte_pktmbuf_adj(mbuf, hdr_len - DPP_HW_CRC_LEN);

	if (ftmh.pkt_size != rte_pktmbuf_pkt_len(mbuf)) {
		opennsl_stats.rx_drops[RxDropPktSizeMismatch]++;
		return -1;
	}

	// TODO: multiple units
	err = fal_opennsl_port_to_dpdk_port(0, ftmh.sys_port, dpdk_port);
	if (err < 0) {
		opennsl_stats.rx_drops[RxDropUnknownIntf]++;
		return -1;
	}

	opennsl_stats.pstats[ftmh.sys_port].rx_pkts++;

	/*
	 * VLAN stripping would ordinarily be done by the backplane
	 * PMD, but as the NIC cannot parse the custom encap, it
	 * doesn't know it's there. Therefore, check and remove it if
	 * necessary here.
	 */
	rte_vlan_strip(mbuf);

	opennsl_stats.bp_rx_pkts++;
	opennsl_stats.bp_rx_bytes += rte_pktmbuf_pkt_len(mbuf);
	return 0;
}

static bool fal_opennsl_dpp_rx_backplane_framer(
	struct rte_mbuf *mbuf, uint16_t *dpdk_port)
{
	if (fal_opennsl_get_backplane_port() == 0)
		return false;
	
	return fal_bcm_dpp_backplane_rx(mbuf, dpdk_port) >= 0;
}

static int
fal_opennsl_dpp_port_init(int unit, opennsl_port_t port)
{
	opennsl_vlan_port_t vp;
	int rv;

	/*
	 * Set a unique class per port
	 *
	 * The class (confusingly referred to as VLAN domain), is used
	 * as an extra key in lookups of packet VLAN information, and
	 * having all ports share a single class (VLAN domain) means
	 * that we cannot set per-port, per-VLAN properties, since
	 * only one InLif will be created and the properties will be
	 * associated with that InLif which will be used by all ports.
	 *
	 * By setting the class ID to be unique per-port, then this
	 * means lookups are done by port and packet VLAN, and it
	 * forces the SDK to create an InLIF per-port, rather than one
	 * shared by all ports (i.e. at the cost of more resources if
	 * this isn't desired).
	 *
	 * Note: this isn't declaring separate isolated VLAN domains
	 * by itself - this is defined by VSI as a result of the InLif
	 * lookup and if these VSIs are shared between all ports then
	 * the ports are still effectively part of one VLAN domain.
	 */
	rv = opennsl_port_class_set(unit, port, opennslPortClassId, port);
	if (rv != OPENNSL_E_NONE) {
		ERROR("%s: Failed to set port class property: %s\n",
			  __func__, opennsl_errmsg(rv));
		return rv;
	}

	/*
	 * Create VLAN port with mapping from port to
	 * VLAN ID in packet, i.e. creating a shared
	 * VLAN domain for all ports.
	 *
	 * OPENNSL_VLAN_PORT_VSI_BASE_VID could be used
	 * here instead of OPENNSL_VLAN_ALL to mean VSI =
	 * VSI base + VID in packet, but it would
	 * likely mean manual maintainance of the
	 * flood groups by adding the VLAN GPort to
	 * them rather than the physical (local)
	 * GPort, and there is no requirement to
	 * support multiple VLAN domains at this time.
	 */
	opennsl_vlan_port_t_init(&vp);
	vp.criteria = OPENNSL_VLAN_PORT_MATCH_PORT;
	vp.flags = 0x800 /* ingress-only */;
	vp.vsi = ((opennsl_vlan_t)0xffff); /* VSI = VID in packet */
	vp.port = port;
	rv = opennsl_vlan_port_create(unit, &vp);
	if (rv != OPENNSL_E_NONE) {
		ERROR("%s: Failed to create vlan port: %s\n",
			  __func__, opennsl_errmsg(rv));
		return rv;
	} else {
		INFO("%s: port %d vlan-gport 0x%x\n", __func__,
			 port, vp.vlan_port_id);
	}

	return OPENNSL_E_NONE;
}

static int
fal_opennsl_dpp_pre_alloc_res(
	int unit, enum fal_opennsl_res_type type, uint32_t count,
	int *id_array, uint32_t *sdk_flags)
{
	uint32_t starting_id;
	uint32_t id_idx;
	int ret;

	switch (type) {
	case FAL_OPENNSL_RES_FEC:
		/*
		 * Due to the restriction on the DPP architecture that
		 * ECMP members must have consequetive FEC IDs, we
		 * must pre-allocate a batch of IDs here.
		 */
		ret = fal_opennsl_id_alloc(fal_opennsl_fec_id_table, count,
				       &starting_id);
		if (ret < 0)
			return ret;
		for (id_idx = 0; id_idx < count; id_idx++)
			id_array[id_idx] =
				1 /* FEC */ << 29 |
				(starting_id + id_idx +
				 4096 /* ECMP FECs */);
		/* signal that we pre-allocated the ID */
		*sdk_flags |= OPENNSL_L3_WITH_ID;
		break;
	case FAL_OPENNSL_RES_MCAST:
		ret = fal_opennsl_id_alloc(fal_opennsl_mcast_id_table, count,
				       &starting_id);
		if (ret < 0)
			return ret;
		/*
		 * The first number of values are reserved for VLAN flood
		 * groups so start allocation from above.
		 */
		for (id_idx = 0; id_idx < count; id_idx++)
			id_array[id_idx] = starting_id + id_idx +
				RSRVED_VLAN_FLOOD_MCAST_GRPS;
		/* signal that we pre-allocated the ID */
		*sdk_flags |= OPENNSL_MULTICAST_WITH_ID;
		break;
	default:
		break;
	}

	return 0;
}

static int
fal_opennsl_dpp_init(int unit)
{
	int ret;

	/* Shared table for all units as it is a global ID space */
	if (!fal_opennsl_fec_id_table) {
		/* Reasonable guess */
		int fec_db_size = 4096;

		ret = fal_opennsl_id_table_alloc(fec_db_size,
					     &fal_opennsl_fec_id_table);
		if (ret < 0) {
			ERROR("%s: failed to allocate FEC ID table of size %d - %s\n",
			      __func__, fec_db_size, strerror(-ret));
			return ret;
		}
	}

	/* Shared table for all units as it is a global ID space */
	if (!fal_opennsl_mcast_id_table) {
		/* Reasonable guess */
		int mcast_db_size = 4096;

		ret = fal_opennsl_id_table_alloc(mcast_db_size,
					     &fal_opennsl_mcast_id_table);
		if (ret < 0) {
			ERROR("%s: failed to allocate multicast ID table of size %d - %s\n",
			      __func__, mcast_db_size, strerror(-ret));
			return ret;
		}
	}

	return 0;
}

static int
fal_opennsl_dpp_pre_alloc_res_free(
	int unit, enum fal_opennsl_res_type type, int id)
{
	uint32_t fal_fec_id;
	int ret;

	switch (type) {
	case FAL_OPENNSL_RES_FEC:
		fal_fec_id = OPENNSL_L3_ITF_VAL_GET(id) - 4096 /* ECMP FECs */;
		ret = fal_opennsl_id_free(fal_opennsl_fec_id_table, 1, fal_fec_id);
		if (ret < 0)
			return ret;
		break;
	case FAL_OPENNSL_RES_MCAST:
		ret = fal_opennsl_id_free(fal_opennsl_mcast_id_table, 1,
				      id - RSRVED_VLAN_FLOOD_MCAST_GRPS);
		if (ret < 0)
			return ret;
		break;
	default:
		break;
	}

	return 0;
}

const struct fal_opennsl_chip_cfg fal_opennsl_dpp_chip_cfg = {
	.crc_trim = false,
	.vlan_insert = false,
	.hdr_insert = true,
	.tx_backplane_framer = fal_opennsl_insert_hdrs,
	.rx_backplane_framer = fal_opennsl_dpp_rx_backplane_framer,
	.port_init = fal_opennsl_dpp_port_init,
	.pre_alloc_res = fal_opennsl_dpp_pre_alloc_res,
	.pre_alloc_res_free = fal_opennsl_dpp_pre_alloc_res_free,
	.init = fal_opennsl_dpp_init,
};
