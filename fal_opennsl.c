/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 */
/*-
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <net/if.h>

#include <ini.h>

#include "platform-defines.h"
#include <opennsl/types.h>
#include <opennsl/rx.h>
#include <opennsl/tx.h>
#include <opennsl/link.h>
#include <opennsl/error.h>
#include <opennsl/port.h>
#include <opennsl/stg.h>
#include <opennsl/vlan.h>
#include <opennsl/l2.h>
#include <opennsl/stack.h>
#include <opennsl/init.h>
#include <opennsl/mirrorX.h>
#include <opennsl/multicast.h>
#include <sal/driver.h>

#include <rte_config.h>
#include <rte_memory.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_version.h>

#include <fal_plugin.h>
#include <json_writer.h>
#include <bridge_flags.h>
#include <bridge_vlan_set.h>

#include "fal_opennsl.h"
#include "fal_opennsl_debug.h"
#include "fal_opennsl_l3.h"

//TODO: how big is this?
//If we allow reloading of the port configuration
//this may need to be done differently in the future
// as it stands now, this is allocated at bootup and
// referenced there after so no need for synchronization.
static struct opennsl_port *ports[OPENNSL_UNITS_MAX][OPENNSL_PBMP_PORT_MAX];
static struct opennsl_port *rte_ports[RTE_MAX_ETHPORTS];

static struct rte_mempool *unit_rx_pools[OPENNSL_UNITS_MAX];
bool l3_support = true;

int fal_opennsl_ndevs = 0;

static int trap_ids[opennslRxTrapCount];

#define MAX_BP_PORTS 2

struct bp_port {
	struct rte_pci_addr cpu_bp_addr;
	opennsl_port_t          opennsl_port;
	int                 dpdk_port;
};

static struct fal_opennsl_configuration {
	char *config_file;
	char *rc_file;
	struct bp_port bp_ports[MAX_BP_PORTS];
	int  num_bp_ports;
	char *port_updown_script;
	bool generic_port_naming;
	char *generic_port_name[OPENNSL_PBMP_PORT_MAX];
} fal_opennsl_configuration;

static bool fal_plugin_inited;
static uint32 fal_opennsl_debug;

static char *rx_drop_reason_strs[RxDropMax] = {
	[RxDropHdrParseFail] = "HdrParseFail",
	[RxDropUnknownIntf] = "UnknownIntf",
	[RxDropNoMempool] = "NoMempool",
	[RxDropAllocFail] = "AllocFail",
	[RxDropConvertFail] = "ConvertFail",
	[RxDropEnqFail] = "EnqFail",
	[RxDropPktTooSmall] = "PktTooSmall",
	[RxDropPktSizeMismatch] = "PktSizeMismatch"
};

static char *tx_drop_reason_strs[TxDropMax] = {
	[TxDropAllocFail] = "AllocFail",
	[TxDropConvertFail] = "ConvertFail",
	[TxDropPrependFail] = "PrependFail",
	[TxDropTxFail] = "TxFail"
};

struct opennsl_stats opennsl_stats;
const struct fal_opennsl_chip_cfg **fal_opennsl_chip_cfg;

static bool rx_backplane_framer(struct rte_mbuf *mbuf, uint16_t *dpdk_port)
{
	return false;
}

static const struct fal_opennsl_chip_cfg fal_opennsl_default_chip_cfg = {
	.crc_trim = true,
	.vlan_insert = true,
	.hdr_insert = false,
	.rx_backplane_framer = rx_backplane_framer,
};

/*
 * OPENNSL error codes and _SHR_E_LIMIT are negative numbers
 */
int fal_opennsl_error_code_map[-_SHR_E_LIMIT] = {
	[-OPENNSL_E_NONE]      = 0,
	[-OPENNSL_E_INTERNAL]  = -EPERM,
	[-OPENNSL_E_MEMORY]    = -ENOMEM,
	[-OPENNSL_E_UNIT]      = -EINVAL,
	[-OPENNSL_E_PARAM]     = -EINVAL,
	[-OPENNSL_E_EMPTY]     = -EPERM,
	[-OPENNSL_E_FULL]      = -ENOSPC,
	[-OPENNSL_E_NOT_FOUND] = -ENOENT,
	[-OPENNSL_E_EXISTS]    = -EEXIST,
	[-OPENNSL_E_TIMEOUT]   = -ETIMEDOUT,
	[-OPENNSL_E_BUSY]      = -EBUSY,
	[-OPENNSL_E_FAIL]      = -EPERM,
	[-OPENNSL_E_DISABLED]  = -EPERM,
	[-OPENNSL_E_BADID]     = -EINVAL,
	[-OPENNSL_E_RESOURCE]  = -ENOSPC,
	[-OPENNSL_E_CONFIG]    = -EPERM,
	[-OPENNSL_E_UNAVAIL]   = -EPERM,
	[-OPENNSL_E_INIT]      = -EPERM,
	[-OPENNSL_E_PORT]      = -EINVAL
};

int fal_opennsl_map_error_code(opennsl_error_t opennsl_error)
{
	return fal_opennsl_error_code_map[-opennsl_error];
}

static bool fal_opennsl_is_dpp_device(int unit)
{
	opennsl_info_t info;
	opennsl_info_get(unit, &info);

	return (info.device == 0x8375) /* Qumran MX */ ||
		(info.device == 0x8470) /* Qumran AX */;
}

static int _platform_init(char *config_file, char *rc_file)
{
	int rv;
	int i;
	opennsl_info_t info;

	opennsl_init_t init_info;

	memset(&init_info, 0, sizeof(init_info));
	init_info.cfg_fname = config_file;
	init_info.cfg_post_fname = rc_file;

	rv = opennsl_driver_init(&init_info);
	if (rv != OPENNSL_E_NONE) {
		ERROR("Could not initialize platform : %s", opennsl_errmsg(rv));
		return fal_opennsl_map_error_code(rv);
	}

	rv = opennsl_attach_max(&fal_opennsl_ndevs);
	if (rv != OPENNSL_E_NONE) {
		ERROR("Could not determine max units : %s", opennsl_errmsg(rv));
		return fal_opennsl_map_error_code(rv);
	}
	fal_opennsl_ndevs++;
	INFO("Attached %d units\n", fal_opennsl_ndevs);

	fal_opennsl_chip_cfg = calloc(fal_opennsl_ndevs, sizeof(*fal_opennsl_chip_cfg));
	if (!fal_opennsl_chip_cfg) {
		ERROR("out of memory during FAL OPENNSL init\n");
		return -ENOMEM;
	}

	for (i = 0; i < fal_opennsl_ndevs; i++) {
		rv = opennsl_info_get(i, &info);
		if (rv != OPENNSL_E_NONE) {
			ERROR("Could not get info for unit %d : %s\n",
			      i, opennsl_errmsg(rv));
			continue;
		}
		if (fal_opennsl_is_dpp_device(i)) {
			fal_opennsl_chip_cfg[i] = &fal_opennsl_dpp_chip_cfg;
		} else {
			fal_opennsl_chip_cfg[i] = &fal_opennsl_default_chip_cfg;
		}
		if (fal_opennsl_chip_cfg[i]->init) {
			rv = fal_opennsl_chip_cfg[i]->init(i);
			if (OPENNSL_FAILURE(rv))
				return rv;
		}

		if (fal_opennsl_chip_cfg[i]->cfg_l2_learn_cpu_notif) {
			rv = fal_opennsl_chip_cfg[i]->cfg_l2_learn_cpu_notif(i);
			if (OPENNSL_FAILURE(rv))
				return rv;
		}
	}

	INFO("Applied post initialization script from "
		 "file \"%s\"\n", rc_file);
	INFO("Common SDK init completed\r\n");

	/*
	for (i = 0; i < fal_opennsl_ndevs; i++)
	{
	  rc = opennsl_rx_init(i);
	  if (OPENNSL_FAILURE(rc))
	  {
	    ERROR("RX init failed, unit %d rc %d \n", i, rc);
	    break;
	  }
	}
	*/
	memset(trap_ids, 0xFF, sizeof(trap_ids));

	/*
	 * This will log on failure, so no need to log again here
	 */
	rv = fal_opennsl_l3_init();
	if (rv != OPENNSL_E_NONE)
		l3_support = false;

	return OPENNSL_E_NONE;
}

static int parse_platform_entry(void *cookie, const char *section,
				const char *name, const char *value)
{
	struct fal_opennsl_configuration *configuration = cookie;

	if (strcasecmp(section, "broadcom") == 0) {
		if (strcasecmp(name, "config") == 0) {
			free(configuration->config_file);
			configuration->config_file = strdup(value);
			if (!configuration->config_file) {
				ERROR("strdup of config: %s\n",
				      strerror(errno));
				return 0;
			}
		} else if (strcasecmp(name, "rc") == 0) {
			free(configuration->rc_file);
			configuration->rc_file = strdup(value);
			if (!configuration->rc_file) {
				ERROR("strdup of rc: %s\n",
				      strerror(errno));
				return 0;
			}
		} else if (strncmp(name, "backplane_port",
				   strlen("backplane_port")) == 0) {
			int i = configuration->num_bp_ports;
			if (i == MAX_BP_PORTS) {
				ERROR("Max backplane count reached\n");
				return 0;
			}
			struct bp_port *bp = &configuration->bp_ports[i];

			int rc = sscanf(value, "%hhx:%hhx.%hhu,%u",
					&bp->cpu_bp_addr.bus,
					&bp->cpu_bp_addr.devid,
					&bp->cpu_bp_addr.function,
					&bp->opennsl_port);
			if (rc != 4) {
				ERROR("Invalid backplane entry. %d fields read\n",
				      rc);
				return 0;
			}
			configuration->num_bp_ports = ++i;
		} else if (strcasecmp(name, "port_updown_script") == 0) {
			free(configuration->port_updown_script);
			configuration->port_updown_script =
				strdup(value);
			if (!configuration->port_updown_script) {
				ERROR("strdup of port_updown_script: %s\n",
				      strerror(errno));
				return 0;
			}
		} else if (strcasecmp(name, "generic_port_naming") == 0) {
			configuration->generic_port_naming =
						atoi(value) ? true : false;
		} else if (strncasecmp(name,
				       "generic_port_name",
				       strlen("generic_port_name")) == 0) {
			unsigned int port;

			int rc = sscanf(name, "generic_port_name%u", &port);
			if (rc != 1 ||
			    port >= OPENNSL_PBMP_PORT_MAX) {
				ERROR("Bad port translation: %s\n", value);
				return 0;
			}
			free(configuration->generic_port_name[port]);
			configuration->generic_port_name[port] = strdup(value);
		}
	}

	return 1;
}

static int fal_parse_platform_config(const char *platform_conf)
{
	FILE *f;
	int rv;

	if (!platform_conf)
		return -1;

	f = fopen(platform_conf, "r");
	if (!f)
		return -1;
	rv = ini_parse_file(f, parse_platform_entry, &fal_opennsl_configuration);
	if (rv)
		ERROR("Failed to parse %s\n", opennsl_errmsg(rv));
	fclose(f);
	return OPENNSL_E_NONE;
}

int fal_plugin_init()
{
	opennsl_error_t rv;
	uint16_t num_ports, port;
	unsigned int i;

	for (i = 0; i < OPENNSL_PBMP_PORT_MAX; i++)
		if (fal_opennsl_configuration.generic_port_naming &&
		    !fal_opennsl_configuration.generic_port_name[i])
			if (asprintf(&fal_opennsl_configuration.generic_port_name[i],
						 "p%u", i) < 0) {
				return -1;
			}

	rv = fal_parse_platform_config(PLATFORM_FILE);
	if (rv != OPENNSL_E_NONE)
		return rv;

#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
	num_ports = rte_eth_dev_count_avail();
#else
	num_ports = rte_eth_dev_count();
#endif
	for (port = 0; port < num_ports; port++) {
		struct rte_eth_dev_info dev;
		rte_eth_dev_info_get(port, &dev);
#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
		const struct rte_bus *bus = rte_bus_find_by_device(dev.device);
		struct rte_pci_device *pci = NULL;
		if (bus && !strcmp(bus->name, "pci"))
			pci = RTE_DEV_TO_PCI(dev.device);
#else
		struct rte_pci_device *pci = dev.pci_dev;
#endif
		if (pci) {
			struct rte_pci_addr *loc;
			struct bp_port *bp;

			loc = &pci->addr;
			for (int i = 0; i < fal_opennsl_configuration.num_bp_ports;
			     i++) {
				bp = &fal_opennsl_configuration.bp_ports[i];
				if (loc->bus == bp->cpu_bp_addr.bus &&
				    loc->devid == bp->cpu_bp_addr.devid &&
				    loc->function == bp->cpu_bp_addr.function)
					bp->dpdk_port = port;
			}
		}
	}

	INFO("Initializing OPENNSL plugin\n");
	rv = _platform_init(fal_opennsl_configuration.config_file,
			    fal_opennsl_configuration.rc_file);
	if (rv != OPENNSL_E_NONE) {
		ERROR("Failed to initialize OPENNSL. rc=%s\n", opennsl_errmsg(rv));
		return rv;
	}
	fal_plugin_inited = true;
	INFO("OPENNSL plugin initialized successfully\n");
	return 0;
}

void fal_plugin_cleanup(void)
{
	unsigned int i;

	for (i = 0; i < OPENNSL_PBMP_PORT_MAX; i++)
		free(fal_opennsl_configuration.generic_port_name[i]);
}

static char *fal_opennsl_device_name(int unit, opennsl_port_t port)
{
	char ifname[IF_NAMESIZE];
	char *generic_name = fal_opennsl_configuration.generic_port_name[port];

	if (generic_name)
		snprintf(ifname, IF_NAMESIZE, "%s", generic_name);
	else
		snprintf(ifname, IF_NAMESIZE, "%s", opennsl_port_name(unit, port));
	return strdup(ifname);
}

struct opennsl_port *fal_opennsl_lookup_port(int unit, int port)
{
	if (unit > OPENNSL_UNITS_MAX)
		return NULL;

	if (port > OPENNSL_PBMP_PORT_MAX)
		return NULL;

	return ports[unit][port];
}

static int fal_opennsl_create_dpdk_vdev(int unit, opennsl_port_t port,
				    opennsl_gport_t sysport)
{
	char *ifname = fal_opennsl_device_name(unit, port);
	struct opennsl_port *bport = NULL;
	int rv = 0;
	INFO("Creating port for %s, %d, %d\n", ifname, unit, port);
	rv = fal_opennsl_pmd_register_rte_eth(ifname, unit, port, sysport, &bport);
	if (rv < 0) {
		ERROR("Failed to create port for %s, %d, %d\n", ifname, unit, port);
		goto out;
	}
	INFO("Created port for %s, %d, %d, 0x%x, %p\n", ifname, unit,
	     port, sysport, bport);
	ports[unit][port] = bport;
	rte_ports[fal_opennsl_pmd_port_get_portid(bport)] = bport;
out:
	free(ifname);
	return rv;
}

void fal_opennsl_port_updown(int unit, opennsl_port_t port, bool up)
{
	char str[PATH_MAX];
	char *port_name;
	FILE *p;

	if (!fal_opennsl_configuration.port_updown_script)
		return;

	port_name = fal_opennsl_device_name(unit, port);
	if (snprintf(str, sizeof(str), "%s %s %s",
		     fal_opennsl_configuration.port_updown_script,
		     up ? "up" : "down", port_name) < 0) {
		ERROR("out of space in port_updown command argument string\n");
		free(port_name);
		return;
	}
	free(port_name);

	p = popen(str, "r");
	if (!p) {
		ERROR("failed to invoke port updown script: %s\n",
		      strerror(errno));
		return;
	}

	if (pclose(p) == -1)
		ERROR("pclose of port updown script: %s",
		      strerror(errno));
}

static int
fal_opennsl_convert_pkt_to_mbuf(int unit, struct rte_mbuf *dest, opennsl_pkt_t *src)
{
	//TODO: mbuf chains
	//TODO: zerocopy
	uint32_t mbuf_avail  = dest->buf_len - RTE_PKTMBUF_HEADROOM;
	uint32_t pkt_len = src->tot_len;
	uint32_t cpy_len = RTE_MIN(pkt_len, mbuf_avail);
	int pkt_start = src->tot_len - src->pkt_len;

	if (fal_opennsl_chip_cfg[unit]->crc_trim)
		cpy_len = cpy_len - ETHER_CRC_LEN - pkt_start;
	else
		cpy_len = cpy_len - pkt_start;

	if (pkt_len == 0 || src->pkt_data == NULL) {
		return -1;
	}
	if (src->blk_count > 1) {
		INFO("Packet block count %d\n", src->blk_count);
	}
	rte_memcpy(rte_pktmbuf_mtod(dest, void *),
			   &src->pkt_data->data[pkt_start],
			   cpy_len);
	rte_pktmbuf_pkt_len(dest) = rte_pktmbuf_data_len(dest) = cpy_len;
	dest->nb_segs = 1;
	rte_vlan_strip(dest);
	return 0;
}

static opennsl_rx_t fal_opennsl_rx_cb(int unit, opennsl_pkt_t *pkt, void *cookie)
{
	struct opennsl_port *port;

	port = fal_opennsl_lookup_port(pkt->unit, pkt->src_port);
	if (port == NULL) {
		opennsl_stats.rx_drops[RxDropUnknownIntf]++;
		return OPENNSL_RX_NOT_HANDLED;
	}
	struct rte_mempool *mp = unit_rx_pools[unit];
	if (mp == NULL) {
		opennsl_stats.rx_drops[RxDropNoMempool]++;
		return OPENNSL_RX_NOT_HANDLED;
	}

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mp);
	if (mbuf == NULL) {
		opennsl_stats.rx_drops[RxDropAllocFail]++;
		return OPENNSL_RX_NOT_HANDLED;
	}
	mbuf->port = fal_opennsl_pmd_port_get_portid(port);
	if (fal_opennsl_convert_pkt_to_mbuf(unit, mbuf, pkt) < 0) {
		opennsl_stats.rx_drops[RxDropConvertFail]++;
		rte_pktmbuf_free(mbuf);
		return OPENNSL_RX_NOT_HANDLED;
	}
	if (fal_opennsl_pmd_port_enqueue_rx_mbuf(port, &mbuf, 1) < 0) {
		opennsl_stats.rx_drops[RxDropEnqFail]++;
		rte_pktmbuf_free(mbuf);
		return OPENNSL_RX_NOT_HANDLED;
	}

	opennsl_stats.rx_pkts++;
	opennsl_stats.rx_bytes += pkt->pkt_len;
	return OPENNSL_RX_HANDLED;
}

#if 0
static int fal_opennsl_get_num_unit_interfaces(int unit)
{
	int ret = 0;
	opennsl_port_t port;
	opennsl_port_config_t     pcfg;
	if (OPENNSL_SUCCESS(opennsl_port_config_get(unit, &pcfg))) {
		OPENNSL_PBMP_ITER(pcfg.port, port) {
			ret++;
		}
	}
	return ret;
}

static int fal_opennsl_rx_alloc(int unit, int size, uint32 flags, void **pkt_buf)
{
	struct rte_mempool *mp = unit_rx_pools[unit];
	if (mp == NULL) {
		return -1;
	}
	pkt_buf = (void *)rte_pktmbuf_alloc(mp);
	return 0;
}

static int fal_opennsl_rx_free(int unit, void *pkt_buf)
{
	rte_pktmbuf_free(pkt_buf);
	return 0;
}
#endif

static struct rte_mempool *fal_opennsl_create_unit_rx_pool(int unit)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	snprintf(name, RTE_MEMPOOL_NAMESIZE, "opennsl_rx_unit_%u",
		(unsigned int)unit);
	struct rte_mempool *mp;

	mp = rte_pktmbuf_pool_create(name, 2560/*based on 10gb with one queue*/,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		SOCKET_ID_ANY/*TODO: should be the socket for the
					   pci interface but I haven't figured out
					   how to get that yet.*/);

	/* Try and reuse existing mbuf pool on restart */
	if (mp == NULL && rte_errno == EEXIST)
		mp = rte_mempool_lookup(name);

	if (mp == NULL)
		return NULL;

	unit_rx_pools[unit] = mp;

	return mp;
}

static int fal_opennsl_rx_init(int unit)
{
	INFO("Starting OpenNSL RX subsystem\n");
	opennsl_rx_cfg_t rx_cfg;
	opennsl_error_t rc = OPENNSL_E_NONE;
	struct rte_mempool *mp = fal_opennsl_create_unit_rx_pool(unit);
	if (mp == NULL)
		return OPENNSL_E_MEMORY;

	rc = opennsl_rx_register(unit, "fal_opennsl_rx",
				 fal_opennsl_rx_cb, 10, NULL, OPENNSL_RCO_F_ALL_COS);
	if (OPENNSL_FAILURE(rc)) {
		ERROR("OPENNSL Failed to register receive subsystem; unit: %d error: %s\n",
			  unit, opennsl_errmsg(rc));
		return -1;
	}

	opennsl_rx_cfg_t_init(&rx_cfg);
	rx_cfg.pkt_size = RTE_MBUF_DEFAULT_BUF_SIZE;
	rx_cfg.pkts_per_chain = 15;
	rx_cfg.global_pps = 0;
	rx_cfg.max_burst = 200;
	rx_cfg.chan_cfg[1].chains = 4;
	rx_cfg.chan_cfg[1].cos_bmp = 0xffffffff;

	//TODO: adjust the config options
	rc = opennsl_rx_start(unit, &rx_cfg);
	if (rc != OPENNSL_E_NONE) {
		ERROR("OPENNSL Failed to start receive subsystem; unit: %d error: %s\n",
			  unit, opennsl_errmsg(rc));
		return -1;
	}

/*	TODO: this doesn't work...
	rc = opennsl_rx_control_set(unit, opennslRxControlCRCStrip, 1);
	if (OPENNSL_FAILURE(rc)) {
		ERROR("OPENNSL Failed to set CRC strip: unit: %d error: %s\n",
			  unit, opennsl_errmsg(rc));
		return -1;
	}
*/
	return 0;
}

static void fal_opennsl_linkscan_cb(int unit, opennsl_port_t port,
	opennsl_port_info_t *info)
{
	struct opennsl_port *bport = fal_opennsl_lookup_port(unit, port);
	if (bport == NULL) {
		return;
	}
	struct rte_eth_link link = {
		.link_speed = fal_opennsl_port_opennsl_to_dpdk_speed(bport, info->speed),
		.link_duplex = fal_opennsl_port_opennsl_to_dpdk_duplex(bport, info->duplex),
		.link_status = fal_opennsl_port_opennsl_to_dpdk_status(bport, info->linkstatus)
	};
	fal_opennsl_pmd_port_set_link(bport, &link);
}

static void fal_opennsl_linkscan_init(int unit)
{
	opennsl_error_t rc = OPENNSL_E_NONE;
	rc = opennsl_linkscan_register(unit, fal_opennsl_linkscan_cb);
	if (rc != OPENNSL_E_NONE) {
		ERROR("OPENNSL Failed to start linkscan subsystem; unit: %d error: %s\n",
			  unit, opennsl_errmsg(rc));
		return;
	}
}

int fal_opennsl_port_to_system_port(int unit, opennsl_port_t port,
				opennsl_gport_t *sysport)
{
	opennsl_gport_t modport;
	int rv;

	/* get the MODPORT */
	rv = opennsl_port_gport_get(unit, port, &modport);
	if (rv != OPENNSL_E_NONE)
		return rv;

	/* translate MODPORT to SYSTEM_PORT */
	rv = opennsl_stk_gport_sysport_get(unit, modport, sysport);

	/* If we don't have stacking... */
	if (rv == OPENNSL_E_UNAVAIL) {
		*sysport = port;
		return OPENNSL_E_NONE;
	}
	return rv;
}

bool fal_opennsl_is_backplane_port(opennsl_port_t port)
{
	for (int i = 0; i < fal_opennsl_configuration.num_bp_ports; i++) {
		if (fal_opennsl_configuration.bp_ports[i].opennsl_port == port)
			return true;
	}

	return false;
}

static bool fal_opennsl_is_supported_port(int unit, opennsl_port_t port)
{
	char *port_name = opennsl_port_name(unit, port);

	/* ignore higig ports & interlaken ports */
	if (port_name &&
		((strncmp(port_name, "hg", 2) == 0) ||
		 (strncmp(port_name, "il", 2) == 0)))
		return false;

	return true;
}

/*
 * There are certain rx traps that need to be enabled on a per port
 * basis and then their behaviour is configured globally. This function
 * enables those 'interesting' traps and then their behaviour is defined
 * globally based on the router's init/configured policy.
 */
static int
fal_opennsl_switch_control_port_set(int unit, enum fal_opennsl_switch_control type,
				opennsl_port_t port)
{
	const struct fal_opennsl_chip_cfg *chip_cfg = fal_opennsl_chip_cfg[unit];
	int rv = OPENNSL_E_NONE;

	switch (type) {
	case FAL_OPENNSL_SWITCH_CONTROL_ICMP_REDIR_TO_CPU:
		if (chip_cfg->cfg_l3_per_port_punt_icmp_redir) {
			rv = chip_cfg->cfg_l3_per_port_punt_icmp_redir(unit,
								       port);
			if (rv != 0) {
				ERROR("Failed to set ICMP Redir trap on port %d : %s",
				      port, opennsl_errmsg(rv));
			}
		}
		break;
	}
	return rv;
}

void fal_plugin_setup_interfaces(void)
{
	int unit, rv;
	int port, nports, ncpu_ports;
	opennsl_port_config_t     pcfg;
	opennsl_gport_t sysport;
	opennsl_port_ability_t abil;

	if (!fal_plugin_inited) {
		ERROR("fal plugin not initialized\n");
		return;
	}

	INFO("Creating OPENNSL interfaces\n");
	for (unit = 0; unit < fal_opennsl_ndevs; unit++) {
		INFO("Processing unit %d\n", unit);

		rv = opennsl_port_config_get(unit, &pcfg);
		if (rv != OPENNSL_E_NONE) {
			ERROR("OPENNSL failed to get port config %d\n", unit);
			continue;
		}
		OPENNSL_PBMP_COUNT(pcfg.port, nports);
		INFO("OPENNSL got port config. %d ports enabled\n",
			 nports);
		if (OPENNSL_PBMP_IS_NULL(pcfg.port)) {
			INFO("OPENNSL port config is empty\n");
			continue;
		}
		OPENNSL_PBMP_ITER(pcfg.port, port) {
			INFO("Processing port port %d on unit %d\n", port, unit);
			rv = fal_opennsl_port_to_system_port(unit, port, &sysport);
			if (rv != OPENNSL_E_NONE) {
				ERROR("Failed to translate unit %d port %d to sysport: %s\n",
				      unit, port, opennsl_errmsg(rv));
				continue;
			}

			/* skip initializing backplane ports as DPDK ports */
			if (fal_opennsl_is_backplane_port(port)) {
				rv = opennsl_port_ability_advert_get(unit, port,
								 &abil);
				if (rv != OPENNSL_E_NONE) {
					ERROR("Failed to get capabilities for unit %d, port %d: %s\n",
					      unit, port, opennsl_errmsg(rv));
					continue;
				}
				rv = opennsl_port_ability_advert_set(unit, port, &abil);
				if (rv != OPENNSL_E_NONE) {
					ERROR("Failed to set capabilities for unit %d, port %d: %s\n",
					      unit, port, opennsl_errmsg(rv));
					continue;
				}

				if (fal_opennsl_chip_cfg[unit]->configure_backplane_port)
					fal_opennsl_chip_cfg[unit]->configure_backplane_port(unit, port);
			} else {
				if (fal_opennsl_is_supported_port(unit, port)) {
					fal_opennsl_create_dpdk_vdev(unit, port, sysport);
					/*
					 * Set up per port switch controls
					 */
					rv = fal_opennsl_switch_control_port_set(
						unit, FAL_OPENNSL_SWITCH_CONTROL_ICMP_REDIR_TO_CPU,
						port);
					if (rv != OPENNSL_E_NONE) {
						ERROR("Failed to init switch control on port %d: %s",
						      port, opennsl_errmsg(rv));
						continue;
					}
				}
			}

			if (fal_opennsl_chip_cfg[unit]->port_init) {
				rv = fal_opennsl_chip_cfg[unit]->port_init(unit, port);
				if (rv != OPENNSL_E_NONE)
					continue;
			}
		}

		OPENNSL_PBMP_COUNT(pcfg.cpu, ncpu_ports);
		INFO("OPENNSL processing CPU ports. %d ports enabled\n",
			 ncpu_ports);
		OPENNSL_PBMP_ITER(pcfg.cpu, port) {
			INFO("Processing port port %d on unit %d\n", port, unit);
			rv = opennsl_port_control_set(unit, port, opennslPortControlL2Move,
				OPENNSL_PORT_LEARN_FWD);
			if (rv != OPENNSL_E_NONE) {
				ERROR("OPENNSL failed to setup CPU port L2Move %d\n", unit);
			}
		}
		fal_opennsl_linkscan_init(unit);

		/* Only register for CMIC RX if there is no backplane */
		if (fal_opennsl_get_backplane_port() == 0)
			fal_opennsl_rx_init(unit);

		/*
		 * Set up stats for storm control upfront
		 */
		//rv = fal_opennsl_setup_storm_ctl_stats(unit);
	}
	INFO("Created OPENNSL interfaces\n");
}

int fal_plugin_init_log(void)
{
	return 0;
}

int fal_opennsl_lookup_port_info(int ifindex, int *unit, opennsl_port_t *port,
			     struct opennsl_port **opennslport)
{
	uint16_t rte_port;
	int rv = fal_port_byifindex(ifindex, &rte_port);
	if (rv < 0) {
		ERROR("%s: Failed to get the rte_port for ifindex: %d\n", __func__, ifindex);
		return rv;
	}
	struct opennsl_port *bport = rte_ports[rte_port];
	if (bport == NULL) {
		/* Not an OPENNSL port skip. */
		INFO("%s: skipping, port(ifindex=%d, rte_port=%d) not managed by fal_opennsl\n",
			__func__, ifindex, rte_port);
		return -1;
	}
	*unit = fal_opennsl_pmd_port_get_unit(bport);
	*port = fal_opennsl_pmd_port_get_port(bport);
	*opennslport = bport;
	return 0;
}

int fal_opennsl_lookup_port_sysport(int ifindex, opennsl_gport_t *sysport)
{
	uint16_t rte_port;
	int rv = fal_port_byifindex(ifindex, &rte_port);
	if (rv < 0) {
		ERROR("%s: Failed to get the rte_port for ifindex: %d\n",
		      __func__, ifindex);
		return rv;
	}
	struct opennsl_port *bport = rte_ports[rte_port];
	if (bport == NULL) {
		/* Not an OPENNSL port skip. */
		INFO("%s: skipping, port(ifindex=%d, rte_port=%d) not managed by fal_opennsl\n",
		     __func__, ifindex, rte_port);
		return -1;
	}
	*sysport = fal_opennsl_pmd_port_get_sysport(bport);
	return 0;
}

void fal_plugin_opennsl_shell_cmd(FILE *f, int argc, char **argv)
{
	int i, j, cursor = 0, len = 0;
	char *cmd_str;
	FILE *tmp_stdout;

	for (i = 1; i < argc; i++) {
		len += strlen(argv[i]) + 1;
	}
	cmd_str = malloc(len);
	for (i = 1; i < argc; i++) {
		j = strlen(argv[i]);
		strcpy(&cmd_str[cursor], argv[i]);
		cursor += j;
		cmd_str[cursor] = ' ';
		cursor++;
	}
	cmd_str[cursor-1] = 0;
	tmp_stdout = stdout;
	stdout = f;

#ifdef INCLUDE_DIAG_SHELL
	int rv = opennsl_driver_process_command(cmd_str);
	if (OPENNSL_FAILURE(rv))
		ERROR("Command %s failed : %s\n", cmd_str,
		      opennsl_errmsg(rv));
#endif

	free(cmd_str);
	stdout = tmp_stdout;
}

static void fal_plugin_opennsl_portinfo_cmd(FILE *f, int argc, char **argv)
{
	int unit, port, nports, err;
	opennsl_port_config_t pcfg;
	opennsl_port_info_t portinfo;
	uint32 class;
	opennsl_gport_t gport;

	json_writer_t *wr;

	wr = jsonw_new(f);
	if (!wr) {
		fprintf(f, "Could not allocate json writer\n");
		return;
	}

	jsonw_pretty(wr, true);
	jsonw_name(wr, "opennslPortinfo");
	jsonw_start_array(wr);
	for (unit = 0; unit < fal_opennsl_ndevs; unit++) {
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "Unit", unit);
		int rv = opennsl_port_config_get(unit, &pcfg);
		if (rv != OPENNSL_E_NONE) {
			jsonw_string(wr, "OPENNSL failed to get port config");
			continue;
		}
		OPENNSL_PBMP_COUNT(pcfg.port, nports);
		if (OPENNSL_PBMP_IS_NULL(pcfg.port)) {
			jsonw_string(wr, "OPENNSL port config is empty");
			continue;
		}
		jsonw_start_array(wr);
		OPENNSL_PBMP_ITER(pcfg.port, port) {
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "Port", port);
			err = opennsl_port_selective_get(unit, port, &portinfo);
			if (err < 0) {
				jsonw_string(wr, "Could not get info for port");
				continue;
			}
			jsonw_uint_field(wr, "Action Mask 1", portinfo.action_mask);
			jsonw_uint_field(wr, "Action Mask 2", portinfo.action_mask2);
			jsonw_uint_field(wr, "Learn Flags", portinfo.learn);
			jsonw_uint_field(wr, "Discard Flags", portinfo.discard);
			jsonw_uint_field(wr, "Untagged vlan", portinfo.untagged_vlan);
			jsonw_uint_field(wr, "Pause Tx", portinfo.pause_tx);
			jsonw_uint_field(wr, "Pause Rx", portinfo.pause_rx);
			jsonw_uint_field(wr, "Fault", portinfo.fault);
			opennsl_port_gport_get(unit, port, &gport);
			jsonw_uint_field(wr, "GPort", gport);
			jsonw_name(wr, "Port classes");
			jsonw_start_object(wr);
			err = opennsl_port_class_get(unit, port, opennslPortClassId, &class);
			jsonw_uint_field(wr, "ID", class);
			err = opennsl_port_class_get(unit, port, opennslPortClassL2Lookup, &class);
			jsonw_uint_field(wr, "L2Lookup", class);
			jsonw_end_object(wr);
			jsonw_name(wr, "Control fields");
			jsonw_start_object(wr);
			jsonw_end_object(wr);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	fflush(f);
	jsonw_destroy(&wr);
}

static char *debug_bits[] = {
	"packet", 
};

/* find debug bit based on name, allow abbreviation */
static int find_debug_bit(const char *str)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(debug_bits); i++)
		if (strncmp(debug_bits[i], str, strlen(str)) == 0)
			return i;
	return -1;
}

static void fal_plugin_opennsl_debug_cmd(FILE *f, int argc, char **argv)
{
	int i;
	
	if (argc < 3) {
		fprintf(f, "Usage: fal plugin opennsl debug <flag> <enable|disable>");
		return;
	}

	i = find_debug_bit(argv[1]);
	if (i < 0) {
		fprintf(f, "Unknown debug flag %s\n", argv[1]);
		return;
	}

	if (!strcmp(argv[2], "enable"))
		fal_opennsl_debug |= (1ul << i);
	else if (!strcmp(argv[2], "disable"))
		fal_opennsl_debug &= ~(1ul << i);
	else
		fprintf(f, "Unknown option %s\n", argv[2]);
	fprintf(f, "Debug = 0x%x\n", fal_opennsl_debug);
}

static void fal_plugin_opennsl_stats(FILE *f, int argc, char **argv)
{
	json_writer_t *wr;

	if (argc < 2) {
		fprintf(f, "Usage: fal plugin opennsl stats <show|clear>");
		return;
	}

	if (!strcmp(argv[1], "clear")) {
		memset(&opennsl_stats, 0, sizeof(opennsl_stats));
		return;
	}

	if (strcmp(argv[1], "show")) {
		fprintf(f, "Usage: fal plugin opennsl stats <show|clear>");
		return;
	}

	wr = jsonw_new(f);
	if (!wr) {
		fprintf(f, "Could not allocate json writer\n");
		return;
	}

	jsonw_pretty(wr, true);
	jsonw_name(wr, "opennslStats");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "BPRxPkts", opennsl_stats.bp_rx_pkts);
	jsonw_uint_field(wr, "BPRxBytes", opennsl_stats.bp_rx_bytes);
	jsonw_uint_field(wr, "RxPkts", opennsl_stats.rx_pkts);
	jsonw_uint_field(wr, "RxBytes", opennsl_stats.rx_bytes);
	jsonw_name(wr, "RxDrops");
	jsonw_start_object(wr);
	for (int i = RxDropMin + 1; i < RxDropMax; i++) {
		jsonw_uint_field(wr, rx_drop_reason_strs[i], opennsl_stats.rx_drops[i]);
	}
	jsonw_end_object(wr);
	jsonw_uint_field(wr, "BPTxPkts", opennsl_stats.bp_tx_pkts);
	jsonw_uint_field(wr, "BPTxBytes", opennsl_stats.bp_tx_bytes);
	jsonw_uint_field(wr, "TxPkts", opennsl_stats.tx_pkts);
	jsonw_uint_field(wr, "TxBytes", opennsl_stats.tx_bytes);
	jsonw_name(wr, "TxDrops");
	jsonw_start_object(wr);
	for (int i = TxDropMin + 1; i < TxDropMax; i++) {
		jsonw_uint_field(wr, tx_drop_reason_strs[i], opennsl_stats.tx_drops[i]);
	}
	jsonw_end_object(wr);
	jsonw_name(wr, "PortStats");
	jsonw_start_array(wr);
	for (int i = 0; i < OPENNSL_PBMP_PORT_MAX; i++) {
		if (!opennsl_stats.pstats[i].rx_pkts && !opennsl_stats.pstats[i].tx_pkts)
			continue;
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "Port", i);
		if (opennsl_stats.pstats[i].rx_pkts)
			jsonw_uint_field(wr, "RxPkts",
					 opennsl_stats.pstats[i].rx_pkts);
		if (opennsl_stats.pstats[i].tx_pkts)
			jsonw_uint_field(wr, "TxPkts",
					 opennsl_stats.pstats[i].tx_pkts);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
	fflush(f);
	jsonw_destroy(&wr);
}

static void fal_plugin_opennsl_phy_cmd(FILE *f, int argc, char **argv)
{
	int unit = 0;
	int rc;

	if (argc < 2)
		goto usage;

	if (!strcmp(argv[1], "diag")) {
		opennsl_port_t port;

		if (argc < 4)
			goto usage;
		port = strtol(argv[2], NULL, 10);
		if (!strcmp(argv[3], "loopback")) {
			opennsl_port_info_t info;
			opennsl_port_info_t_init(&info);

			if (argc < 5) {
				fprintf(f,
					"Usage: fal plugin opennsl phy diag <port> loopback mode=<none|mac|phy|rmt>\n");
				return;
			}

			info.action_mask = OPENNSL_PORT_ATTR_LOOPBACK_MASK;
			if (!strcmp(argv[4], "mode=none"))
				info.loopback = OPENNSL_PORT_LOOPBACK_NONE;
			else if (!strcmp(argv[4], "mode=mac"))
				info.loopback = OPENNSL_PORT_LOOPBACK_MAC;
			else if (!strcmp(argv[4], "mode=phy"))
				info.loopback = OPENNSL_PORT_LOOPBACK_PHY;
			else if (!strcmp(argv[4], "mode=rmt"))
				info.loopback = OPENNSL_PORT_LOOPBACK_PHY_REMOTE;
			else {
				fprintf(f,
					"Usage: fal plugin opennsl phy diag <port> loopback mode=<none|mac|phy|rmt>\n");
				return;
			}

			rc = opennsl_port_selective_set(unit, port, &info);
			if (rc)
				fprintf(f,
					"Failed to set loopback mode for port: %d (0x%x)",
					rc, rc);

			INFO(
				"Loopback mode %d set for port %d\n",
				info.loopback, port);
			return;
		}
	} else {
		goto usage;
	}

	return;

usage:
	fprintf(f,
		"Usage: fal plugin opennsl phy diag <port> <dsc|loopback|eyescan> <parameters>");
}

static void fal_opennsl_stat_db_show(FILE *f, int argc, char **argv)
{
	json_writer_t *wr;
	int unit = 0;

	if (!fal_opennsl_chip_cfg[unit]->dump_stat_db)
		return;

	wr = jsonw_new(f);
	if (!wr) {
		fprintf(f, "Could not allocate json writer\n");
		return;
	}

	jsonw_pretty(wr, true);

	fal_opennsl_chip_cfg[unit]->dump_stat_db(unit, wr);

	fflush(f);
	jsonw_destroy(&wr);
}

static void fal_opennsl_cntr_cmd(FILE *f, int argc, char **argv)
{
	int unit = 0;

	if (!fal_opennsl_chip_cfg[unit]->cntr_cmd)
		return;

	fal_opennsl_chip_cfg[unit]->cntr_cmd(f, argc, argv);
}

void fal_plugin_command(FILE *f, int argc, char **argv)
{
	if (argc < 2 || strcmp(argv[0], "opennsl")) {
		fprintf(f,
			"Usage: fal plugin opennsl <shell <cmd> | portinfo | debug | stats | fdb ... | phy ...>\n");
		return;
	}

	argc--;
	argv++;
	if (!strcmp(argv[0], "shell"))
		fal_plugin_opennsl_shell_cmd(f, argc, argv);
	else if (!strcmp(argv[0], "portinfo"))
		fal_plugin_opennsl_portinfo_cmd(f, argc, argv);
	else if (!strcmp(argv[0], "debug"))
		fal_plugin_opennsl_debug_cmd(f, argc, argv);
	else if (!strcmp(argv[0], "stats"))
		fal_plugin_opennsl_stats(f, argc, argv);
	else if (!strcmp(argv[0], "stat_db"))
		fal_opennsl_stat_db_show(f, argc, argv);
	else if (!strcmp(argv[0], "cntr"))
		fal_opennsl_cntr_cmd(f, argc, argv);
	else if (!strcmp(argv[0], "fdb"))
		fal_plugin_opennsl_fdb(f, argc, argv);
	else if (!strcmp(argv[0], "phy"))
		fal_plugin_opennsl_phy_cmd(f, argc, argv);
	else
		fprintf(f, "Unknown command %s\n", argv[0]);
}

int fal_opennsl_rx_trap_unset(
	const struct fal_opennsl_rx_trap_type_setup *trap_setup)
{
	int unit = 0;
	int ret = OPENNSL_E_NONE;

	if (trap_ids[trap_setup->type] < 0)
		return ret;

	ret = opennsl_rx_trap_type_destroy(unit, trap_ids[trap_setup->type]);
	if (OPENNSL_FAILURE(ret)) {
		ERROR("%s: opennsl_rx_trap_type_destroy %s failed - %s\n",
		      __func__, trap_setup->str,
		      opennsl_errmsg(ret));
		return ret;
	}
	trap_ids[trap_setup->type] = -1;
	return ret;
}

int fal_opennsl_rx_trap_set(
	const struct fal_opennsl_rx_trap_type_setup *trap_setup)
{
	opennsl_mirror_options_t mirror_cmd;
	opennsl_rx_trap_config_t rx_trap_config;
	int unit = 0;
	int trap_id;
	int ret = OPENNSL_E_NONE;

	if (trap_ids[trap_setup->type] >= 0)
		trap_id = trap_ids[trap_setup->type];
	else {
		ret = opennsl_rx_trap_type_create(unit, 0,
					     trap_setup->type,
					     &trap_id);
		if (OPENNSL_FAILURE(ret)) {
			ERROR("%s: opennsl_rx_trap_type_create %s failed - %s\n",
			      __func__, trap_setup->str,
			      opennsl_errmsg(ret));
			return ret;
		}
		trap_ids[trap_setup->type] = trap_id;
	}
	opennsl_mirror_options_t_init(&mirror_cmd);
	opennsl_rx_trap_config_t_init(&rx_trap_config);
	rx_trap_config.mirror_cmd = &mirror_cmd;
	rx_trap_config.flags |= OPENNSL_RX_TRAP_UPDATE_DEST;
	if (trap_setup->punt)
		rx_trap_config.dest_port = fal_opennsl_get_punt_port();
	else
		rx_trap_config.dest_port = trap_setup->port;
	rx_trap_config.trap_strength = trap_setup->strength;
	ret = opennsl_rx_trap_set(unit, trap_id, &rx_trap_config);
	if (OPENNSL_FAILURE(ret)) {
		ERROR("%s: opennsl_rx_trap_set %s failed - %s\n",
		      __func__, trap_setup->str,
		      opennsl_errmsg(ret));
	}
	return ret;
}

/*
 * Global switch operations
 */

/*
 * Set global switch attribute values
 */
int fal_plugin_set_switch_attribute(const struct fal_attribute_t *attr)
{
	enum fal_packet_action_t action;
	int ret = OPENNSL_E_NONE;

	if (!attr) {
		ret = OPENNSL_E_PARAM;
		ERROR("%s: Failed to set attribute - %s\n",
		      __func__, opennsl_errmsg(ret));
		return ret;
	}

	switch (attr->id) {
	case FAL_SWITCH_ATTR_RX_ICMP_REDIR_ACTION:
		action = attr->value.u32;
		ret = fal_opennsl_set_ip_icmp_redirect(action);
		if (!OPENNSL_FAILURE(ret)) {
			INFO("%s: %d action set to %d\n", __func__,
			     attr->id, action);
		}
		break;
	}
	return ret;
}

/*
 * get backplane port id
 * For now, always return the first backplane port
 */
opennsl_port_t fal_opennsl_get_backplane_port(void)
{
	if (fal_opennsl_configuration.num_bp_ports)
		return fal_opennsl_configuration.bp_ports[0].opennsl_port;
	return 0;
}


uint16_t fal_opennsl_get_backplane_dpdk_port(void)
{
	if (fal_opennsl_configuration.num_bp_ports)
		return fal_opennsl_configuration.bp_ports[0].dpdk_port;
	return -1;
}

/*
 * Get a port to use for punting packets to the software dataplane
 */
opennsl_port_t fal_opennsl_get_punt_port(void)
{
	if (fal_opennsl_configuration.num_bp_ports)
		return fal_opennsl_configuration.bp_ports[0].opennsl_port;
	return OPENNSL_GPORT_LOCAL_CPU;
}

opennsl_port_t fal_opennsl_get_dummy_mirror_port(int unit, unsigned int index)
{
	return OPENNSL_GPORT_BLACK_HOLE;
}

char *fal_opennsl_get_gport_name(int unit, opennsl_port_t gport, char *buf,
			     size_t len)
{
	if (!OPENNSL_GPORT_IS_SET(gport)) {
		snprintf(buf, len, "%s", opennsl_port_name(unit, gport));
	} else if (OPENNSL_GPORT_IS_MODPORT(gport)) {
		snprintf(buf, len, "%s",
			 opennsl_port_name(unit,
					   OPENNSL_GPORT_MODPORT_PORT_GET(gport)));
	} else {
		snprintf(buf, len, "<unknown-0x%x>", gport);
	}
	return buf;
}
