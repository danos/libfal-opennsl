/*
 * Copyright (c) 2018, AT&T Intellectual Property.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 */
/*
 * Copyright(c) 2016 Brocade Communications Systems
 * Adapted from DPDK ring PMD licensed as below:
 */
/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
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

#ifndef _RTE_ETH_OPENNSLSW_H_
#define _RTE_ETH_OPENNSLSW_H_

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <opennsl/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct opennsl_port;

int fal_opennsl_pmd_register_rte_eth(const char *name, int unit, opennsl_port_t port,
				 opennsl_gport_t sysport, struct opennsl_port **bport);

int fal_opennsl_pmd_port_enqueue_rx_mbuf(struct opennsl_port *port,
	struct rte_mbuf **bufs, int nb_bufs);

uint16_t fal_opennsl_pmd_port_get_portid(struct opennsl_port *port);

struct bridge_vlan_set *fal_opennsl_pmd_port_get_vlans(struct opennsl_port *port);

struct bridge_vlan_set *fal_opennsl_pmd_port_get_untagged_vlans(struct opennsl_port *port);

opennsl_port_t fal_opennsl_pmd_port_get_port(struct opennsl_port *port);

int fal_opennsl_pmd_port_get_unit(struct opennsl_port *port);

opennsl_gport_t fal_opennsl_pmd_port_get_sysport(struct opennsl_port *port);

int fal_opennsl_pmd_port_set_link(struct opennsl_port *port,
	struct rte_eth_link *link);

int fal_opennsl_pmd_port_read_link(struct opennsl_port *port,
	struct rte_eth_link *link);

uint32_t fal_opennsl_port_opennsl_to_dpdk_speed(struct opennsl_port *port, int speed);
uint16_t fal_opennsl_port_opennsl_to_dpdk_duplex(struct opennsl_port *port, int duplex);
uint16_t fal_opennsl_port_opennsl_to_dpdk_status(struct opennsl_port *port, int linkstatus);

void fal_opennsl_pmd_port_set_pvid(struct opennsl_port *port, uint16_t pvid);
uint16_t fal_opennsl_pmd_port_get_pvid(struct opennsl_port *port);
#ifdef __cplusplus
}
#endif

#endif
