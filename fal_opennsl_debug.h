/*-
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef __FAL_OPENNSL_DEBUG_H__
#define __FAL_OPENNSL_DEBUG_H__

#include <rte_log.h>

#define LOG(l, t, ...)											\
	rte_log(RTE_LOG_ ## l,										\
		RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__);

#define INFO(...) LOG(INFO, FAL_OPENNSL,  __VA_ARGS__);
#define ERROR(...) LOG(ERR, FAL_OPENNSL, __VA_ARGS__);
#define DEBUG(...) LOG(DEBUG, FAL_OPENNSL, __VA_ARGS__);

#define FAL_OPENNSL_DEBUG_PKT          0x00000001

#define FAL_OPENNSL_DBG(flag, ...)						   \
	if (fal_opennsl_debug & flag)                          \
		DEBUG(__VA_ARGS__);

#endif
