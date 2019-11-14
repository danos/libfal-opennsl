/*
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * ID allocation manager
 */
#ifndef __FAL_OPENNSL_ID_MGR_H__
#define __FAL_OPENNSL_ID_MGR_H__

#include <stdint.h>

struct fal_opennsl_id_table;

int fal_opennsl_id_table_alloc(uint32_t max_ids,
			   struct fal_opennsl_id_table **table);
int fal_opennsl_id_table_free(struct fal_opennsl_id_table *table);
int fal_opennsl_id_alloc(struct fal_opennsl_id_table *table, uint32_t number,
		     uint32_t *starting_id);
int fal_opennsl_id_free(struct fal_opennsl_id_table *table, uint32_t number,
		    uint32_t starting_id);

#endif
