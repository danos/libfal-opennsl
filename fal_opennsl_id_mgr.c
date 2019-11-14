/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * ID allocation manager
 */

#include <bsd/sys/bitstring.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#include "fal_opennsl_id_mgr.h"

struct fal_opennsl_id_table {
	uint32_t max_ids;
	bitstr_t ids[];
};

int fal_opennsl_id_table_alloc(uint32_t max_ids,
			   struct fal_opennsl_id_table **table)
{
	*table = calloc(1, offsetof(struct fal_opennsl_id_table,
				    ids[bitstr_size(max_ids)]));
	if (!*table)
		return -ENOMEM;

	(*table)->max_ids = max_ids;

	return 0;
}

int fal_opennsl_id_table_free(struct fal_opennsl_id_table *table)
{
	free(table);

	return 0;
}

int fal_opennsl_id_alloc(struct fal_opennsl_id_table *table, uint32_t number,
		     uint32_t *starting_id)
{
	uint32_t succ_id;
	uint32_t id;

	if (!number)
		return -ENOSPC;

	for (id = 0; id < table->max_ids; id++) {
		if (!bit_test(table->ids, id)) {
			/*
			 * found a free id at the starting point, so
			 * now check whether the whole range is free.
			 */
			for (succ_id = id;
			     succ_id < id + number && succ_id < table->max_ids;
			     succ_id++) {
				if (bit_test(table->ids, succ_id)) {
					/*
					 * didn't find a free range -
					 * no point in trying other
					 * starting points within the
					 * range, so skip to the entry
					 * at the end.
					 */
					id += number - 1;
					break;
				}
			}
			if (succ_id == id + number) {
				for (succ_id = id;
				     succ_id < id + number;
				     succ_id++)
					bit_set(table->ids, succ_id);
				*starting_id = id;
				return 0;
			}
		}
	}

	return -ENOSPC;
}

int fal_opennsl_id_free(struct fal_opennsl_id_table *table, uint32_t number,
		    uint32_t starting_id)
{
	uint32_t id;

	/* check that the ids are actually valid */
	for (id = starting_id; id < starting_id + number; id++)
		if (!bit_test(table->ids, id))
			return -EINVAL;

	for (id = starting_id; id < starting_id + number; id++)
		bit_clear(table->ids, id);

	return 0;
}

#ifdef TEST

int main(int argc, char *argv[])
{
	struct fal_opennsl_id_table *table;
	uint32_t id2;
	uint32_t id;
	int ret;

	ret = fal_opennsl_id_table_alloc(6, &table);
	if (ret) abort();

	/* allocate and free one ID */

	ret = fal_opennsl_id_alloc(table, 1, &id);
	if (ret) abort();
	ret = fal_opennsl_id_free(table, 1, id);
	if (ret) abort();

	/* allocate a range, test out of space, free the range */

	ret = fal_opennsl_id_alloc(table, 6, &id);
	if (ret) abort();
	ret = fal_opennsl_id_alloc(table, 1, &id2);
	if (ret != -ENOSPC) abort();
	ret = fal_opennsl_id_free(table, 6, id);
	if (ret) abort();

	/* allocate IDs leaving a gap, then allocate a range */

	ret = fal_opennsl_id_alloc(table, 1, &id);
	if (ret) abort();
	ret = fal_opennsl_id_alloc(table, 1, &id2);
	if (ret) abort();
	if (id == id2) abort();
	ret = fal_opennsl_id_free(table, 1, id);
	if (ret) abort();
	ret = fal_opennsl_id_alloc(table, 2, &id);
	if (ret) abort();
	if (id == id2 || id + 1 == id2) abort();
	ret = fal_opennsl_id_free(table, 1, id2);
	if (ret) abort();
	ret = fal_opennsl_id_free(table, 2, id);
	if (ret) abort();

	ret = fal_opennsl_id_table_free(table);
	if (ret) abort();

	return 0;
}

#endif /* TEST */
