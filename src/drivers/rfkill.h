/*
 * Linux rfkill helper functions for driver wrappers
 * Copyright (c) 2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef RFKILL_H
#define RFKILL_H

struct rfkill_data {
	struct rfkill_config *cfg;
	int fd;
	int is_blocked;
};

struct rfkill_config {
	void *ctx;
	void (*blocked_cb)(void *ctx, int rfkill_index);
	void (*unblocked_cb)(void *ctx, int rfkill_index);
};

struct rfkill_data * rfkill_init(struct rfkill_config *cfg,
				 const char *phyname);
void rfkill_deinit(struct rfkill_data *rfkill);
int rfkill_idx_belongs_to_phyname(int rfkill_idx,
				  const char *phyname);
#endif /* RFKILL_H */
