/*
 * Proxmity Ranging
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PROXIMITY_RANGING_H
#define PROXIMITY_RANGING_H

#include "utils/list.h"

/**
 * PR_MAX_PEER - Maximum number of Proximity Ranging peers that device can store
 */
#define PR_MAX_PEER 100

/**
 * struct pr_device_info - Proximity ranging peer information
 */
struct pr_device {
	struct dl_list list;
	struct os_reltime last_seen;

	/**
	 * pr_device_addr - PR Device Address of the peer
	 */
	u8 pr_device_addr[ETH_ALEN];
};


struct pr_config {
	u8 dev_addr[ETH_ALEN];

	/**
	 * dev_name - Device Name
	 */
	char *dev_name;

	/**
	 * cb_ctx - Context to use with callback functions
	 */
	void *cb_ctx;
};

struct pr_data {
	/**
	 * cfg - PR module configuration
	 *
	 * This is included in the same memory allocation with the
	 * struct pr_data and as such, must not be freed separately.
	 */
	struct pr_config *cfg;

	struct dl_list devices;
};

struct pr_data * pr_init(const struct pr_config *cfg);
void pr_deinit(struct pr_data *pr);

#endif /* PROXIMITY_RANGING_H */
