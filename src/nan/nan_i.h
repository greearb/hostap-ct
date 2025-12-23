/*
 * Wi-Fi Aware - Internal definitions for NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_I_H
#define NAN_I_H

struct nan_config;

struct nan_data {
	struct nan_config *cfg;
	u8 nan_started:1;
};

#endif /* NAN_I_H */
