/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_H
#define NAN_H

struct nan_cluster_config;

struct nan_config {
	void *cb_ctx;

	/**
	 * start - Start NAN
	 * @ctx: Callback context from cb_ctx
	 * @config: NAN cluster configuration
	 */
	int (*start)(void *ctx, struct nan_cluster_config *config);

	/**
	 * stop - Stop NAN
	 * @ctx: Callback context from cb_ctx
	 */
	void (*stop)(void *ctx);
};

struct nan_data * nan_init(const struct nan_config *cfg);
void nan_deinit(struct nan_data *nan);
int nan_start(struct nan_data *nan, struct nan_cluster_config *config);
void nan_stop(struct nan_data *nan);
void nan_flush(struct nan_data *nan);

#endif /* NAN_H */
