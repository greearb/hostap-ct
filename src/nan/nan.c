/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "nan.h"
#include "nan_i.h"


struct nan_data * nan_init(const struct nan_config *cfg)
{
	struct nan_data *nan;

	if (!cfg->start || !cfg->stop)
		return NULL;

	nan = os_zalloc(sizeof(*nan));
	if (!nan)
		return NULL;

	nan->cfg = os_memdup(cfg, sizeof(*cfg));
	if (!nan->cfg) {
		os_free(nan);
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "NAN: Initialized");

	return nan;
}


void nan_deinit(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Deinit");
	os_free(nan->cfg);
	os_free(nan);
}


int nan_start(struct nan_data *nan, struct nan_cluster_config *config)
{
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Starting/joining NAN cluster");

	if (nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already started");
		return -1;
	}

	ret = nan->cfg->start(nan->cfg->cb_ctx, config);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to start - ret=%d", ret);
		return ret;
	}
	nan->nan_started = 1;

	return 0;
}


void nan_flush(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Reset internal state");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already stopped");
		return;
	}

	nan->nan_started = 0;
}


void nan_stop(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Stopping");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already stopped");
		return;
	}

	nan_flush(nan);
	nan->cfg->stop(nan->cfg->cb_ctx);
}
