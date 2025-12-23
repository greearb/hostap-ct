/*
 * wpa_supplicant - NAN
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "nan/nan.h"
#include "config.h"

#define DEFAULT_NAN_MASTER_PREF 2
#define DEFAULT_NAN_DUAL_BAND   0


static int wpas_nan_start_cb(void *ctx, struct nan_cluster_config *config)
{
	struct wpa_supplicant *wpa_s = ctx;

	return wpa_drv_nan_start(wpa_s, config);
}


static void wpas_nan_stop_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_drv_nan_stop(wpa_s);
}


int wpas_nan_init(struct wpa_supplicant *wpa_s)
{
	struct nan_config nan;

	if (!(wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_SUPPORT_NAN) ||
	    !(wpa_s->nan_drv_flags & WPA_DRIVER_FLAGS_NAN_SUPPORT_SYNC_CONFIG))
	{
		wpa_printf(MSG_INFO, "NAN: Driver does not support NAN");
		return -1;
	}

	os_memset(&nan, 0, sizeof(nan));
	nan.cb_ctx = wpa_s;

	nan.start = wpas_nan_start_cb;
	nan.stop = wpas_nan_stop_cb;

	wpa_s->nan = nan_init(&nan);
	if (!wpa_s->nan) {
		wpa_printf(MSG_INFO, "NAN: Failed to init");
		return -1;
	}

	return 0;
}


void wpas_nan_deinit(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->nan)
		return;

	nan_deinit(wpa_s->nan);
	wpa_s->nan = NULL;
}


static int wpas_nan_ready(struct wpa_supplicant *wpa_s)
{
	return wpa_s->nan_mgmt && wpa_s->nan &&
		wpa_s->wpa_state != WPA_INTERFACE_DISABLED;
}


/* Join a cluster using current configuration */
int wpas_nan_start(struct wpa_supplicant *wpa_s)
{
	struct nan_cluster_config cluster_config;

	if (!wpas_nan_ready(wpa_s))
		return -1;

	if (!(wpa_s->nan_drv_flags &
	      WPA_DRIVER_FLAGS_NAN_SUPPORT_SYNC_CONFIG)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Driver doesn't support configurable NAN sync");
		return -1;
	}

	cluster_config.master_pref = DEFAULT_NAN_MASTER_PREF;
	cluster_config.dual_band = DEFAULT_NAN_DUAL_BAND;

	return nan_start(wpa_s->nan, &cluster_config);
}


int wpas_nan_stop(struct wpa_supplicant *wpa_s)
{
	if (!wpas_nan_ready(wpa_s))
		return -1;

	nan_stop(wpa_s->nan);
	nan_de_set_cluster_id(wpa_s->nan_de, NULL);

	return 0;
}


void wpas_nan_flush(struct wpa_supplicant *wpa_s)
{
	if (!wpas_nan_ready(wpa_s))
		return;

	nan_flush(wpa_s->nan);
}


void wpas_nan_cluster_join(struct wpa_supplicant *wpa_s,
			   const u8 *cluster_id,
			   bool new_cluster)
{
	if (!wpas_nan_ready(wpa_s))
		return;

	wpa_msg_global(wpa_s, MSG_INFO, NAN_CLUSTER_JOIN "cluster_id=" MACSTR
		       " new=%d", MAC2STR(cluster_id), new_cluster);

	nan_de_set_cluster_id(wpa_s->nan_de, cluster_id);
}


void wpas_nan_next_dw(struct wpa_supplicant *wpa_s, u32 freq)
{
	if (!wpas_nan_ready(wpa_s))
		return;

	wpa_printf(MSG_DEBUG, "NAN: Next DW notification freq=%d", freq);
	nan_de_dw_trigger(wpa_s->nan_de, freq);
}
