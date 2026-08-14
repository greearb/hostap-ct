/*
 * WPA Supplicant - background scan and roaming module: simple
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "drivers/driver.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "config.h"
#include "wnm_sta.h"
#include "bss.h"
#include "ctrl_iface.h"
#include "bgscan.h"

struct bgscan_simple_data {
	struct wpa_supplicant *wpa_s;
	const struct wpa_ssid *ssid;
	unsigned int use_btm_query; /* number of btm queries to schedule */
	unsigned int use_nr_request; /* number of neighbor report requests */
	unsigned int scan_action_count; /* counter for short scan actions */
	int scan_interval;
	int signal_threshold;
	int short_scan_count; /* counter for scans using short scan interval */
	int max_short_scans; /* maximum times we short-scan before back-off */
	int short_interval; /* use if signal < threshold */
	int long_interval; /* use if signal > threshold */
	struct os_reltime last_bgscan;
};

#ifndef CONFIG_NO_RRM
enum bgscan_scan_action_type {
	BGSCAN_BTM_QUERY,
	BGSCAN_NR_REQUEST,
	/* Book mark for length of enum. Insert new members above.*/
	BGSCAN_MAX
};

static bool bgscan_simple_btm_query(struct wpa_supplicant *wpa_s,
	                            struct bgscan_simple_data *data)
{
	if (!data->use_btm_query || wpa_s->conf->disable_btm ||
	    !wpa_s->current_bss ||
	    !wpa_bss_ext_capab(wpa_s->current_bss,
			       WLAN_EXT_CAPAB_BSS_TRANSITION)) {
		wpa_printf(MSG_DEBUG,
			   "bgscan simple: Inadequate capabilities for BTM Query.");
		return false;
	}

	if (wnm_send_bss_transition_mgmt_query(wpa_s,
					       WNM_TRANSITION_REASON_BETTER_AP_FOUND,
					       NULL, 0)) {
		wpa_printf(MSG_DEBUG,
			   "bgscan simple: Failed to send BSS transition management query");
		return false;
	}

	return true;
}

static bool bgscan_simple_nr_request(struct wpa_supplicant *wpa_s,
	                             struct bgscan_simple_data *data)
{
	struct wpa_ssid_value ssid_p;

	if (!data->use_nr_request ||
	    !wpa_s->current_bss) {
		wpa_printf(MSG_DEBUG,
			   "bgscan simple: Inadequate capabilities for neighbor report request.");
		return false;
	}

	memcpy(ssid_p.ssid, wpa_s->current_bss->ssid, SSID_MAX_LEN);
	ssid_p.ssid_len = MIN(wpa_s->current_bss->ssid_len, SSID_MAX_LEN);
	if (wpas_rrm_send_neighbor_rep_request(wpa_s, &ssid_p, 0, 0,
					       wpas_ctrl_neighbor_rep_cb,
					       wpa_s)) {
		wpa_printf(MSG_DEBUG,
			   "bgscan simple: Failed to send neighbor report request");
		return false;
	}

	return true;
}

static bool bgscan_schedule_action(struct wpa_supplicant *wpa_s,
				   struct bgscan_simple_data *data,
				   unsigned int schedule_period,
				   enum bgscan_scan_action_type type,
				   unsigned int max_scan_actions,
				   bool (*to_schedule)(struct wpa_supplicant*, struct bgscan_simple_data*),
				   char* debug)
{
	unsigned int round;

	/* Each schedulee takes an action each round, so dividing by the number
	 * of schedulees gives the round count. The current period is then
	 * determined with a modulus as the scheduling is cyclic. Returning
	 * true here indicates we were able to schedule the schedulee, and vice-
	 * versa. */
	round = (data->scan_action_count / BGSCAN_MAX) % (schedule_period + 1);
	if ((data->scan_action_count % BGSCAN_MAX == type))
		data->scan_action_count++;
	else
		return false;
	if (round >= max_scan_actions)
		return false;

	wpa_printf(MSG_DEBUG,
		   "bgscan simple: Scheduled %s %d/%d",
		   debug, (round + 1), max_scan_actions);

	if (!to_schedule(wpa_s, data))
		wpa_printf(MSG_DEBUG, "bgscan simple: Schedulable %s failed!", debug);

	return true;
}
#endif

static bool bgscan_run_schedule(struct wpa_supplicant *wpa_s,
				struct bgscan_simple_data *data)
{
#ifndef CONFIG_NO_RRM
	/* The schedule period is the longest running schedulee in terms of
	 * rounds it will be present for. */
	int i;
	unsigned int schedule_period = data->use_btm_query;
	schedule_period = MAX(schedule_period, data->use_nr_request);
	/* Check the schedule twice, as we may need to in a cyclic manner;
	 * If one schedulee has remaining rounds to run, but was just
	 * previously scheduled, it will need to be checked again if all
	 * the other schedulees forgo scheduling. */
	for (i = 0; i < 2; i++) {
		if (bgscan_schedule_action(wpa_s, data, schedule_period,
					  BGSCAN_BTM_QUERY, data->use_btm_query,
					  bgscan_simple_btm_query, "BTM Query"))
			return true;
		if (bgscan_schedule_action(wpa_s, data, schedule_period,
					  BGSCAN_NR_REQUEST, data->use_nr_request,
					  bgscan_simple_nr_request, "Neighbor Report Request"))
			return true;
	}
#endif
	return false;
}

static void bgscan_simple_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct bgscan_simple_data *data = eloop_ctx;
	struct wpa_supplicant *wpa_s = data->wpa_s;
	struct wpa_driver_scan_params params;
	bool was_scan_action = false;

	if (bgscan_run_schedule(wpa_s, data)) {
		was_scan_action = true;
		/* Start a new timeout for the next scan action. */
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_simple_timeout, data, NULL);
		goto scan_ok;
	}

	os_memset(&params, 0, sizeof(params));
	params.num_ssids = 1;
	params.ssids[0].ssid = data->ssid->ssid;
	params.ssids[0].ssid_len = data->ssid->ssid_len;
	
	if (data->ssid->freq_list == NULL)
			params.freqs = data->ssid->scan_freq;
	else
			params.freqs = data->ssid->freq_list;

	/* Add OWE transition mode SSID of the current network */
	wpa_add_owe_scan_ssid(wpa_s, &params, data->ssid,
			      wpa_s->max_scan_ssids - params.num_ssids);

	/* Add OWE transition mode SSID of the current network */
	wpa_add_owe_scan_ssid(wpa_s, &params, data->ssid,
			      wpa_s->max_scan_ssids - params.num_ssids);

	/*
	 * A more advanced bgscan module would learn about most like channels
	 * over time and request scans only for some channels (probing others
	 * every now and then) to reduce effect on the data connection.
	 */

	wpa_printf(MSG_DEBUG, "bgscan simple: Request a background scan");
	if (wpa_supplicant_trigger_scan(wpa_s, &params, true, false)) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Failed to trigger scan");
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_simple_timeout, data, NULL);
	} else {
	scan_ok:
		if (data->scan_interval == data->short_interval) {
			/* btm is more efficient than scan, we assume,
			 * so don't penalize it.
			 */
			if (!was_scan_action)
				data->short_scan_count++;
			if (data->short_scan_count >= data->max_short_scans) {
				data->scan_interval = data->long_interval;
				wpa_printf(MSG_DEBUG, "bgscan simple: Backing "
					   "off to long scan interval");
			}
		} else if (data->short_scan_count > 0) {
			/*
			 * If we lasted a long scan interval without any
			 * CQM triggers, decrease the short-scan count,
			 * which allows 1 more short-scan interval to
			 * occur in the future when CQM triggers.
			 */
			data->short_scan_count--;
		}
		os_get_reltime(&data->last_bgscan);
	}
}


static int bgscan_simple_get_params(struct bgscan_simple_data *data,
				    const char *params)
{
	const char *pos;

	data->use_btm_query = 0;
	data->use_nr_request = 0;

	data->short_interval = atoi(params);

	pos = os_strchr(params, ':');
	if (pos == NULL)
		return 0;
	pos++;
	data->signal_threshold = atoi(pos);
	pos = os_strchr(pos, ':');
	if (pos == NULL) {
		wpa_printf(MSG_ERROR, "bgscan simple: Missing scan interval "
			   "for high signal");
		return -1;
	}
	pos++;
	data->long_interval = atoi(pos);
	pos = os_strchr(pos, ':');
	if (pos) {
		pos++;
		data->use_btm_query = atoi(pos);
	}
	pos = os_strchr(pos, ':');
	if (pos) {
		pos++;
		data->use_nr_request = atoi(pos);
	}

	return 0;
}


static void * bgscan_simple_init(struct wpa_supplicant *wpa_s,
				 const char *params,
				 const struct wpa_ssid *ssid)
{
	struct bgscan_simple_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->wpa_s = wpa_s;
	data->ssid = ssid;
	if (bgscan_simple_get_params(data, params) < 0) {
		os_free(data);
		return NULL;
	}
	if (data->short_interval <= 0)
		data->short_interval = 30;
	if (data->long_interval <= 0)
		data->long_interval = 30;

	wpa_printf(MSG_DEBUG, "bgscan simple: Signal strength threshold %d  "
		   "Short bgscan interval %d  Long bgscan interval %d",
		   data->signal_threshold, data->short_interval,
		   data->long_interval);

	if (data->signal_threshold &&
	    wpa_drv_signal_monitor(wpa_s, data->signal_threshold, 4) < 0) {
		wpa_printf(MSG_ERROR, "bgscan simple: Failed to enable "
			   "signal strength monitoring");
	}

	data->scan_interval = data->short_interval;
	data->max_short_scans = data->long_interval / data->short_interval + 1;
	if (data->signal_threshold) {
		wpa_s->signal_threshold = data->signal_threshold;
		/* Poll for signal info to set initial scan interval */
		struct wpa_signal_info siginfo;
		if (wpa_drv_signal_poll(wpa_s, &siginfo) == 0 &&
		    siginfo.data.signal >= data->signal_threshold)
			data->scan_interval = data->long_interval;
	}
	wpa_printf(MSG_DEBUG, "bgscan simple: Init scan interval: %d",
		   data->scan_interval);
	eloop_register_timeout(data->scan_interval, 0, bgscan_simple_timeout,
			       data, NULL);

	/*
	 * This function is called immediately after an association, so it is
	 * reasonable to assume that a scan was completed recently. This makes
	 * us skip an immediate new scan in cases where the current signal
	 * level is below the bgscan threshold.
	 */
	os_get_reltime(&data->last_bgscan);

	return data;
}


static void bgscan_simple_deinit(void *priv)
{
	struct bgscan_simple_data *data = priv;
	eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
	if (data->signal_threshold) {
		data->wpa_s->signal_threshold = 0;
		wpa_drv_signal_monitor(data->wpa_s, 0, 0);
	}
	os_free(data);
}


static int bgscan_simple_notify_scan(void *priv,
				     struct wpa_scan_results *scan_res)
{
	struct bgscan_simple_data *data = priv;

	wpa_printf(MSG_DEBUG, "bgscan simple: scan result notification");

	eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
	eloop_register_timeout(data->scan_interval, 0, bgscan_simple_timeout,
			       data, NULL);

	/*
	 * A more advanced bgscan could process scan results internally, select
	 * the BSS and request roam if needed. This sample uses the existing
	 * BSS/ESS selection routine. Change this to return 1 if selection is
	 * done inside the bgscan module.
	 */

	return 0;
}


static void bgscan_simple_notify_beacon_loss(void *priv)
{
	wpa_printf(MSG_DEBUG, "bgscan simple: beacon loss");
	/* TODO: speed up background scanning */
}


static void bgscan_simple_notify_signal_change(void *priv, int above,
					       int current_signal,
					       int current_noise,
					       int current_txrate)
{
	struct bgscan_simple_data *data = priv;
	int scan = 0;
	struct os_reltime now;

	if (data->short_interval == data->long_interval ||
	    data->signal_threshold == 0)
		return;

	wpa_printf(MSG_DEBUG, "bgscan simple: signal level changed "
		   "(above=%d current_signal=%d current_noise=%d "
		   "current_txrate=%d))", above, current_signal,
		   current_noise, current_txrate);
	if (data->scan_interval == data->long_interval && !above) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Start using short "
			   "bgscan interval");
		data->scan_interval = data->short_interval;
		os_get_reltime(&now);
		if (now.sec > data->last_bgscan.sec + 1 &&
		    data->short_scan_count <= data->max_short_scans)
			/*
			 * If we haven't just previously (<1 second ago)
			 * performed a scan, and we haven't depleted our
			 * budget for short-scans, perform a scan
			 * immediately.
			 */
			scan = 1;
		else if (data->last_bgscan.sec + data->long_interval >
			 now.sec + data->scan_interval) {
			/*
			 * Restart scan interval timer if currently scheduled
			 * scan is too far in the future.
			 */
			eloop_cancel_timeout(bgscan_simple_timeout, data,
					     NULL);
			eloop_register_timeout(data->scan_interval, 0,
					       bgscan_simple_timeout, data,
					       NULL);
		}
	} else if (data->scan_interval == data->short_interval && above) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Start using long bgscan "
			   "interval");
		data->scan_interval = data->long_interval;
		eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
		eloop_register_timeout(data->scan_interval, 0,
				       bgscan_simple_timeout, data, NULL);
	} else if (!above) {
		/*
		 * Signal dropped further 4 dB. Request a new scan if we have
		 * not yet scanned in a while.
		 */
		os_get_reltime(&now);
		if (now.sec > data->last_bgscan.sec + 10)
			scan = 1;
	}

	if (scan) {
		wpa_printf(MSG_DEBUG, "bgscan simple: Trigger immediate scan");
		eloop_cancel_timeout(bgscan_simple_timeout, data, NULL);
		eloop_register_timeout(0, 0, bgscan_simple_timeout, data,
				       NULL);
	}
}


const struct bgscan_ops bgscan_simple_ops = {
	.name = "simple",
	.init = bgscan_simple_init,
	.deinit = bgscan_simple_deinit,
	.notify_scan = bgscan_simple_notify_scan,
	.notify_beacon_loss = bgscan_simple_notify_beacon_loss,
	.notify_signal_change = bgscan_simple_notify_signal_change,
};
