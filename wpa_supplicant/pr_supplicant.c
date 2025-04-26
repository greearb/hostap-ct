/*
 * Proxmity Ranging
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "utils/common.h"
#include "common/proximity_ranging.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#include "pr_supplicant.h"


int wpas_pr_init(struct wpa_global *global, struct wpa_supplicant *wpa_s,
		 const struct wpa_driver_capa *capa)
{
	struct pr_config pr;

	if (global->pr)
		return 0;

	os_memset(&pr, 0, sizeof(pr));

	os_memcpy(pr.dev_addr, wpa_s->own_addr, ETH_ALEN);
	pr.cb_ctx = wpa_s;
	pr.dev_name = wpa_s->conf->device_name;
	pr.pasn_type = wpa_s->conf->pr_pasn_type;
	pr.preferred_ranging_role = wpa_s->conf->pr_preferred_role;

	pr.edca_ista_support = wpa_s->drv_flags2 &
		WPA_DRIVER_FLAGS2_FTM_INITIATOR;
	pr.edca_rsta_support = wpa_s->drv_flags &
		WPA_DRIVER_FLAGS_FTM_RESPONDER;
	pr.edca_format_and_bw = capa->edca_format_and_bw;
	pr.max_rx_antenna = capa->max_rx_antenna;
	pr.max_tx_antenna = capa->max_tx_antenna;

	pr.ntb_ista_support = wpa_s->drv_flags2 &
		WPA_DRIVER_FLAGS2_NON_TRIGGER_BASED_INITIATOR;
	pr.ntb_rsta_support = wpa_s->drv_flags2 &
		WPA_DRIVER_FLAGS2_NON_TRIGGER_BASED_RESPONDER;
	pr.ntb_format_and_bw = capa->ntb_format_and_bw;
	pr.max_tx_ltf_repetations = capa->max_tx_ltf_repetations;
	pr.max_rx_ltf_repetations = capa->max_rx_ltf_repetations;
	pr.max_tx_ltf_total = capa->max_tx_ltf_total;
	pr.max_rx_ltf_total = capa->max_rx_ltf_total;
	pr.max_rx_sts_le_80 = capa->max_rx_sts_le_80;
	pr.max_rx_sts_gt_80 = capa->max_rx_sts_gt_80;
	pr.max_tx_sts_le_80 = capa->max_tx_sts_le_80;
	pr.max_tx_sts_gt_80 = capa->max_tx_sts_gt_80;

	pr.support_6ghz = wpas_is_6ghz_supported(wpa_s, true);

	pr.secure_he_ltf = wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_SEC_LTF_STA;

	if (wpa_s->conf->country[0] && wpa_s->conf->country[1]) {
		os_memcpy(pr.country, wpa_s->conf->country, 2);
		pr.country[2] = 0x04;
	} else {
		os_memcpy(pr.country, "XX\x04", 3);
	}

	global->pr = pr_init(&pr);
	if (!global->pr) {
		wpa_printf(MSG_DEBUG, "PR: Failed to init PR");
		return -1;
	}
	global->pr_init_wpa_s = wpa_s;

	return 0;
}


void wpas_pr_deinit(struct wpa_supplicant *wpa_s)
{
	if (wpa_s == wpa_s->global->pr_init_wpa_s) {
		pr_deinit(wpa_s->global->pr);
		wpa_s->global->pr = NULL;
		wpa_s->global->pr_init_wpa_s = NULL;
	}
}
