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


static int wpas_pr_edca_get_bw(enum edca_format_and_bw_value format_and_bw)
{
	switch (format_and_bw) {
	case EDCA_FORMAT_AND_BW_VHT20:
		return 20;
	case EDCA_FORMAT_AND_BW_HT40:
	case EDCA_FORMAT_AND_BW_VHT40:
		return 40;
	case EDCA_FORMAT_AND_BW_VHT80:
		return 80;
	case EDCA_FORMAT_AND_BW_VHT80P80:
	case EDCA_FORMAT_AND_BW_VHT160_DUAL_LO:
	case EDCA_FORMAT_AND_BW_VHT160_SINGLE_LO:
		return 160;
	default:
		return 0;
	}
}


static int wpas_pr_ntb_get_bw(enum ntb_format_and_bw_value format_and_bw)
{
	switch (format_and_bw) {
	case NTB_FORMAT_AND_BW_HE20:
		return 20;
	case NTB_FORMAT_AND_BW_HE40:
		return 40;
	case NTB_FORMAT_AND_BW_HE80:
		return 80;
	case NTB_FORMAT_AND_BW_HE80P80:
	case NTB_FORMAT_AND_BW_HE160_DUAL_LO:
	case NTB_FORMAT_AND_BW_HE160_SINGLE_LO:
		return 160;
	default:
		return 0;
	}
}


static bool
wpas_pr_edca_is_valid_op_class(enum edca_format_and_bw_value format_and_bw,
			       const struct oper_class_map *op_class_map)
{
	int bw = 0, op_class_bw = 0;

	if (!op_class_map)
		return false;

	op_class_bw = oper_class_bw_to_int(op_class_map);
	bw = wpas_pr_edca_get_bw(format_and_bw);

	if (!op_class_bw || !bw)
		return false;

	if (format_and_bw <= EDCA_FORMAT_AND_BW_VHT80 &&
	    format_and_bw >= EDCA_FORMAT_AND_BW_VHT20 &&
	    op_class_bw <= bw)
		return true;

	if (format_and_bw == EDCA_FORMAT_AND_BW_VHT80P80 &&
	    (op_class_bw < bw || op_class_map->bw == BW80P80))
		return true;

	if ((format_and_bw == EDCA_FORMAT_AND_BW_VHT160_DUAL_LO ||
	     format_and_bw == EDCA_FORMAT_AND_BW_VHT160_SINGLE_LO) &&
	    (op_class_bw < bw || op_class_map->bw == BW160))
		return true;

	return false;
}


static bool
wpas_pr_ntb_is_valid_op_class(enum ntb_format_and_bw_value format_and_bw,
			      const struct oper_class_map *op_class_map)
{
	int bw = 0, op_class_bw = 0;

	if (!op_class_map)
		return false;

	op_class_bw = oper_class_bw_to_int(op_class_map);
	bw = wpas_pr_ntb_get_bw(format_and_bw);

	if (!op_class_bw || !bw)
		return false;

	if (format_and_bw <= NTB_FORMAT_AND_BW_HE80 &&
	    format_and_bw >= NTB_FORMAT_AND_BW_HE20 &&
	    op_class_bw <= bw)
		return true;

	if (format_and_bw == NTB_FORMAT_AND_BW_HE80P80 &&
		   (op_class_bw < bw || op_class_map->bw == BW80P80))
		return true;

	if ((format_and_bw == NTB_FORMAT_AND_BW_HE160_DUAL_LO ||
	     format_and_bw == NTB_FORMAT_AND_BW_HE160_SINGLE_LO) &&
	    (op_class_bw < bw || op_class_map->bw == BW160))
		return true;

	return false;
}


static void
wpas_pr_setup_edca_channels(struct wpa_supplicant *wpa_s,
			    struct pr_channels *chan,
			    enum edca_format_and_bw_value format_and_bw)
{
	struct hostapd_hw_modes *mode;
	int cla = 0, i;

	for (i = 0; global_op_class[i].op_class; i++) {
		unsigned int ch;
		struct pr_op_class *op = NULL;
		const struct oper_class_map *o = &global_op_class[i];

		mode = get_mode(wpa_s->hw.modes, wpa_s->hw.num_modes, o->mode,
				is_6ghz_op_class(o->op_class));
		if (!mode || is_6ghz_op_class(o->op_class) ||
		    !wpas_pr_edca_is_valid_op_class(format_and_bw, o))
			continue;

		for (ch = o->min_chan; ch <= o->max_chan; ch += o->inc) {
			enum chan_allowed res;

			/* Check for non-continuous jump in channel index
			 * increment.
			 */
			if (o->op_class >= 128 && o->op_class <= 130 &&
			    ch < 149 && ch + o->inc > 149)
				ch = 149;

			res = verify_channel(mode, o->op_class, ch, o->bw);

			if (res == ALLOWED) {
				if (!op) {
					if (cla == PR_MAX_OP_CLASSES)
						continue;

					wpa_printf(MSG_DEBUG,
						   "PR: Add operating class: %u (EDCA)",
						   o->op_class);
					op = &chan->op_class[cla];
					cla++;
					op->op_class = o->op_class;
				}
				if (op->channels == PR_MAX_OP_CLASS_CHANNELS)
					continue;
				op->channel[op->channels] = ch;
				op->channels++;
			}
		}

		if (op)
			wpa_hexdump(MSG_DEBUG, "PR: Channels (EDCA)",
				    op->channel, op->channels);
	}

	chan->op_classes = cla;
}


static void
wpas_pr_setup_ntb_channels(struct wpa_supplicant *wpa_s,
			   struct pr_channels *chan,
			   enum ntb_format_and_bw_value format_and_bw,
			   bool allow_6ghz)
{
	int cla = 0, i;
	struct hostapd_hw_modes *mode;

	for (i = 0; global_op_class[i].op_class; i++) {
		unsigned int ch;
		struct pr_op_class *op = NULL;
		const struct oper_class_map *o = &global_op_class[i];

		mode = get_mode(wpa_s->hw.modes, wpa_s->hw.num_modes, o->mode,
				is_6ghz_op_class(o->op_class));
		if (!mode || (!allow_6ghz && is_6ghz_op_class(o->op_class)) ||
		    !wpas_pr_ntb_is_valid_op_class(format_and_bw, o))
			continue;

		for (ch = o->min_chan; ch <= o->max_chan; ch += o->inc) {
			enum chan_allowed res;

			/* Check for non-continuous jump in channel index
			 * increment.
			 */
			if (o->op_class >= 128 && o->op_class <= 130 &&
			    ch < 149 && ch + o->inc > 149)
				ch = 149;

			res = verify_channel(mode, o->op_class, ch, o->bw);

			if (res == ALLOWED) {
				if (!op) {
					if (cla == PR_MAX_OP_CLASSES)
						continue;
					wpa_printf(MSG_DEBUG,
						   "PR: Add operating class: %u (NTB)",
						   o->op_class);
					op = &chan->op_class[cla];
					cla++;
					op->op_class = o->op_class;
				}
				if (op->channels == PR_MAX_OP_CLASS_CHANNELS)
					continue;
				op->channel[op->channels] = ch;
				op->channels++;
			}
		}
		if (op) {
			wpa_hexdump(MSG_DEBUG, "PR: Channels (NTB)",
				    op->channel, op->channels);
		}
	}

	chan->op_classes = cla;
}


struct wpabuf * wpas_pr_usd_elems(struct wpa_supplicant *wpa_s)
{
	return pr_prepare_usd_elems(wpa_s->global->pr);
}


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

	wpas_pr_setup_edca_channels(wpa_s, &pr.edca_channels,
				    pr.edca_format_and_bw);

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

	wpas_pr_setup_ntb_channels(wpa_s, &pr.ntb_channels,
				   pr.ntb_format_and_bw,
				   pr.support_6ghz);

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
