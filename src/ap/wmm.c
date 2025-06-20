/*
 * hostapd / WMM (Wi-Fi Multimedia)
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "wmm.h"


static inline u8 wmm_aci_aifsn(int aifsn, int acm, int aci)
{
	u8 ret;
	ret = (aifsn << WMM_AC_AIFNS_SHIFT) & WMM_AC_AIFSN_MASK;
	if (acm)
		ret |= WMM_AC_ACM;
	ret |= (aci << WMM_AC_ACI_SHIFT) & WMM_AC_ACI_MASK;
	return ret;
}


static inline u8 wmm_ecw(int ecwmin, int ecwmax)
{
	return ((ecwmin << WMM_AC_ECWMIN_SHIFT) & WMM_AC_ECWMIN_MASK) |
		((ecwmax << WMM_AC_ECWMAX_SHIFT) & WMM_AC_ECWMAX_MASK);
}


static void
wmm_set_regulatory_limit(const struct hostapd_wmm_ac_params *wmm_conf,
			 struct hostapd_wmm_ac_params *wmm,
			 const struct hostapd_wmm_rule *wmm_reg)
{
	int ac;

	for (ac = 0; ac < WMM_AC_NUM; ac++) {
		wmm[ac].cwmin = MAX(wmm_conf[ac].cwmin, wmm_reg[ac].min_cwmin);
		wmm[ac].cwmax = MAX(wmm_conf[ac].cwmax, wmm_reg[ac].min_cwmax);
		wmm[ac].aifs = MAX(wmm_conf[ac].aifs, wmm_reg[ac].min_aifs);
		wmm[ac].txop_limit =
			MIN(wmm_conf[ac].txop_limit, wmm_reg[ac].max_txop);
		wmm[ac].admission_control_mandatory =
			wmm_conf[ac].admission_control_mandatory;
	}
}


/*
 * Calculate WMM regulatory limit if any.
 */
static void wmm_calc_regulatory_limit(struct hostapd_data *hapd,
				      struct hostapd_wmm_ac_params *acp)
{
	struct hostapd_hw_modes *mode = hapd->iface->current_mode;
	int c;

	os_memcpy(acp, hapd->iconf->wmm_ac_params,
		  sizeof(hapd->iconf->wmm_ac_params));

	for (c = 0; mode && c < mode->num_channels; c++) {
		struct hostapd_channel_data *chan = &mode->channels[c];

		if (chan->freq != hapd->iface->freq)
			continue;

		if (chan->wmm_rules_valid)
			wmm_set_regulatory_limit(hapd->iconf->wmm_ac_params,
						 acp, chan->wmm_rules);
		break;
	}

	/*
	 * Check if we need to update set count. Since both were initialized to
	 * zero we can compare the whole array in one shot.
	 */
	if (os_memcmp(acp, hapd->iface->prev_wmm,
		      sizeof(hapd->iconf->wmm_ac_params)) != 0) {
		os_memcpy(hapd->iface->prev_wmm, acp,
			  sizeof(hapd->iconf->wmm_ac_params));
		hapd->parameter_set_count++;
	}
}


size_t hostapd_eid_wmm_len(struct hostapd_data *hapd) {
	return hapd->conf->wmm_enabled? sizeof(struct wmm_parameter_element) + 2 : 0;
}


/*
 * Add WMM Parameter Element to Beacon, Probe Response, and (Re)Association
 * Response frames.
 */
u8 * hostapd_eid_wmm(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	struct wmm_parameter_element *wmm =
		(struct wmm_parameter_element *) (pos + 2);
	struct hostapd_wmm_ac_params wmmp[WMM_AC_NUM];
	int e;

	os_memset(wmmp, 0, sizeof(wmmp));

	if (!hapd->conf->wmm_enabled)
		return eid;
	wmm_calc_regulatory_limit(hapd, wmmp);
	eid[0] = WLAN_EID_VENDOR_SPECIFIC;
	wmm->oui[0] = 0x00;
	wmm->oui[1] = 0x50;
	wmm->oui[2] = 0xf2;
	wmm->oui_type = WMM_OUI_TYPE;
	wmm->oui_subtype = WMM_OUI_SUBTYPE_PARAMETER_ELEMENT;
	wmm->version = WMM_VERSION;
	wmm->qos_info = hapd->parameter_set_count & 0xf;

	if (hapd->conf->wmm_uapsd &&
	    (hapd->iface->drv_flags & WPA_DRIVER_FLAGS_AP_UAPSD))
		wmm->qos_info |= 0x80;

	wmm->reserved = 0;

	/* fill in a parameter set record for each AC */
	for (e = 0; e < 4; e++) {
		struct wmm_ac_parameter *ac = &wmm->ac[e];
		struct hostapd_wmm_ac_params *acp = &wmmp[e];

		ac->aci_aifsn = wmm_aci_aifsn(acp->aifs,
					      acp->admission_control_mandatory,
					      e);
		ac->cw = wmm_ecw(acp->cwmin, acp->cwmax);
		ac->txop_limit = host_to_le16(acp->txop_limit);
	}

	pos = (u8 *) (wmm + 1);
	eid[1] = pos - eid - 2; /* element length */

	return pos;
}


/*
 * This function is called when a station sends an association request with
 * WMM info element. The function returns 1 on success or 0 on any error in WMM
 * element. eid does not include Element ID and Length octets.
 */
int hostapd_eid_wmm_valid(struct hostapd_data *hapd, const u8 *eid, size_t len)
{
	struct wmm_information_element *wmm;

	wpa_hexdump(MSG_MSGDUMP, "WMM IE", eid, len);

	if (len < sizeof(struct wmm_information_element)) {
		wpa_printf(MSG_DEBUG, "Too short WMM IE (len=%lu)",
			   (unsigned long) len);
		return 0;
	}

	wmm = (struct wmm_information_element *) eid;
	wpa_printf(MSG_DEBUG, "Validating WMM IE: OUI %02x:%02x:%02x  "
		   "OUI type %d  OUI sub-type %d  version %d  QoS info 0x%x",
		   wmm->oui[0], wmm->oui[1], wmm->oui[2], wmm->oui_type,
		   wmm->oui_subtype, wmm->version, wmm->qos_info);
	if (wmm->oui_subtype != WMM_OUI_SUBTYPE_INFORMATION_ELEMENT ||
	    wmm->version != WMM_VERSION) {
		wpa_printf(MSG_DEBUG, "Unsupported WMM IE Subtype/Version");
		return 0;
	}

	return 1;
}


static void wmm_send_action(struct hostapd_data *hapd, const u8 *addr,
			    const struct wmm_tspec_element *tspec,
			    u8 action_code, u8 dialogue_token, u8 status_code)
{
	u8 buf[256];
	struct ieee80211_mgmt *m = (struct ieee80211_mgmt *) buf;
	struct wmm_tspec_element *t = (struct wmm_tspec_element *)
		m->u.action.u.wmm_action.variable;
	int len;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		       "action response - reason %d", status_code);
	os_memset(buf, 0, sizeof(buf));
	m->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					WLAN_FC_STYPE_ACTION);
	os_memcpy(m->da, addr, ETH_ALEN);
	os_memcpy(m->sa, hapd->own_addr, ETH_ALEN);
	os_memcpy(m->bssid, hapd->own_addr, ETH_ALEN);
	m->u.action.category = WLAN_ACTION_WMM;
	m->u.action.u.wmm_action.action_code = action_code;
	m->u.action.u.wmm_action.dialog_token = dialogue_token;
	m->u.action.u.wmm_action.status_code = status_code;
	os_memcpy(t, tspec, sizeof(struct wmm_tspec_element));
	len = ((u8 *) (t + 1)) - buf;

	if (hostapd_drv_send_mlme(hapd, m, len, 0, NULL, 0, 0) < 0)
		wpa_printf(MSG_INFO, "wmm_send_action: send failed");
}


int wmm_process_tspec(struct wmm_tspec_element *tspec)
{
	u64 medium_time;
	unsigned int pps, duration;
	unsigned int up, psb, dir, tid;
	u16 val, surplus;

	up = (tspec->ts_info[1] >> 3) & 0x07;
	psb = (tspec->ts_info[1] >> 2) & 0x01;
	dir = (tspec->ts_info[0] >> 5) & 0x03;
	tid = (tspec->ts_info[0] >> 1) & 0x0f;
	wpa_printf(MSG_DEBUG, "WMM: TS Info: UP=%d PSB=%d Direction=%d TID=%d",
		   up, psb, dir, tid);
	val = le_to_host16(tspec->nominal_msdu_size);
	wpa_printf(MSG_DEBUG, "WMM: Nominal MSDU Size: %d%s",
		   val & 0x7fff, val & 0x8000 ? " (fixed)" : "");
	wpa_printf(MSG_DEBUG, "WMM: Mean Data Rate: %u bps",
		   le_to_host32(tspec->mean_data_rate));
	wpa_printf(MSG_DEBUG, "WMM: Minimum PHY Rate: %u bps",
		   le_to_host32(tspec->minimum_phy_rate));
	val = le_to_host16(tspec->surplus_bandwidth_allowance);
	wpa_printf(MSG_DEBUG, "WMM: Surplus Bandwidth Allowance: %u.%04u",
		   val >> 13, 10000 * (val & 0x1fff) / 0x2000);

	val = le_to_host16(tspec->nominal_msdu_size);
	if (val == 0) {
		wpa_printf(MSG_DEBUG, "WMM: Invalid Nominal MSDU Size (0)");
		return WMM_ADDTS_STATUS_INVALID_PARAMETERS;
	}
	/* pps = Ceiling((Mean Data Rate / 8) / Nominal MSDU Size) */
	pps = ((le_to_host32(tspec->mean_data_rate) / 8) + val - 1) / val;
	wpa_printf(MSG_DEBUG, "WMM: Packets-per-second estimate for TSPEC: %d",
		   pps);

	if (le_to_host32(tspec->minimum_phy_rate) < 1000000) {
		wpa_printf(MSG_DEBUG, "WMM: Too small Minimum PHY Rate");
		return WMM_ADDTS_STATUS_INVALID_PARAMETERS;
	}

	duration = (le_to_host16(tspec->nominal_msdu_size) & 0x7fff) * 8 /
		(le_to_host32(tspec->minimum_phy_rate) / 1000000) +
		50 /* FIX: proper SIFS + ACK duration */;

	/* unsigned binary number with an implicit binary point after the
	 * leftmost 3 bits, i.e., 0x2000 = 1.0 */
	surplus = le_to_host16(tspec->surplus_bandwidth_allowance);
	if (surplus <= 0x2000) {
		wpa_printf(MSG_DEBUG, "WMM: Surplus Bandwidth Allowance not "
			   "greater than unity");
		return WMM_ADDTS_STATUS_INVALID_PARAMETERS;
	}

	medium_time = (u64) surplus * pps * duration / 0x2000;
	wpa_printf(MSG_DEBUG, "WMM: Estimated medium time: %lu",
		   (unsigned long) medium_time);

	/*
	 * TODO: store list of granted (and still active) TSPECs and check
	 * whether there is available medium time for this request. For now,
	 * just refuse requests that would by themselves take very large
	 * portion of the available bandwidth.
	 */
	if (medium_time > 750000) {
		wpa_printf(MSG_DEBUG, "WMM: Refuse TSPEC request for over "
			   "75%% of available bandwidth");
		return WMM_ADDTS_STATUS_REFUSED;
	}

	/* Convert to 32 microseconds per second unit */
	tspec->medium_time = host_to_le16(medium_time / 32);

	return WMM_ADDTS_STATUS_ADMISSION_ACCEPTED;
}


static void wmm_addts_req(struct hostapd_data *hapd,
			  const struct ieee80211_mgmt *mgmt,
			  const struct wmm_tspec_element *tspec, size_t len)
{
	const u8 *end = ((const u8 *) mgmt) + len;
	int res;
	struct wmm_tspec_element tspec_resp;

	if ((const u8 *) (tspec + 1) > end) {
		wpa_printf(MSG_DEBUG, "WMM: TSPEC overflow in ADDTS Request");
		return;
	}

	wpa_printf(MSG_DEBUG, "WMM: ADDTS Request (Dialog Token %d) for TSPEC "
		   "from " MACSTR,
		   mgmt->u.action.u.wmm_action.dialog_token,
		   MAC2STR(mgmt->sa));

	os_memcpy(&tspec_resp, tspec, sizeof(struct wmm_tspec_element));
	res = wmm_process_tspec(&tspec_resp);
	wpa_printf(MSG_DEBUG, "WMM: ADDTS processing result: %d", res);

	wmm_send_action(hapd, mgmt->sa, &tspec_resp, WMM_ACTION_CODE_ADDTS_RESP,
			mgmt->u.action.u.wmm_action.dialog_token, res);
}


void hostapd_wmm_action(struct hostapd_data *hapd,
			const struct ieee80211_mgmt *mgmt, size_t len)
{
	int action_code;
	int left = len - IEEE80211_HDRLEN - 4;
	const u8 *pos = ((const u8 *) mgmt) + IEEE80211_HDRLEN + 4;
	struct ieee802_11_elems elems;
	struct sta_info *sta = ap_get_sta(hapd, mgmt->sa);

	/* check that the request comes from a valid station */
	if (!sta ||
	    (sta->flags & (WLAN_STA_ASSOC | WLAN_STA_WMM)) !=
	    (WLAN_STA_ASSOC | WLAN_STA_WMM)) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "wmm action received is not from associated wmm"
			       " station");
		/* TODO: respond with action frame refused status code */
		return;
	}

	if (left < 0)
		return; /* not a valid WMM Action frame */

	/* extract the tspec info element */
	if (ieee802_11_parse_elems(pos, left, &elems, 1) == ParseFailed) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "hostapd_wmm_action - could not parse wmm "
			       "action");
		/* TODO: respond with action frame invalid parameters status
		 * code */
		return;
	}

	if (!elems.wmm_tspec ||
	    elems.wmm_tspec_len != (sizeof(struct wmm_tspec_element) - 2)) {
		hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "hostapd_wmm_action - missing or wrong length "
			       "tspec");
		/* TODO: respond with action frame invalid parameters status
		 * code */
		return;
	}

	/* TODO: check the request is for an AC with ACM set, if not, refuse
	 * request */

	action_code = mgmt->u.action.u.wmm_action.action_code;
	switch (action_code) {
	case WMM_ACTION_CODE_ADDTS_REQ:
		wmm_addts_req(hapd, mgmt, (struct wmm_tspec_element *)
			      (elems.wmm_tspec - 2), len);
		return;
#if 0
	/* TODO: needed for client implementation */
	case WMM_ACTION_CODE_ADDTS_RESP:
		wmm_setup_request(hapd, mgmt, len);
		return;
	/* TODO: handle station teardown requests */
	case WMM_ACTION_CODE_DELTS:
		wmm_teardown(hapd, mgmt, len);
		return;
#endif
	}

	hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		       "hostapd_wmm_action - unknown action code %d",
		       action_code);
}

size_t hostapd_eid_eht_epcs_ml_len(struct mld_info *mld)
{
	size_t len = 3 + sizeof(struct ieee80211_eht_ml) +
		     sizeof(struct eht_ml_epcs_common_info);
	int link_id;

	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; ++link_id) {
		if (!mld->links[link_id].valid)
			continue;

		/* Subelement ID + Length + STA Control + STA Profile
		 * STA Profile: Contains only one WMM Parameter Element
		 */
		len += 2 + sizeof(struct ieee80211_eht_per_sta_profile) +
		       2 + sizeof(struct wmm_parameter_element);
	}

	return len;
}

int hostapd_eid_eht_epcs_ml(struct hostapd_data *hapd, struct wpabuf *buf,
			    struct mld_info *mld, u16 *wmm_idx_tbl)
{
#ifdef CONFIG_IEEE80211BE
	struct hapd_interfaces *ifaces = hapd->iface->interfaces;
	int link_id;

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	wpabuf_put_u8(buf, hostapd_eid_eht_epcs_ml_len(mld) - 2);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);
	wpabuf_put_le16(buf, MULTI_LINK_CONTROL_TYPE_PRIOR_ACCESS);

	/* Common Info */
	wpabuf_put_u8(buf, sizeof(struct eht_ml_epcs_common_info));
	wpabuf_put_data(buf, hapd->mld->mld_addr, ETH_ALEN);

	/* Link Info */
	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; ++link_id) {
		struct wmm_parameter_element *elem;
		u16 idx = wmm_idx_tbl[link_id];
		u8 *pos, ac;

		if (!mld->links[link_id].valid)
			continue;

		/* Per-STA Profile subelement */
		wpabuf_put_u8(buf, EHT_ML_SUB_ELEM_PER_STA_PROFILE);
		wpabuf_put_u8(buf, sizeof(struct ieee80211_eht_per_sta_profile) +
				   2 + sizeof(struct wmm_parameter_element));
		wpabuf_put_le16(buf, link_id);

		/* WMM Parameter Element */
		pos = wpabuf_put(buf, 2 + sizeof(struct wmm_parameter_element));
		if (!pos)
			return -ENOBUFS;

		if (hostapd_eid_wmm(hapd, pos) == pos)
			return -EPERM;

		/* Overwrite AC parameters with EPCS ones */
		elem = (struct wmm_parameter_element *)(pos + 2);
		for (ac = WMM_AC_BE; ac < WMM_AC_NUM; ++ac) {
			struct hostapd_wmm_ac_params *epcs = &ifaces->epcs.wmm_tbl[idx][ac];
			struct wmm_ac_parameter *params = &elem->ac[ac];

			params->aci_aifsn = wmm_aci_aifsn(epcs->aifs,
							  epcs->admission_control_mandatory,
							  ac);
			params->cw = wmm_ecw(epcs->cwmin, epcs->cwmax);
			params->txop_limit = host_to_le16(epcs->txop_limit);
		}
	}
#endif

	return 0;
}

