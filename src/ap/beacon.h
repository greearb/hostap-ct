/*
 * hostapd / IEEE 802.11 Management: Beacon and Probe Request/Response
 * Copyright (c) 2002-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef BEACON_H
#define BEACON_H

struct ieee80211_mgmt;

enum bss_crit_update_event {
	BSS_CRIT_UPDATE_EVENT_CSA,
	BSS_CRIT_UPDATE_EVENT_ECSA,
	BSS_CRIT_UPDATE_EVENT_EDCA,
	BSS_CRIT_UPDATE_EVENT_QUIET,
	BSS_CRIT_UPDATE_EVENT_DSSS,
	BSS_CRIT_UPDATE_EVENT_HT_OPERATION,
	BSS_CRIT_UPDATE_EVENT_WBCS,
	BSS_CRIT_UPDATE_EVENT_CS_WRAP,
	BSS_CRIT_UPDATE_EVENT_OP_MODE_NOTIF,
	BSS_CRIT_UPDATE_EVENT_QUIET_CH,
	BSS_CRIT_UPDATE_EVENT_VHT_OPERATION,
	BSS_CRIT_UPDATE_EVENT_HE_OPERATION,
	BSS_CRIT_UPDATE_EVENT_BCAST_TWT,
	BSS_CRIT_UPDATE_EVENT_BCAST_TWT_PARAM_SET,
	BSS_CRIT_UPDATE_EVENT_CCA,
	BSS_CRIT_UPDATE_EVENT_MU_EDCA,
	BSS_CRIT_UPDATE_EVENT_SR,
	BSS_CRIT_UPDATE_EVENT_UORA,
	BSS_CRIT_UPDATE_EVENT_IDX_ADJUST_FACTOR,
	BSS_CRIT_UPDATE_EVENT_EHT_OPERATION,
	BSS_CRIT_UPDATE_EVENT_TPE,
	BSS_CRIT_UPDATE_EVENT_CH_CHANGED,
	BSS_CRIT_UPDATE_EVENT_RECONFIG,
	BSS_CRIT_UPDATE_EVENT_ADD_LINK,
	BSS_CRIT_UPDATE_EVENT_ATTLM
};

enum {
	BSS_CRIT_UPDATE_NONE,
	BSS_CRIT_UPDATE_SINGLE,
	BSS_CRIT_UPDATE_ALL,
	BSS_CRIT_UPDATE_FLAG
};

void handle_probe_req(struct hostapd_data *hapd,
		      const struct ieee80211_mgmt *mgmt, size_t len,
		      int ssi_signal);
void ieee802_11_set_beacon_per_bss_only(struct hostapd_data *hapd);
int ieee802_11_set_beacon(struct hostapd_data *hapd);
int ieee802_11_set_beacons(struct hostapd_iface *iface);
int ieee802_11_set_bss_critical_update(struct hostapd_data *hapd,
				       enum bss_crit_update_event event);
int ieee802_11_update_beacons(struct hostapd_iface *iface);
int ieee802_11_build_ap_params(struct hostapd_data *hapd,
			       struct wpa_driver_ap_params *params);
void ieee802_11_free_ap_params(struct wpa_driver_ap_params *params);
void sta_track_add(struct hostapd_iface *iface, const u8 *addr, int ssi_signal);
void sta_track_del(struct hostapd_sta_info *info);
void sta_track_expire(struct hostapd_iface *iface, int force);
struct hostapd_data *
sta_track_seen_on(struct hostapd_iface *iface, const u8 *addr,
		  const char *ifname);
void sta_track_claim_taxonomy_info(struct hostapd_iface *iface, const u8 *addr,
				   struct wpabuf **probe_ie_taxonomy);

const u8 * hostapd_wpa_ie(struct hostapd_data *hapd, u8 eid);

u8 * hostapd_unsol_bcast_probe_resp(struct hostapd_data *hapd,
				    struct unsol_bcast_probe_resp *ubpr);
void hostapd_gen_per_sta_profiles(struct hostapd_data *hapd);

#endif /* BEACON_H */
