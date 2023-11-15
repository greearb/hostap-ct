/*
 * DFS - Dynamic Frequency Selection
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2013-2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef DFS_H
#define DFS_H

enum dfs_channel_type {
	DFS_ANY_CHANNEL,
	DFS_AVAILABLE, /* non-radar or radar-available */
	DFS_NO_CAC_YET, /* radar-not-yet-available */
};

int hostapd_handle_dfs(struct hostapd_iface *iface);

int hostapd_dfs_complete_cac(struct hostapd_iface *iface, int success, int freq,
			     int ht_enabled, int chan_offset, int chan_width,
			     int cf1, int cf2);
int hostapd_dfs_pre_cac_expired(struct hostapd_iface *iface, int freq,
				int ht_enabled, int chan_offset, int chan_width,
				int cf1, int cf2);
int hostapd_dfs_radar_detected(struct hostapd_iface *iface, int freq,
			       int ht_enabled,
			       int chan_offset, int chan_width,
			       int cf1, int cf2);
int hostapd_dfs_nop_finished(struct hostapd_iface *iface, int freq,
			     int ht_enabled,
			     int chan_offset, int chan_width, int cf1, int cf2);
int hostapd_dfs_background_chan_update(struct hostapd_iface *iface, int freq,
				       int ht_enabled, int chan_offset, int chan_width,
				       int cf1, int cf2, bool expand);
int hostapd_dfs_sta_update_state(struct hostapd_iface *iface, int freq,
				 int ht_enabled, int chan_offset, int chan_width,
				 int cf1, int cf2, u32 state);
int hostapd_is_dfs_required(struct hostapd_iface *iface);
int hostapd_is_dfs_chan_available(struct hostapd_iface *iface);
int hostapd_dfs_start_cac(struct hostapd_iface *iface, int freq,
			  int ht_enabled, int chan_offset, int chan_width,
			  int cf1, int cf2);
int hostapd_handle_dfs_offload(struct hostapd_iface *iface);
int hostapd_dfs_get_target_state(struct hostapd_iface *iface, enum chan_width width,
				 int center_freq, int center_freq2);
int dfs_find_channel(struct hostapd_iface *iface,
		     struct hostapd_channel_data **ret_chan,
		     int n_chans, int idx, enum dfs_channel_type type);
int hostapd_dfs_handle_csa(struct hostapd_iface *iface,
			   struct csa_settings *settings,
			   struct csa_settings *background_settings,
			   bool cac_required, bool bw_changed);

#endif /* DFS_H */
