/*
 * hostapd / IEEE 802.11bn UHR
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "ieee802_11.h"


size_t hostapd_eid_uhr_capab_len(struct hostapd_data *hapd,
				 enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct uhr_capabilities *uhr_cap;

	mode = hapd->iface->current_mode;
	if (!mode)
		return 0;

	uhr_cap = &mode->uhr_capab[opmode];
	if (!uhr_cap->uhr_supported)
		return 0;

	return 3 /* ext elem header */ +
		sizeof(struct ieee80211_uhr_capabilities);
}


u8 * hostapd_eid_uhr_capab(struct hostapd_data *hapd, u8 *eid,
			   enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct uhr_capabilities *uhr_cap;
	struct ieee80211_uhr_capabilities *cap;
	u8 *pos = eid, *length_pos;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	uhr_cap = &mode->uhr_capab[opmode];
	if (!uhr_cap->uhr_supported)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_UHR_CAPABILITIES;

	cap = (struct ieee80211_uhr_capabilities *) pos;
	os_memcpy(cap->mac, uhr_cap->mac, sizeof(cap->mac));
	os_memcpy(cap->phy, uhr_cap->phy, sizeof(cap->phy));
	pos += sizeof(*cap);

	*length_pos = pos - (eid + 2);
	return pos;
}


u8 * hostapd_eid_uhr_operation(struct hostapd_data *hapd, u8 *eid, bool beacon)
{
	struct ieee80211_uhr_operation *oper;
	u8 *pos = eid;

	if (!hapd->iface->current_mode)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + sizeof(*oper);
	*pos++ = WLAN_EID_EXT_UHR_OPERATION;

	oper = (struct ieee80211_uhr_operation *) pos;
	oper->oper_ctrl = 0;

	/* TODO: Fill in appropriate UHR-MCS max Nss information */
	oper->basic_uhr_mcs_nss_set[0] = 0x11;
	oper->basic_uhr_mcs_nss_set[1] = 0x00;
	oper->basic_uhr_mcs_nss_set[2] = 0x00;
	oper->basic_uhr_mcs_nss_set[3] = 0x00;

	return pos + sizeof(*oper);
}
