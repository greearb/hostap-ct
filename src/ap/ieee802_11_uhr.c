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
#include "sta_info.h"
#include "ieee802_11.h"


size_t hostapd_eid_uhr_capab_len(struct hostapd_data *hapd,
				 enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct uhr_capabilities *uhr_cap;
	size_t len = 3 /* ext elem header */ +
		sizeof(struct ieee80211_uhr_capabilities);

	mode = hapd->iface->current_mode;
	if (!mode)
		return 0;

	uhr_cap = &mode->uhr_capab[opmode];
	if (!uhr_cap->uhr_supported)
		return 0;

	if (uhr_cap->mac[1] & IEEE80211_UHR_MAC_CAP1_DBE_SUPP)
		len++;

	return len;
}


u8 * hostapd_eid_uhr_capab(struct hostapd_data *hapd, u8 *eid,
			   enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct he_capabilities *he_cap;
	struct eht_capabilities *eht_cap;
	struct uhr_capabilities *uhr_cap;
	struct ieee80211_uhr_capabilities *cap;
	u8 *pos = eid, *length_pos;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	he_cap = &mode->he_capab[opmode];
	eht_cap = &mode->eht_capab[opmode];
	uhr_cap = &mode->uhr_capab[opmode];
	if (!he_cap->he_supported ||
	    !eht_cap->eht_supported ||
	    !uhr_cap->uhr_supported)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_UHR_CAPABILITIES;

	cap = (struct ieee80211_uhr_capabilities *) pos;
	os_memcpy(cap->mac, uhr_cap->mac, sizeof(cap->mac));
	os_memcpy(cap->phy, uhr_cap->phy, sizeof(cap->phy));
	pos += sizeof(*cap);

	if (opmode == IEEE80211_MODE_AP &&
	    cap->mac[1] & IEEE80211_UHR_MAC_CAP1_DBE_SUPP) {
		/*
		 * Assume that HE implies VHT implies 80 MHz at least,
		 * DBE doesn't exist on 2.4 GHz and the capability
		 * shouldn't be set by the driver.
		 *
		 * It's also not very relevant if DBE isn't enabled.
		 */
		u8 dbe_bw = IEEE80211_UHR_DBE_CAP_MAX_BW_80MHZ;

		if (he_cap->phy_cap[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
		    HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G)
			dbe_bw = IEEE80211_UHR_DBE_CAP_MAX_BW_160MHZ;

		if (is_6ghz_op_class(hapd->iconf->op_class) &&
		    eht_cap->phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &
		    EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK)
			dbe_bw = IEEE80211_UHR_DBE_CAP_MAX_BW_320MHZ;

		/*
		 * No MCS maps or other further DBE capabilities since we just
		 * use EHT capabilities and advertise full EHT capabilities
		 * even if operating in a lower bandwidth.
		 */
		*pos++ = dbe_bw;
	}

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


static bool ieee80211_invalid_uhr_cap_size(enum hostapd_hw_mode mode,
					   const u8 *uhr_cap, size_t len)
{
	return len < sizeof(struct ieee80211_uhr_capabilities);
}


u16 copy_sta_uhr_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       enum ieee80211_op_mode opmode,
		       const u8 *uhr_capab, size_t uhr_capab_len)
{
	struct hostapd_hw_modes *c_mode = hapd->iface->current_mode;
	enum hostapd_hw_mode mode = c_mode ? c_mode->mode : NUM_HOSTAPD_MODES;

	if (!hostapd_is_uhr_enabled(hapd) || !uhr_capab ||
	    ieee80211_invalid_uhr_cap_size(mode, uhr_capab, uhr_capab_len)) {
		sta->flags &= ~WLAN_STA_UHR;
		os_free(sta->uhr_capab);
		sta->uhr_capab = NULL;
		return WLAN_STATUS_SUCCESS;
	}

	os_free(sta->uhr_capab);
	sta->uhr_capab = os_memdup(uhr_capab, uhr_capab_len);
	if (!sta->uhr_capab) {
		sta->uhr_capab_len = 0;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->flags |= WLAN_STA_UHR;
	sta->uhr_capab_len = uhr_capab_len;

	return WLAN_STATUS_SUCCESS;
}


void hostapd_get_uhr_capab(struct hostapd_data *hapd,
			   const struct ieee80211_uhr_capabilities *src,
			   struct ieee80211_uhr_capabilities *dest,
			   size_t len)
{
	if (!src || !dest)
		return;

	if (len > sizeof(*dest))
		len = sizeof(*dest);
	/* TODO: mask out unsupported features */

	os_memset(dest, 0, sizeof(*dest));
	os_memcpy(dest, src, len);
}
