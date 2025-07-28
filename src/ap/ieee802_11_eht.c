/*
 * hostapd / IEEE 802.11be EHT
 * Copyright (c) 2021-2022, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ocv.h"
#include "common/wpa_ctrl.h"
#include "crypto/crypto.h"
#include "crypto/dh_groups.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "wpa_auth.h"
#include "ieee802_11.h"
#include "ap_drv_ops.h"

static u16 ieee80211_eht_ppet_size(u16 ppe_thres_hdr, const u8 *phy_cap_info)
{
	u8 ru;
	u16 sz = 0;

	if ((phy_cap_info[EHT_PHYCAP_PPE_THRESHOLD_PRESENT_IDX] &
	     EHT_PHYCAP_PPE_THRESHOLD_PRESENT) == 0)
		return 0;

	ru = (ppe_thres_hdr &
	      EHT_PPE_THRES_RU_INDEX_MASK) >> EHT_PPE_THRES_RU_INDEX_SHIFT;
	while (ru) {
		if (ru & 0x1)
			sz++;
		ru >>= 1;
	}

	sz = sz * (1 + ((ppe_thres_hdr & EHT_PPE_THRES_NSS_MASK) >>
			EHT_PPE_THRES_NSS_SHIFT));
	sz = (sz * 6) + 9;
	if (sz % 8)
		sz += 8;
	sz /= 8;

	return sz;
}


static u8 ieee80211_eht_mcs_set_size(enum hostapd_hw_mode mode, u8 opclass,
				     int he_oper_chwidth, const u8 *he_phy_cap,
				     const u8 *eht_phy_cap)
{
	u8 sz = EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;
	bool band24, band5, band6;
	u8 he_phy_cap_chwidth = ~HE_PHYCAP_CHANNEL_WIDTH_MASK;
	u8 cap_chwidth;

	switch (he_oper_chwidth) {
	case CONF_OPER_CHWIDTH_80P80MHZ:
		he_phy_cap_chwidth |=
			HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G;
		/* fall through */
	case CONF_OPER_CHWIDTH_160MHZ:
		he_phy_cap_chwidth |= HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G;
		/* fall through */
	case CONF_OPER_CHWIDTH_80MHZ:
	case CONF_OPER_CHWIDTH_USE_HT:
		he_phy_cap_chwidth |= HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G |
			HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
		break;
	}

	cap_chwidth = he_phy_cap[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX];
	if (he_oper_chwidth != -1)
		he_phy_cap_chwidth &= cap_chwidth;
	else
		he_phy_cap_chwidth = cap_chwidth;

	band24 = mode == HOSTAPD_MODE_IEEE80211B ||
		mode == HOSTAPD_MODE_IEEE80211G ||
		mode == NUM_HOSTAPD_MODES;
	band5 = mode == HOSTAPD_MODE_IEEE80211A ||
		mode == NUM_HOSTAPD_MODES;
	band6 = is_6ghz_op_class(opclass);

	if (band24 &&
	    (he_phy_cap_chwidth & HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G) == 0)
		return EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY;

	if (band5 &&
	    (he_phy_cap_chwidth &
	     (HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G |
	      HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	      HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G)) == 0)
		return EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY;

	if (band5 &&
	    (he_phy_cap_chwidth &
	     (HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	      HE_PHYCAP_CHANNEL_WIDTH_SET_80PLUS80MHZ_IN_5G)))
	    sz += EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	if (band6 &&
	    (eht_phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &
	     EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK))
		sz += EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS;

	return sz;
}


size_t hostapd_eid_eht_capab_len(struct hostapd_data *hapd,
				 enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct eht_capabilities *eht_cap;
	size_t len = 3 + 2 + EHT_PHY_CAPAB_LEN;

	mode = hapd->iface->current_mode;
	if (!mode)
		return 0;

	eht_cap = &mode->eht_capab[opmode];
	if (!eht_cap->eht_supported)
		return 0;

	len += ieee80211_eht_mcs_set_size(mode->mode, hapd->iconf->op_class,
					  hapd->iconf->he_oper_chwidth,
					  mode->he_capab[opmode].phy_cap,
					  eht_cap->phy_cap);
	len += ieee80211_eht_ppet_size(WPA_GET_LE16(&eht_cap->ppet[0]),
				       eht_cap->phy_cap);

	return len;
}

u8 * hostapd_eid_eht_capab(struct hostapd_data *hapd, u8 *eid,
			   enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct eht_capabilities *eht_cap;
	struct ieee80211_eht_capabilities *cap;
	size_t mcs_nss_len, ppe_thresh_len;
	u8 *pos = eid, *length_pos;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	eht_cap = &mode->eht_capab[opmode];
	if (!eht_cap->eht_supported)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_EHT_CAPABILITIES;

	cap = (struct ieee80211_eht_capabilities *) pos;
	os_memset(cap, 0, sizeof(*cap));
	cap->mac_cap = host_to_le16(eht_cap->mac_cap);
	os_memcpy(cap->phy_cap, eht_cap->phy_cap, EHT_PHY_CAPAB_LEN);

	if (!is_6ghz_op_class(hapd->iconf->op_class))
		cap->phy_cap[EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &=
			~EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK;
	if (!hapd->iface->conf->eht_phy_capab.su_beamformer)
		cap->phy_cap[EHT_PHYCAP_SU_BEAMFORMER_IDX] &=
			~EHT_PHYCAP_SU_BEAMFORMER;

	if (!hapd->iface->conf->eht_phy_capab.su_beamformee)
		cap->phy_cap[EHT_PHYCAP_SU_BEAMFORMEE_IDX] &=
			~EHT_PHYCAP_SU_BEAMFORMEE;

	if (!hapd->iface->conf->eht_phy_capab.mu_beamformer)
		cap->phy_cap[EHT_PHYCAP_MU_BEAMFORMER_IDX] &=
			~EHT_PHYCAP_MU_BEAMFORMER_MASK;

	pos = cap->optional;

	mcs_nss_len = ieee80211_eht_mcs_set_size(mode->mode,
						 hapd->iconf->op_class,
						 hapd->iconf->he_oper_chwidth,
						 mode->he_capab[opmode].phy_cap,
						 eht_cap->phy_cap);
	if (mcs_nss_len) {
		os_memcpy(pos, eht_cap->mcs, mcs_nss_len);
		pos += mcs_nss_len;
	}

	ppe_thresh_len = ieee80211_eht_ppet_size(
				WPA_GET_LE16(&eht_cap->ppet[0]),
				eht_cap->phy_cap);
	if (ppe_thresh_len) {
		os_memcpy(pos, eht_cap->ppet, ppe_thresh_len);
		pos += ppe_thresh_len;
	}

	*length_pos = pos - (eid + 2);
	return pos;
}


u8 * hostapd_eid_eht_operation(struct hostapd_data *hapd, u8 *eid)
{
	struct hostapd_config *conf = hapd->iconf;
	struct ieee80211_eht_operation *oper;
	u8 *pos = eid, seg0 = 0, seg1 = 0;
	enum oper_chan_width chwidth;
	size_t elen = 1 + 4;
	bool eht_oper_info_present;
	u16 punct_bitmap = hostapd_get_punct_bitmap(hapd);

	if (!hapd->iface->current_mode)
		return eid;

	if (is_6ghz_op_class(conf->op_class))
		chwidth = op_class_to_ch_width(conf->op_class);
	else
		chwidth = conf->eht_oper_chwidth;

	eht_oper_info_present = chwidth == CONF_OPER_CHWIDTH_320MHZ ||
		punct_bitmap;

	if (eht_oper_info_present)
		elen += 3;

	if (punct_bitmap)
		elen += EHT_OPER_DISABLED_SUBCHAN_BITMAP_SIZE;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 1 + elen;
	*pos++ = WLAN_EID_EXT_EHT_OPERATION;

	oper = (struct ieee80211_eht_operation *) pos;
	oper->oper_params = 0;

	if (hapd->iconf->eht_default_pe_duration)
		oper->oper_params |= EHT_OPER_DEFAULT_PE_DURATION;

	/* TODO: Fill in appropriate EHT-MCS max Nss information */
	oper->basic_eht_mcs_nss_set[0] = 0x11;
	oper->basic_eht_mcs_nss_set[1] = 0x00;
	oper->basic_eht_mcs_nss_set[2] = 0x00;
	oper->basic_eht_mcs_nss_set[3] = 0x00;

	if (!eht_oper_info_present)
		return pos + elen;

	oper->oper_params |= EHT_OPER_INFO_PRESENT;
	seg0 = hostapd_get_oper_centr_freq_seg0_idx(conf);

	switch (chwidth) {
	case CONF_OPER_CHWIDTH_320MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_320MHZ;
		seg1 = seg0;
		if (hapd->iconf->channel < seg0)
			seg0 -= 16;
		else
			seg0 += 16;
		break;
	case CONF_OPER_CHWIDTH_160MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_160MHZ;
		seg1 = seg0;
		if (hapd->iconf->channel < seg0)
			seg0 -= 8;
		else
			seg0 += 8;
		break;
	case CONF_OPER_CHWIDTH_80MHZ:
		oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_80MHZ;
		break;
	case CONF_OPER_CHWIDTH_USE_HT:
		if (seg0)
			oper->oper_info.control |= EHT_OPER_CHANNEL_WIDTH_40MHZ;
		break;
	default:
		return eid;
	}

	oper->oper_info.ccfs0 = seg0 ? seg0 : hapd->iconf->channel;
	oper->oper_info.ccfs1 = seg1;

	if (punct_bitmap) {
		oper->oper_params |= EHT_OPER_DISABLED_SUBCHAN_BITMAP_PRESENT;
		oper->oper_info.disabled_chan_bitmap =
			host_to_le16(punct_bitmap);
	}

	return pos + elen;
}

u8 mlo_non_inherit_list_6ghz[] = {
	WLAN_EID_AP_CHANNEL_REPORT,
	WLAN_EID_HT_CAP,
	WLAN_EID_HT_OPERATION,
	WLAN_EID_VHT_CAP,
	WLAN_EID_VHT_OPERATION,
};

u8 mlo_non_inherit_list_6ghz_ext[] = {
};

u8 mlo_non_inherit_list_2_5ghz[] = {
	WLAN_EID_VHT_CAP,
	WLAN_EID_VHT_OPERATION,
	WLAN_EID_TRANSMIT_POWER_ENVELOPE,
};

u8 mlo_non_inherit_list_2_5ghz_ext[] = {
	WLAN_EID_EXT_HE_6GHZ_BAND_CAP,
};

size_t hostapd_eid_non_inheritance_len(struct hostapd_data *hapd)
{
	size_t len = 4;

	if (is_6ghz_op_class(hapd->iconf->op_class)) {
		len += sizeof(mlo_non_inherit_list_6ghz);
		len += sizeof(mlo_non_inherit_list_6ghz_ext);
	} else {
		len += sizeof(mlo_non_inherit_list_2_5ghz);
		len += sizeof(mlo_non_inherit_list_2_5ghz_ext);
	}

	return len;
}

u8 * hostapd_eid_non_inheritance(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid, *len_pos;
	int i;

	*pos++ = WLAN_EID_EXTENSION;
	len_pos = pos++;
	*pos++ = WLAN_EID_EXT_NON_INHERITANCE;
	if (is_6ghz_op_class(hapd->iconf->op_class)) {
		/* Element ID list */
		*pos++ = sizeof(mlo_non_inherit_list_6ghz);
		for (i = 0; i < sizeof(mlo_non_inherit_list_6ghz); i++)
			*pos++ = mlo_non_inherit_list_6ghz[i];

		/* Element ID Extension list */
		*pos++ = sizeof(mlo_non_inherit_list_6ghz_ext);
		for (i = 0; i < sizeof(mlo_non_inherit_list_6ghz_ext); i++)
			*pos++ = mlo_non_inherit_list_6ghz_ext[i];
	} else {
		/* Element ID list */
		*pos++ = sizeof(mlo_non_inherit_list_2_5ghz);
		for (i = 0; i < sizeof(mlo_non_inherit_list_2_5ghz); i++)
			*pos++ = mlo_non_inherit_list_2_5ghz[i];

		/* Element ID Extension list */
		*pos++ = sizeof(mlo_non_inherit_list_2_5ghz_ext);
		for (i = 0; i < sizeof(mlo_non_inherit_list_2_5ghz_ext); i++)
			*pos++ = mlo_non_inherit_list_2_5ghz_ext[i];
	}
	*len_pos = pos - (eid + 2);
	return pos;
}
static bool check_valid_eht_mcs_nss(struct hostapd_data *hapd, const u8 *ap_mcs,
				    const u8 *sta_mcs, u8 mcs_count, u8 map_len)
{
	unsigned int i, j;

	for (i = 0; i < mcs_count; i++) {
		ap_mcs += i * 3;
		sta_mcs += i * 3;

		for (j = 0; j < map_len; j++) {
			if (((ap_mcs[j] >> 4) & 0xFF) == 0)
				continue;

			if ((sta_mcs[j] & 0xFF) == 0)
				continue;

			return true;
		}
	}

	wpa_printf(MSG_DEBUG,
		   "No matching EHT MCS found between AP TX and STA RX");
	return false;
}


static bool check_valid_eht_mcs(struct hostapd_data *hapd,
				const u8 *sta_eht_capab,
				enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	const struct ieee80211_eht_capabilities *capab;
	const u8 *ap_mcs, *sta_mcs;
	u8 mcs_count = 1;

	mode = hapd->iface->current_mode;
	if (!mode)
		return true;

	ap_mcs = mode->eht_capab[opmode].mcs;
	capab = (const struct ieee80211_eht_capabilities *) sta_eht_capab;
	sta_mcs = capab->optional;

	if (ieee80211_eht_mcs_set_size(mode->mode, hapd->iconf->op_class,
				       hapd->iconf->he_oper_chwidth,
				       mode->he_capab[opmode].phy_cap,
				       mode->eht_capab[opmode].phy_cap) ==
	    EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY)
		return check_valid_eht_mcs_nss(
			hapd, ap_mcs, sta_mcs, 1,
			EHT_PHYCAP_MCS_NSS_LEN_20MHZ_ONLY);

	switch (hapd->iface->conf->eht_oper_chwidth) {
	case CONF_OPER_CHWIDTH_320MHZ:
		mcs_count++;
		/* fall through */
	case CONF_OPER_CHWIDTH_80P80MHZ:
	case CONF_OPER_CHWIDTH_160MHZ:
		mcs_count++;
		break;
	default:
		break;
	}

	return check_valid_eht_mcs_nss(hapd, ap_mcs, sta_mcs, mcs_count,
				       EHT_PHYCAP_MCS_NSS_LEN_20MHZ_PLUS);
}


static bool ieee80211_invalid_eht_cap_size(enum hostapd_hw_mode mode,
					   u8 opclass, const u8 *he_cap,
					   const u8 *eht_cap, size_t len)
{
	const struct ieee80211_he_capabilities *he_capab;
	struct ieee80211_eht_capabilities *cap;
	const u8 *he_phy_cap;
	size_t cap_len;
	u16 ppe_thres_hdr;

	he_capab = (const struct ieee80211_he_capabilities *) he_cap;
	he_phy_cap = he_capab->he_phy_capab_info;
	cap = (struct ieee80211_eht_capabilities *) eht_cap;
	cap_len = sizeof(*cap) - sizeof(cap->optional);
	if (len < cap_len)
		return true;

	cap_len += ieee80211_eht_mcs_set_size(mode, opclass, -1, he_phy_cap,
					      cap->phy_cap);
	if (len < cap_len)
		return true;

	ppe_thres_hdr = len > cap_len + 1 ?
		WPA_GET_LE16(&eht_cap[cap_len]) : 0x01ff;
	cap_len += ieee80211_eht_ppet_size(ppe_thres_hdr, cap->phy_cap);

	return len < cap_len;
}


u16 copy_sta_eht_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       enum ieee80211_op_mode opmode,
		       const u8 *he_capab, size_t he_capab_len,
		       const u8 *eht_capab, size_t eht_capab_len)
{
	struct hostapd_hw_modes *c_mode = hapd->iface->current_mode;
	enum hostapd_hw_mode mode = c_mode ? c_mode->mode : NUM_HOSTAPD_MODES;

	if (!hapd->iconf->ieee80211be || hapd->conf->disable_11be ||
	    !he_capab || he_capab_len < IEEE80211_HE_CAPAB_MIN_LEN ||
	    !eht_capab ||
	    ieee80211_invalid_eht_cap_size(mode, hapd->iconf->op_class,
					   he_capab, eht_capab,
					   eht_capab_len) ||
	    !check_valid_eht_mcs(hapd, eht_capab, opmode)) {
		sta->flags &= ~WLAN_STA_EHT;
		os_free(sta->eht_capab);
		sta->eht_capab = NULL;
		return WLAN_STATUS_SUCCESS;
	}

	os_free(sta->eht_capab);
	sta->eht_capab = os_memdup(eht_capab, eht_capab_len);
	if (!sta->eht_capab) {
		sta->eht_capab_len = 0;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->flags |= WLAN_STA_EHT;
	sta->eht_capab_len = eht_capab_len;

	return WLAN_STATUS_SUCCESS;
}


void hostapd_get_eht_capab(struct hostapd_data *hapd,
			   const struct ieee80211_eht_capabilities *src,
			   struct ieee80211_eht_capabilities *dest,
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


/* Beacon or a non ML Probe Response frame should include
 * Common Info Length(1) + MLD MAC Address(6) +
 * Link ID Info(1) + BSS Parameters Change count(1) +
 * EML Capabilities (2) + MLD Capabilities (2)
 */
#define EHT_ML_COMMON_INFO_LEN 13
/*
 * control (2) + station info length (1) + MAC address (6) +
 * beacon interval (2) + TSF offset (8) + DTIM info (2)
 */
#define EHT_ML_STA_INFO_LEN 21
u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
				     u8 *eid, struct mld_info *mld_info,
				     bool include_mld_id, bool include_bpcc)
{
	struct wpabuf *buf;
	u16 control;
	u8 *pos = eid;
	const u8 *ptr;
	size_t len, slice_len;
	u8 link_id;
	u8 common_info_len;
	u16 mld_cap;
	u8 max_simul_links, active_links = 0;

	if (hapd->mld && !(hapd->mld->active_links & BIT(hapd->mld_link_id))) {
		wpa_printf(MSG_ERROR, "MLD: Current link %d is not active for %s",
			   hapd->mld_link_id, hapd->mld->name);
		return pos;
	}

	/*
	 * As the Multi-Link element can exceed the size of 255 bytes need to
	 * first build it and then handle fragmentation.
	 */
	buf = wpabuf_alloc(1024);
	if (!buf)
		return pos;

	/* Multi-Link Control field */
	control = MULTI_LINK_CONTROL_TYPE_BASIC |
		BASIC_MULTI_LINK_CTRL_PRES_LINK_ID |
		BASIC_MULTI_LINK_CTRL_PRES_BSS_PARAM_CH_COUNT |
		BASIC_MULTI_LINK_CTRL_PRES_MLD_CAPA;

	if (!hapd->iconf->eml_disable)
		control |= BASIC_MULTI_LINK_CTRL_PRES_EML_CAPA;

	/*
	 * Set the basic Multi-Link common information. Hard code the common
	 * info length to 13 based on the length of the present fields:
	 * Length (1) + MLD address (6) + Link ID (1) +
	 * BSS Parameters Change Count (1) + EML Capabilities (2) +
	 * MLD Capabilities and Operations (2)
	 */
	common_info_len = EHT_ML_COMMON_INFO_LEN;

	if (hapd->iconf->eml_disable)
		common_info_len -= 2; /* EML Capabilities (2) */

	if (include_mld_id && hostapd_get_mld_id(hapd)) {
		/* AP MLD ID */
		control |= BASIC_MULTI_LINK_CTRL_PRES_AP_MLD_ID;
		common_info_len++;
	}

	wpabuf_put_le16(buf, control);

	wpabuf_put_u8(buf, common_info_len);

	/* Own MLD MAC Address */
	wpabuf_put_data(buf, hapd->mld->mld_addr, ETH_ALEN);

	/* Own Link ID */
	wpabuf_put_u8(buf, hapd->mld_link_id);

	/* Currently hard code the BSS Parameters Change Count to 0x1 */
	wpabuf_put_u8(buf, hapd->eht_mld_bss_param_change);

	if (!hapd->iconf->eml_disable) {
		wpa_printf(MSG_DEBUG, "MLD: EML Capabilities=0x%x",
			   hapd->iface->mld_eml_capa);
		wpabuf_put_le16(buf, hapd->iface->mld_eml_capa);
	}

	mld_cap = hapd->iface->mld_mld_capa;
	max_simul_links = mld_cap & EHT_ML_MLD_CAPA_MAX_NUM_SIM_LINKS_MASK;
	active_links = hostapd_get_active_links(hapd);

	if (active_links > max_simul_links) {
		wpa_printf(MSG_ERROR,
			   "MLD: Error in max simultaneous links, advertised: 0x%x current: 0x%x",
			   max_simul_links, active_links);
		active_links = max_simul_links;
	}

	mld_cap &= ~EHT_ML_MLD_CAPA_MAX_NUM_SIM_LINKS_MASK;
	mld_cap |= active_links & EHT_ML_MLD_CAPA_MAX_NUM_SIM_LINKS_MASK;

	/* TODO: Advertise T2LM based on driver support as well */
	mld_cap |= EHT_ML_MLD_CAPA_TID_TO_LINK_MAP_ALL_TO_ALL;

	mld_cap |= EHT_ML_MLD_CAPA_LINK_RECONF_OP_SUPPORT;

	wpa_printf(MSG_DEBUG, "MLD: MLD Capabilities and Operations=0x%x",
		   mld_cap);
	wpabuf_put_le16(buf, mld_cap);

	if (include_mld_id && hostapd_get_mld_id(hapd)) {
		wpa_printf(MSG_DEBUG, "MLD: AP MLD ID=0x%x",
			   hostapd_get_mld_id(hapd));
		wpabuf_put_u8(buf, hostapd_get_mld_id(hapd));
	}

	if (!mld_info)
		goto out;

	/* Add link info for the other links */
	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		struct mld_link_info *link = &mld_info->links[link_id];
		size_t sta_info_len = EHT_ML_STA_INFO_LEN;
		struct hostapd_data *link_bss;
		size_t total_len;

		/* Skip the local one */
		if (link_id == hapd->mld_link_id || !link->valid)
			continue;

		link_bss = hostapd_mld_get_link_bss(hapd, link_id);
		if (!link_bss) {
			wpa_printf(MSG_ERROR,
				   "MLD: Couldn't find link BSS - skip it");
			continue;
		}

		/* BSS Parameters Change Count (1) for (Re)Association Response
		 * frames */
		if (include_bpcc)
			sta_info_len++;

		total_len = sta_info_len + link->resp_sta_profile_len;

		/* Per-STA Profile subelement */
		wpabuf_put_u8(buf, EHT_ML_SUB_ELEM_PER_STA_PROFILE);

		if (total_len <= 255)
			wpabuf_put_u8(buf, total_len);
		else
			wpabuf_put_u8(buf, 255);

		/* STA Control */
		control = (link_id & 0xf) |
			EHT_PER_STA_CTRL_MAC_ADDR_PRESENT_MSK |
			EHT_PER_STA_CTRL_COMPLETE_PROFILE_MSK |
			EHT_PER_STA_CTRL_TSF_OFFSET_PRESENT_MSK |
			EHT_PER_STA_CTRL_BEACON_INTERVAL_PRESENT_MSK |
			EHT_PER_STA_CTRL_DTIM_INFO_PRESENT_MSK;

		if (include_bpcc)
			control |= EHT_PER_STA_CTRL_BSS_PARAM_CNT_PRESENT_MSK;

		wpabuf_put_le16(buf, control);

		/* STA Info */

		/* STA Info Length */
		wpabuf_put_u8(buf, sta_info_len - 2);
		wpabuf_put_data(buf, link->local_addr, ETH_ALEN);
		wpabuf_put_le16(buf, link_bss->iconf->beacon_int);

		/* TSF Offset */
		/*
		 * TODO: Currently setting TSF offset to zero. However, this
		 * information needs to come from the driver.
		 */
		wpabuf_put_le64(buf, link_bss->tsf_offset[hapd->mld_link_id]);

		/* DTIM Info */
		wpabuf_put_u8(buf, 0); /* DTIM Count */
		wpabuf_put_u8(buf, link_bss->conf->dtim_period);

		/* BSS Parameters Change Count */
		if (include_bpcc)
			wpabuf_put_u8(buf, link_bss->eht_mld_bss_param_change);

		if (!link->resp_sta_profile)
			continue;

#define EXT_EID_TAG_LEN 3
		link->sta_prof_offset = wpabuf_len(buf) + EXT_EID_TAG_LEN;

		/* Fragment the sub element if needed */
		if (total_len <= 255) {
			wpabuf_put_data(buf, link->resp_sta_profile,
					link->resp_sta_profile_len);
		} else {
			ptr = link->resp_sta_profile;
			len = link->resp_sta_profile_len;

			slice_len = 255 - sta_info_len;

			wpabuf_put_data(buf, ptr, slice_len);
			len -= slice_len;
			ptr += slice_len;

			while (len) {
				if (len <= 255)
					slice_len = len;
				else
					slice_len = 255;

				wpabuf_put_u8(buf, EHT_ML_SUB_ELEM_FRAGMENT);
				wpabuf_put_u8(buf, slice_len);
				wpabuf_put_data(buf, ptr, slice_len);

				len -= slice_len;
				ptr += slice_len;
			}
		}
	}

out:
	/* Fragment the Multi-Link element, if needed */
	len = wpabuf_len(buf);
	ptr = wpabuf_head(buf);

	if (len <= 254)
		slice_len = len;
	else
		slice_len = 254;

	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = slice_len + 1;
	*pos++ = WLAN_EID_EXT_MULTI_LINK;
	os_memcpy(pos, ptr, slice_len);

	ptr += slice_len;
	pos += slice_len;
	len -= slice_len;

	while (len) {
		if (len <= 255)
			slice_len = len;
		else
			slice_len = 255;

		*pos++ = WLAN_EID_FRAGMENT;
		*pos++ = slice_len;
		os_memcpy(pos, ptr, slice_len);

		ptr += slice_len;
		pos += slice_len;
		len -= slice_len;
	}

	wpabuf_free(buf);
	return pos;
}


size_t hostapd_eid_eht_basic_ml_len(struct hostapd_data *hapd,
				    struct sta_info *info,
				    bool include_mld_id, bool include_bpcc)
{
	int link_id;
	size_t len, num_frags;

	if (!hapd->conf->mld_ap)
		return 0;

	/* Include WLAN_EID_EXT_MULTI_LINK (1) */
	len = 1;
	/* control field */
	len += 2;
	/* Common info len for Basic MLE */
	len += EHT_ML_COMMON_INFO_LEN;
	if (include_mld_id)
		len++;

	if (!info)
		goto out;

	/* Add link info for the other links */
	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		struct mld_link_info *link = &info->mld_info.links[link_id];
		struct hostapd_data *link_bss;
		size_t sta_prof_len = EHT_ML_STA_INFO_LEN +
			link->resp_sta_profile_len;

		/* Skip the local one */
		if (link_id == hapd->mld_link_id || !link->valid)
			continue;

		link_bss = hostapd_mld_get_link_bss(hapd, link_id);
		if (!link_bss) {
			wpa_printf(MSG_ERROR,
				   "MLD: Couldn't find link BSS - skip it");
			continue;
		}

		/* BSS Parameters Change Count (1) for (Re)Association Response
		 * frames */
		if (include_bpcc)
			sta_prof_len++;

		/* Per-STA Profile Subelement(1), Length (1) */
		len += 2;
		len += sta_prof_len;
		/* Consider Fragment EID(1) and Length (1) for each subelement
		 * fragment. */
		if (sta_prof_len > 255) {
			num_frags = (sta_prof_len / 255 - 1) +
				!!(sta_prof_len % 255);
			len += num_frags * 2;
		}

	}

out:
	if (len > 255) {
		num_frags = (len / 255 - 1) + !!(len % 255);
		len += num_frags * 2;
	}

	/* WLAN_EID_EXTENSION (1) + length (1) */
	return len + 2;
}


static u8 * hostapd_eid_eht_reconf_ml(struct hostapd_data *hapd, u8 *eid)
{
#ifdef CONFIG_TESTING_OPTIONS
	struct hostapd_data *other_hapd;
	u16 control;
	u8 *pos = eid;
	unsigned int i;

	wpa_printf(MSG_DEBUG, "MLD: Reconfiguration ML");

	/* First check if the element needs to be added */
	for (i = 0; i < hapd->iface->interfaces->count; i++) {
		other_hapd = hapd->iface->interfaces->iface[i]->bss[0];

		wpa_printf(MSG_DEBUG, "MLD: Reconfiguration ML: %u",
			   other_hapd->eht_mld_link_removal_count);

		if (other_hapd->eht_mld_link_removal_count)
			break;
	}

	/* No link is going to be removed */
	if (i == hapd->iface->interfaces->count)
		return eid;

	wpa_printf(MSG_DEBUG, "MLD: Reconfiguration ML: Adding element");

	/* The length will be set at the end */
	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 0;
	*pos++ = WLAN_EID_EXT_MULTI_LINK;

	/* Set the Multi-Link Control field */
	control = MULTI_LINK_CONTROL_TYPE_RECONF;
	WPA_PUT_LE16(pos, control);
	pos += 2;

	/* Common Info doesn't include any information */
	*pos++ = 1;

	/* Add the per station profiles */
	for (i = 0; i < hapd->iface->interfaces->count; i++) {
		other_hapd = hapd->iface->interfaces->iface[i]->bss[0];
		if (!other_hapd->eht_mld_link_removal_count)
			continue;

		/* Subelement ID is 0 */
		*pos++ = 0;
		*pos++ = 5;

		control = other_hapd->mld_link_id |
			EHT_PER_STA_RECONF_CTRL_AP_REMOVAL_TIMER;

		WPA_PUT_LE16(pos, control);
		pos += 2;

		/* STA profile length */
		*pos++ = 3;

		WPA_PUT_LE16(pos, other_hapd->eht_mld_link_removal_count);
		pos += 2;
	}

	eid[1] = pos - eid - 2;

	wpa_hexdump(MSG_DEBUG, "MLD: Reconfiguration ML", eid, eid[1] + 2);
	return pos;
#else /* CONFIG_TESTING_OPTIONS */
	return eid;
#endif /* CONFIG_TESTING_OPTIONS */
}


size_t hostapd_eid_eht_attlm_len(struct hostapd_data * hapd)
{
	size_t len;

	if (!hostapd_is_attlm_active(hapd))
		return 0;

	/* Element ID: 1 octet
	 * Length: 1 octet
	 * Extended Element ID: 1 octet
	 * Control: 2 octets (Link Mapping Presence Bitmap set for all TIDs)
	 * Mapping Switch Time: 0 or 2 octets
	 * Expected Duration: 3 octets (must included in Adv-TTLM)
	 * Link Mapping (size of 2) for All 8 TIDs: 2 * 8 octets
	 */
	len = 3 + 2 + 3 + 2 * 8;
	if (hapd->mld->new_attlm.switch_time_tsf_tu != 0)
		len += 2;

	return len;
}


u8 * hostapd_eid_eht_attlm(struct hostapd_data *hapd, u8 *eid)
{
	struct attlm_settings *attlm;
	struct os_reltime now, res;
	int i;
	u16 control = 0;
	u8 *pos = eid;
	u16 enabled_links;

	if (!hostapd_is_attlm_active(hapd))
		return eid;

	attlm = &hapd->mld->new_attlm;

	/* The length will be set at the end */
	*pos++ = WLAN_EID_EXTENSION;
	*pos++ = 0;
	*pos++ = WLAN_EID_EXT_TID_TO_LINK_MAPPING;

	/* Set the A-TTLM Control field */
	control = (IEEE80211_TTLM_CONTROL_DIRECTION & attlm->direction) |
		  IEEE80211_TTLM_CONTROL_EXPECTED_DUR_PRESENT |
		  IEEE80211_TTLM_CONTROL_INDICATOR;

	if (attlm->switch_time_tsf_tu != 0)
		control |= IEEE80211_TTLM_CONTROL_SWITCH_TIME_PRESENT;

	WPA_PUT_LE16(pos, control);
	pos += 2;

	/* switch time & expected duration */
	if (attlm->switch_time_tsf_tu != 0) {
		WPA_PUT_LE16(pos, attlm->switch_time_tsf_tu);
		pos += 2;

		WPA_PUT_LE24(pos, (attlm->duration * 1000) >> 10);
		pos += 3;
	} else {
		u32 diff;

		os_get_reltime(&now);
		os_reltime_sub(&now, &attlm->start_time, &res);
		diff = (u32)os_reltime_in_ms(&res);

		if (attlm->duration <= diff)
			return eid;

		WPA_PUT_LE24(pos, ((attlm->duration - diff) * 1000) >> 10);
		pos += 3;
	}

	/* Link Mapping of each TID (0 - 7) */
	enabled_links = hapd->conf->mld_allowed_links & ~attlm->disabled_links;
	for (i = 0; i < 8; i++) {
		WPA_PUT_LE16(pos, enabled_links);
		pos += 2;
	}

	eid[1] = pos - eid - 2;

	return pos;
}


static size_t hostapd_eid_eht_ml_len(struct mld_info *info,
				     bool include_mld_id, bool include_bpcc,
				     u8 eml_disable)
{
	size_t len = 0;
	size_t eht_ml_len = 2 + EHT_ML_COMMON_INFO_LEN;
	u8 link_id;

	if (eml_disable)
		eht_ml_len -= 2; /* EML Capabilities (2) */

	if (include_mld_id)
		eht_ml_len++;

	for (link_id = 0; info && link_id < ARRAY_SIZE(info->links);
	     link_id++) {
		struct mld_link_info *link;
		size_t sta_len = EHT_ML_STA_INFO_LEN;

		link = &info->links[link_id];
		if (!link->valid)
			continue;

		sta_len += link->resp_sta_profile_len;

		/* BSS Parameters Change Count (1) for (Re)Association Response
		 * frames */
		if (include_bpcc)
			sta_len++;

		/* Element data and (fragmentation) headers */
		eht_ml_len += sta_len;
		eht_ml_len += 2 + sta_len / 255 * 2;
	}

	/* Element data */
	len += eht_ml_len;

	/* First header (254 bytes of data) */
	len += 3;

	/* Fragmentation headers; +1 for shorter first chunk */
	len += (eht_ml_len + 1) / 255 * 2;

	return len;
}
#undef EHT_ML_COMMON_INFO_LEN
#undef EHT_ML_STA_INFO_LEN


u8 * hostapd_eid_eht_ml_beacon(struct hostapd_data *hapd,
			       struct mld_info *info,
			       u8 *eid, bool include_mld_id)
{
	eid = hostapd_eid_eht_basic_ml_common(hapd, eid, info, include_mld_id,
					      false);
	return hostapd_eid_eht_reconf_ml(hapd, eid);
}



u8 * hostapd_eid_eht_ml_assoc(struct hostapd_data *hapd, struct sta_info *info,
			      u8 *eid)
{
	if (!ap_sta_is_mld(hapd, info))
		return eid;

	eid = hostapd_eid_eht_basic_ml_common(hapd, eid, &info->mld_info,
					      false, true);
	ap_sta_free_sta_profile(&info->mld_info);
	return hostapd_eid_eht_reconf_ml(hapd, eid);
}


size_t hostapd_eid_eht_ml_beacon_len(struct hostapd_data *hapd,
				     struct mld_info *info,
				     bool include_mld_id)
{
	return hostapd_eid_eht_ml_len(info,
				      include_mld_id && hostapd_get_mld_id(hapd),
				      false,
				      hapd->iconf->eml_disable);
}


struct wpabuf * hostapd_ml_auth_resp(struct hostapd_data *hapd)
{
	struct wpabuf *buf = wpabuf_alloc(12);

	if (!buf)
		return NULL;

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	wpabuf_put_u8(buf, 10);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);
	wpabuf_put_le16(buf, MULTI_LINK_CONTROL_TYPE_BASIC);
	wpabuf_put_u8(buf, ETH_ALEN + 1);
	wpabuf_put_data(buf, hapd->mld->mld_addr, ETH_ALEN);

	return buf;
}


#ifdef CONFIG_SAE

static const u8 *
sae_commit_skip_fixed_fields(const struct ieee80211_mgmt *mgmt, size_t len,
			     const u8 *pos, u16 status_code)
{
	u16 group;
	size_t prime_len;
	struct crypto_ec *ec;

	if (status_code != WLAN_STATUS_SAE_HASH_TO_ELEMENT)
		return pos;

	/* SAE H2E commit message (group, scalar, FFE) */
	if (len < 2) {
		wpa_printf(MSG_DEBUG,
			   "EHT: SAE Group is not present");
		return NULL;
	}

	group = WPA_GET_LE16(pos);
	pos += 2;

	/* TODO: How to parse when the group is unknown? */
	ec = crypto_ec_init(group);
	if (!ec) {
		const struct dh_group *dh = dh_groups_get(group);

		if (!dh) {
			wpa_printf(MSG_DEBUG, "EHT: Unknown SAE group %u",
				   group);
			return NULL;
		}

		prime_len = dh->prime_len;
	} else {
		prime_len = crypto_ec_prime_len(ec);
	}

	wpa_printf(MSG_DEBUG, "EHT: SAE scalar length is %zu", prime_len);

	if (len - 2 < prime_len * (ec ? 3 : 2))
		goto truncated;
	/* scalar */
	pos += prime_len;

	if (ec) {
		pos += prime_len * 2;
		crypto_ec_deinit(ec);
	} else {
		pos += prime_len;
	}

	if (pos - mgmt->u.auth.variable > (int) len) {
	truncated:
		wpa_printf(MSG_DEBUG,
			   "EHT: Too short SAE commit Authentication frame");
		return NULL;
	}

	wpa_hexdump(MSG_DEBUG, "EHT: SAE: Authentication frame elements",
		    pos, (int) len - (pos - mgmt->u.auth.variable));

	return pos;
}


static const u8 *
sae_confirm_skip_fixed_fields(struct hostapd_data *hapd,
			      const struct ieee80211_mgmt *mgmt, size_t len,
			      const u8 *pos, u16 status_code)
{
	struct sta_info *sta;

	if (status_code == WLAN_STATUS_REJECTED_WITH_SUGGESTED_BSS_TRANSITION)
		return pos;

	/* send confirm integer */
	if (len < 2)
		goto truncated;
	pos += 2;

	/*
	 * At this stage we should already have an MLD station and actually SA
	 * will be replaced with the MLD MAC address by the driver. However,
	 * there is at least a theoretical race condition in a case where the
	 * peer sends the SAE confirm message quickly enough for the driver
	 * translation mechanism to not be available to update the SAE confirm
	 * message addresses. Work around that by searching for the STA entry
	 * using the link address of the non-AP MLD if no match is found based
	 * on the MLD MAC address.
	 */
	sta = ap_get_sta(hapd, mgmt->sa);
	if (!sta) {
		wpa_printf(MSG_DEBUG, "SAE: No MLD STA for SAE confirm");
		for (sta = hapd->sta_list; sta; sta = sta->next) {
			int link_id = hapd->mld_link_id;

			if (!sta->mld_info.mld_sta ||
			    sta->mld_info.links[link_id].valid ||
			    !ether_addr_equal(
				    mgmt->sa,
				    sta->mld_info.links[link_id].peer_addr))
				continue;
			wpa_printf(MSG_DEBUG,
				   "SAE: Found MLD STA for SAE confirm based on link address");
			break;
		}
		if (!sta)
			return NULL;
	}

	if (!sta->sae || sta->sae->state < SAE_COMMITTED || !sta->sae->tmp) {
		if (sta->sae)
			wpa_printf(MSG_DEBUG, "SAE: Invalid state=%u",
				   sta->sae->state);
		else
			wpa_printf(MSG_DEBUG, "SAE: No SAE context");
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "SAE: confirm: kck_len=%zu",
		   sta->sae->tmp->kck_len);

	if (len - 2 < sta->sae->tmp->kck_len)
		goto truncated;
	pos += sta->sae->tmp->kck_len;

	if (pos - mgmt->u.auth.variable > (int) len) {
	truncated:
		wpa_printf(MSG_DEBUG,
			   "EHT: Too short SAE confirm Authentication frame");
		return NULL;
	}

	return pos;
}

#endif /* CONFIG_SAE */


static const u8 * auth_skip_fixed_fields(struct hostapd_data *hapd,
					 const struct ieee80211_mgmt *mgmt,
					 size_t len)
{
	u16 auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
#ifdef CONFIG_SAE
	u16 auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	u16 status_code = le_to_host16(mgmt->u.auth.status_code);
#endif /* CONFIG_SAE */
	const u8 *pos = mgmt->u.auth.variable;

	/* Skip fixed fields as based on IEEE Std 802.11-2024, Table 9-71
	 * (Presence of fields and elements in Authentications frames) */
	switch (auth_alg) {
	case WLAN_AUTH_OPEN:
		return pos;
#ifdef CONFIG_SAE
	case WLAN_AUTH_SAE:
		if (auth_transaction == 1) {
			if (status_code == WLAN_STATUS_SUCCESS) {
				wpa_printf(MSG_DEBUG,
					   "EHT: SAE H2E is mandatory for MLD");
				goto out;
			}

			return sae_commit_skip_fixed_fields(mgmt, len, pos,
							    status_code);
		} else if (auth_transaction == 2) {
			return sae_confirm_skip_fixed_fields(hapd, mgmt, len,
							     pos, status_code);
		}

		return pos;
#endif /* CONFIG_SAE */
	/* TODO: Support additional algorithms that can be used for MLO */
	case WLAN_AUTH_FT:
	case WLAN_AUTH_FILS_SK:
	case WLAN_AUTH_FILS_SK_PFS:
	case WLAN_AUTH_FILS_PK:
	case WLAN_AUTH_PASN:
	default:
		break;
	}

#ifdef CONFIG_SAE
out:
#endif /* CONFIG_SAE */
	wpa_printf(MSG_DEBUG,
		   "TODO: Authentication algorithm %u not supported with MLD",
		   auth_alg);
	return NULL;
}


const u8 * hostapd_process_ml_auth(struct hostapd_data *hapd,
				   const struct ieee80211_mgmt *mgmt,
				   size_t len)
{
	struct ieee802_11_elems elems;
	const u8 *pos;

	if (!hapd->conf->mld_ap)
		return NULL;

	len -= offsetof(struct ieee80211_mgmt, u.auth.variable);

	pos = auth_skip_fixed_fields(hapd, mgmt, len);
	if (!pos)
		return NULL;

	if (ieee802_11_parse_elems(pos,
				   (int)len - (pos - mgmt->u.auth.variable),
				   &elems, 0) == ParseFailed) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Failed parsing Authentication frame");
	}

	if (!elems.basic_mle || !elems.basic_mle_len)
		return NULL;

	return get_basic_mle_mld_addr(elems.basic_mle, elems.basic_mle_len);
}


static int hostapd_mld_validate_assoc_info(struct hostapd_data *hapd,
					   struct sta_info *sta)
{
	u8 link_id;
	struct mld_info *info = &sta->mld_info;

	if (!ap_sta_is_mld(hapd, sta)) {
		wpa_printf(MSG_DEBUG, "MLD: Not a non-AP MLD");
		return 0;
	}

	/*
	 * Iterate over the links negotiated in the (Re)Association Request
	 * frame and validate that they are indeed valid links in the local AP
	 * MLD.
	 *
	 * While at it, also update the local address for the links in the
	 * mld_info, so it could be easily available for later flows, e.g., for
	 * the RSN Authenticator, etc.
	 */
	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		struct hostapd_data *other_hapd;

		if (!info->links[link_id].valid || link_id == hapd->mld_link_id)
			continue;

		other_hapd = hostapd_mld_get_link_bss(hapd, link_id);
		if (!other_hapd) {
			wpa_printf(MSG_DEBUG, "MLD: Invalid link ID=%u",
				   link_id);
			return -1;
		}

		os_memcpy(info->links[link_id].local_addr, other_hapd->own_addr,
			  ETH_ALEN);
	}

	return 0;
}


int hostapd_process_ml_assoc_req_addr(struct hostapd_data *hapd,
				      const u8 *basic_mle, size_t basic_mle_len,
				      u8 *mld_addr)
{
	struct wpabuf *mlbuf = ieee802_11_defrag(basic_mle, basic_mle_len,
						 true);
	struct ieee80211_eht_ml *ml;
	struct eht_ml_basic_common_info *common_info;
	size_t ml_len, common_info_len;
	int ret = -1;
	u16 ml_control;

	if (!mlbuf)
		return WLAN_STATUS_SUCCESS;

	ml = (struct ieee80211_eht_ml *) wpabuf_head(mlbuf);
	ml_len = wpabuf_len(mlbuf);

	if (ml_len < sizeof(*ml))
		goto out;

	ml_control = le_to_host16(ml->ml_control);
	if ((ml_control & MULTI_LINK_CONTROL_TYPE_MASK) !=
	    MULTI_LINK_CONTROL_TYPE_BASIC) {
		wpa_printf(MSG_DEBUG, "MLD: Invalid ML type=%u",
			   ml_control & MULTI_LINK_CONTROL_TYPE_MASK);
		goto out;
	}

	/* Common Info Length and MLD MAC Address must always be present */
	common_info_len = 1 + ETH_ALEN;
	/* Ignore optional fields */

	if (sizeof(*ml) + common_info_len > ml_len) {
		wpa_printf(MSG_DEBUG, "MLD: Not enough bytes for common info");
		goto out;
	}

	common_info = (struct eht_ml_basic_common_info *) ml->variable;

	/* Common information length includes the length octet */
	if (common_info->len < common_info_len) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Invalid common info len=%u", common_info->len);
		goto out;
	}

	/* Get the MLD MAC Address */
	os_memcpy(mld_addr, common_info->mld_addr, ETH_ALEN);
	ret = 0;

out:
	wpabuf_free(mlbuf);
	return ret;
}


u16 hostapd_process_ml_assoc_req(struct hostapd_data *hapd,
				 struct ieee802_11_elems *elems,
				 struct sta_info *sta)
{
	struct wpabuf *mlbuf;
	const struct ieee80211_eht_ml *ml;
	const struct eht_ml_basic_common_info *common_info;
	size_t ml_len, common_info_len;
	struct mld_link_info *link_info;
	struct mld_info *info = &sta->mld_info;
	const u8 *pos, *end;
	int ret = -1;
	u16 ml_control;
	const u8 *ml_end;

	mlbuf = ieee802_11_defrag(elems->basic_mle, elems->basic_mle_len, true);
	if (!mlbuf)
		return WLAN_STATUS_SUCCESS;

	ml = wpabuf_head(mlbuf);
	ml_len = wpabuf_len(mlbuf);
	ml_end = ((const u8 *) ml) + ml_len;

	ml_control = le_to_host16(ml->ml_control);
	if ((ml_control & MULTI_LINK_CONTROL_TYPE_MASK) !=
	    MULTI_LINK_CONTROL_TYPE_BASIC) {
		wpa_printf(MSG_DEBUG, "MLD: Invalid ML type=%u",
			   ml_control & MULTI_LINK_CONTROL_TYPE_MASK);
		goto out;
	}

	/* Common Info length and MLD MAC address must always be present */
	common_info_len = 1 + ETH_ALEN;

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_LINK_ID) {
		wpa_printf(MSG_DEBUG, "MLD: Link ID info not expected");
		goto out;
	}

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_BSS_PARAM_CH_COUNT) {
		wpa_printf(MSG_DEBUG, "MLD: BSS params change not expected");
		goto out;
	}

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_MSD_INFO) {
		wpa_printf(MSG_DEBUG, "MLD: Sync delay not expected");
		goto out;
	}

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_EML_CAPA) {
		common_info_len += 2;
	} else {
		wpa_printf(MSG_DEBUG, "MLD: EML capabilities not present");
	}

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_MLD_CAPA) {
		common_info_len += 2;

	} else {
		wpa_printf(MSG_DEBUG, "MLD: MLD capabilities not present");
		goto out;
	}

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_EXT_MLD_CAP) {
		common_info_len += 2;
	} else {
		wpa_printf(MSG_DEBUG, "MLD: EXT ML capabilities not present");
	}

	wpa_printf(MSG_DEBUG, "MLD: expected_common_info_len=%lu",
		   common_info_len);

	if (sizeof(*ml) + common_info_len > ml_len) {
		wpa_printf(MSG_DEBUG, "MLD: Not enough bytes for common info");
		goto out;
	}

	common_info = (const struct eht_ml_basic_common_info *) ml->variable;

	/* Common information length includes the length octet */
	if (common_info->len < common_info_len) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Invalid common info len=%u (expected %zu)",
			   common_info->len, common_info_len);
		goto out;
	}

	pos = common_info->variable;
	end = ((const u8 *) common_info) + common_info->len;

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_EML_CAPA) {
		info->common_info.eml_capa = WPA_GET_LE16(pos);
		pos += 2;
	} else {
		info->common_info.eml_capa = 0;
	}

	info->common_info.mld_capa = WPA_GET_LE16(pos);
	pos += 2;

	if (ml_control & BASIC_MULTI_LINK_CTRL_PRES_EXT_MLD_CAP) {
		pos += 2;
	}

	wpa_printf(MSG_DEBUG, "MLD: addr=" MACSTR ", eml=0x%x, mld=0x%x",
		   MAC2STR(info->common_info.mld_addr),
		   info->common_info.eml_capa, info->common_info.mld_capa);

	/* Check the MLD MAC Address */
	if (!ether_addr_equal(info->common_info.mld_addr,
			      common_info->mld_addr)) {
		wpa_printf(MSG_DEBUG,
			   "MLD: MLD address mismatch between authentication ("
			   MACSTR ") and association (" MACSTR ")",
			   MAC2STR(info->common_info.mld_addr),
			   MAC2STR(common_info->mld_addr));
		goto out;
	}

	info->links[hapd->mld_link_id].valid = 1;

	/* Parse the Link Info field that starts after the end of the variable
	 * length Common Info field. */
	pos = end;
	while (ml_end - pos > 2) {
		size_t sub_elem_len, sta_info_len;
		u16 control;
		const u8 *sub_elem_end;
		int num_frag_subelems;

		num_frag_subelems =
			ieee802_11_defrag_mle_subelem(mlbuf, pos,
						      &sub_elem_len);
		if (num_frag_subelems < 0) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Failed to parse MLE subelem");
			goto out;
		}

		ml_len -= num_frag_subelems * 2;
		ml_end = ((const u8 *) ml) + ml_len;

		wpa_printf(MSG_DEBUG,
			   "MLD: sub element len=%zu, Fragment subelems=%u",
			   sub_elem_len, num_frag_subelems);

		if (2 + sub_elem_len > (size_t) (ml_end - pos)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Invalid link info len: %zu %zu",
				   2 + sub_elem_len, ml_end - pos);
			goto out;
		}

		if (*pos == MULTI_LINK_SUB_ELEM_ID_VENDOR) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Skip vendor specific subelement");

			pos += 2 + sub_elem_len;
			continue;
		}

		if (*pos != MULTI_LINK_SUB_ELEM_ID_PER_STA_PROFILE) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Skip unknown Multi-Link element subelement ID=%u",
				   *pos);
			pos += 2 + sub_elem_len;
			continue;
		}

		/* Skip the subelement ID and the length */
		pos += 2;
		sub_elem_end = pos + sub_elem_len;

		/* Get the station control field */
		if (sub_elem_end - pos < 2) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Too short Per-STA Profile subelement");
			goto out;
		}
		control = WPA_GET_LE16(pos);
		link_info = &info->links[control &
					 EHT_PER_STA_CTRL_LINK_ID_MSK];
		pos += 2;

		if (!(control & EHT_PER_STA_CTRL_COMPLETE_PROFILE_MSK)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Per-STA complete profile expected");
			goto out;
		}

		if (!(control & EHT_PER_STA_CTRL_MAC_ADDR_PRESENT_MSK)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Per-STA MAC address not present");
			goto out;
		}

		if ((control & (EHT_PER_STA_CTRL_BEACON_INTERVAL_PRESENT_MSK |
				EHT_PER_STA_CTRL_DTIM_INFO_PRESENT_MSK))) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Beacon/DTIM interval not expected");
			goto out;
		}

		/* The length octet and the MAC address must be present */
		sta_info_len = 1 + ETH_ALEN;

		if (control & EHT_PER_STA_CTRL_NSTR_LINK_PAIR_PRESENT_MSK) {
			if (control & EHT_PER_STA_CTRL_NSTR_BM_SIZE_MSK)
				link_info->nstr_bitmap_len = 2;
			else
				link_info->nstr_bitmap_len = 1;
		}

		sta_info_len += link_info->nstr_bitmap_len;

		if (sta_info_len > (size_t) (sub_elem_end - pos) ||
		    sta_info_len > *pos ||
		    *pos > sub_elem_end - pos ||
		    sta_info_len > (size_t) (sub_elem_end - pos)) {
			wpa_printf(MSG_DEBUG, "MLD: Invalid STA Info length");
			goto out;
		}

		sta_info_len = *pos;
		end = pos + sta_info_len;

		/* skip the length */
		pos++;

		/* get the link address */
		os_memcpy(link_info->peer_addr, pos, ETH_ALEN);
		wpa_printf(MSG_DEBUG,
			   "MLD: assoc: link id=%u, addr=" MACSTR,
			   control & EHT_PER_STA_CTRL_LINK_ID_MSK,
			   MAC2STR(link_info->peer_addr));

		pos += ETH_ALEN;

		/* Get the NSTR bitmap */
		if (link_info->nstr_bitmap_len) {
			os_memcpy(link_info->nstr_bitmap, pos,
				  link_info->nstr_bitmap_len);
			pos += link_info->nstr_bitmap_len;
		}

		pos = end;

		if (sub_elem_end - pos >= 2)
			link_info->capability = WPA_GET_LE16(pos);

		pos = sub_elem_end;

		wpa_printf(MSG_DEBUG, "MLD: link ctrl=0x%x, " MACSTR
			   ", nstr bitmap len=%u",
			   control, MAC2STR(link_info->peer_addr),
			   link_info->nstr_bitmap_len);

		link_info->valid = true;
	}

	ret = hostapd_mld_validate_assoc_info(hapd, sta);
out:
	wpabuf_free(mlbuf);
	if (ret) {
		os_memset(info, 0, sizeof(*info));
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	return WLAN_STATUS_SUCCESS;
}


void ml_deinit_link_reconf_req(struct link_reconf_req_list **req_list_ptr)
{
	struct link_reconf_req_list *req_list;
	struct link_reconf_req_info *info, *tmp;

	if (!(*req_list_ptr))
		return;

	wpa_printf(MSG_DEBUG, "MLD: Deinit Link Reconf Request context");

	req_list = *req_list_ptr;

	dl_list_for_each_safe(info, tmp, &req_list->add_req,
			      struct link_reconf_req_info, list) {
		dl_list_del(&info->list);
		os_free(info);
	}

	dl_list_for_each_safe(info, tmp, &req_list->del_req,
			      struct link_reconf_req_info, list) {
		dl_list_del(&info->list);
		os_free(info);
	}

	os_free(req_list);
	*req_list_ptr = NULL;
}


void hostapd_link_reconf_resp_tx_status(struct hostapd_data *hapd,
					struct sta_info *sta,
					const struct ieee80211_mgmt *mgmt,
					size_t len, int ok)
{
	u8 dialog_token = mgmt->u.action.u.link_reconf_resp.dialog_token;
	struct hostapd_data *assoc_hapd, *lhapd, *other_hapd;
	struct sta_info *assoc_sta, *lsta, *other_sta;
	struct link_reconf_req_list *req_list;
	struct link_reconf_req_info *info;
	uint8_t link_id;

	wpa_printf(MSG_DEBUG,
		   "MLD: Link Reconf Response TX status - dialog token=%u ok=%d",
		   dialog_token, ok);

	assoc_sta = hostapd_ml_get_assoc_sta(hapd, sta, &assoc_hapd);
	if (!assoc_sta) {
		wpa_printf(MSG_INFO, "MLD: Assoc STA not found for " MACSTR,
			   MAC2STR(mgmt->da));
		return;
	}

	if (!assoc_sta->reconf_req) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Unexpected Link Reconf Request TX status");
		return;
	}

	req_list = assoc_sta->reconf_req;

	if (!ether_addr_equal(mgmt->da, req_list->sta_mld_addr)) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Link Reconfiguration Response TX status from wrong STA");
		return;
	}

	if (dialog_token != req_list->dialog_token) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Link Reconfiguration session expired for %u",
			   dialog_token);
		return;
	}

	if (!ok) {
		wpa_printf(MSG_INFO,
			   "MLD: Link Reconf Response ack failed for " MACSTR
			   "; revert link additions",
			   MAC2STR(mgmt->da));

		dl_list_for_each(info, &req_list->del_req,
				 struct link_reconf_req_info, list) {
			if (info->status != WLAN_STATUS_SUCCESS)
				continue;

			lhapd = NULL;
			lsta = NULL;
			lhapd = hostapd_mld_get_link_bss(hapd, info->link_id);
			if (lhapd)
				lsta = ap_get_sta(lhapd,
						  req_list->sta_mld_addr);

			if (lsta)
				ap_free_sta(lhapd, lsta);
		}
		goto exit;
	}

	if (dl_list_empty(&req_list->del_req))
		goto exit;

	dl_list_for_each(info, &req_list->del_req, struct link_reconf_req_info,
			 list) {
		if (info->status != WLAN_STATUS_SUCCESS)
			continue;

		link_id = info->link_id;
		lhapd = hostapd_mld_get_link_bss(hapd, link_id);
		if (!lhapd) {
			wpa_printf(MSG_INFO,
				   "MLD: Link (%u) hapd cannot be NULL",
				   link_id);
			continue;
		}

		lsta = ap_get_sta(lhapd, mgmt->da);
		if (!lsta) {
			wpa_printf(MSG_INFO,
				   "MLD: Link (%u) STA cannot be NULL",
				   link_id);
			continue;
		}

		/* Reassign assoc_sta to the link with lowest link ID */
		if (!hostapd_sta_is_link_sta(lhapd, lsta) &&
		    lsta == assoc_sta) {
			struct mld_info *mld_info = &assoc_sta->mld_info;
			int i;

			for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
				if (i == assoc_sta->mld_assoc_link_id ||
				    !mld_info->links[i].valid ||
				    req_list->links_del_ok & BIT(i)) {
					continue;
				}
				break;
			}

			if (i == MAX_NUM_MLD_LINKS) {
				wpa_printf(MSG_INFO,
					   "MLD: No new assoc STA could be found; disconnect STA");
				hostapd_notif_disassoc_mld(assoc_hapd, sta,
							   sta->addr);
				goto exit;
			}
			wpa_printf(MSG_DEBUG, "MLD: New assoc link=%d", i);

			/* Reset wpa_auth and assoc link ID */
			for_each_mld_link(other_hapd, lhapd) {
				other_sta = ap_get_sta(other_hapd, mgmt->da);
				if (other_sta)
					other_sta->mld_assoc_link_id = i;
			}

			/* Reset reconfig request queue which will be freed
			 * at the end */
			assoc_sta->reconf_req = NULL;

			/* assoc_sta switched */
			assoc_sta = hostapd_ml_get_assoc_sta(lhapd, lsta,
							     &assoc_hapd);

			/* assoc_sta cannot be NULL since both AP and STA are
			 * MLD and new valid assoc_sta is already found */
			if (!assoc_sta)
				goto exit;

			if (assoc_hapd == lhapd) {
				wpa_printf(MSG_ERROR,
					   "MLD: assoc_hapd is not updated; please check");
				goto exit;
			}

			assoc_sta->reconf_req = req_list;
			wpa_reset_assoc_sm_info(assoc_sta->wpa_sm,
						assoc_hapd->wpa_auth, i);
		}

		/* Free as a link STA */
		ap_free_sta(lhapd, lsta);
		wpa_msg(hapd->msg_ctx, MSG_INFO,
			WPA_EVENT_LINK_STA_REMOVED "sta=" MACSTR " link_id=%u",
			MAC2STR(lsta->addr), link_id);

		for_each_mld_link(other_hapd, lhapd) {
			struct mld_link_info *link;

			other_sta = ap_get_sta(other_hapd, mgmt->da);
			if (!other_sta)
				continue;

			link = &other_sta->mld_info.links[link_id];
			os_free(link->resp_sta_profile);
			link->resp_sta_profile = NULL;
			link->resp_sta_profile_len = 0;
			link->valid = false;
		}
		wpa_auth_set_ml_info(assoc_sta->wpa_sm,
				     assoc_sta->mld_assoc_link_id,
				     &assoc_sta->mld_info);
	}

exit:
	ml_deinit_link_reconf_req(&req_list);
	if (assoc_sta && assoc_sta->reconf_req)
		assoc_sta->reconf_req = NULL;
}


static bool recover_from_zero_links(u16 *links_del_ok, u8 *recovery_link)
{
	u8 pos = 0;
	u16 del_links;

	del_links = *links_del_ok;

	while (del_links) {
		if (del_links & 1)
			break;
		del_links >>= 1;
		pos++;
	}

	/* No link found */
	if (!del_links) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Total valid links is 0 and no del-link found to reject for recovery");
		return false;
	}

	*recovery_link = pos;
	*links_del_ok &= ~BIT(*recovery_link);
	wpa_printf(MSG_INFO,
		   "MLD: Del-link request for link (%u) rejected to recover from no remaining links",
		   *recovery_link);
	return true;
}


static u16
hostapd_ml_process_reconf_link(struct hostapd_data *hapd,
			       struct sta_info *assoc_sta, const u8 *ies,
			       size_t ies_len, u8 link_id, const u8 *link_addr)
{
	struct hostapd_data *lhapd, *other_hapd;
	struct mld_link_info link;
	struct sta_info *lsta, *other_sta;

	lhapd = hostapd_mld_get_link_bss(hapd, link_id);
	if (!lhapd) /* This cannot be NULL */
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	os_memset(&link, 0, sizeof(link));

	link.valid = 1;
	os_memcpy(link.local_addr, lhapd->own_addr, ETH_ALEN);
	os_memcpy(link.peer_addr, link_addr, ETH_ALEN);

	/* Parse STA profile, check the IEs, and send ADD_LINK_STA */
	ieee80211_ml_process_link(lhapd, assoc_sta, &link, ies, ies_len,
				  LINK_PARSE_RECONF, false);
	if (link.status != WLAN_STATUS_SUCCESS)
		return link.status;

	lsta = ap_get_sta(lhapd, assoc_sta->addr);
	if (!lsta)
		return WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;

	for_each_mld_link(other_hapd, lhapd) {
		struct mld_link_info *_link;

		other_sta = ap_get_sta(other_hapd, lsta->addr);
		if (!other_sta)
			continue;

		_link = &other_sta->mld_info.links[link_id];
		_link->valid = true;
		_link->status = WLAN_STATUS_SUCCESS;
		os_memcpy(_link->local_addr, other_hapd->own_addr, ETH_ALEN);
		os_memcpy(_link->peer_addr, link_addr, ETH_ALEN);
	}
	wpa_auth_set_ml_info(lsta->wpa_sm, lsta->mld_assoc_link_id,
			     &lsta->mld_info);

	return WLAN_STATUS_SUCCESS;
}


static int
hostapd_reject_all_reconf_req(struct hostapd_data *hapd, u8 *pos,
			      struct link_reconf_req_list *req_list)
{
	struct link_reconf_req_info *info;
	struct hostapd_data *lhapd;
	struct sta_info *lsta;
	u16 status;
	u8 *buf = pos;

	dl_list_for_each(info, &req_list->add_req, struct link_reconf_req_info,
			 list) {
		lhapd = NULL;
		lsta = NULL;
		*pos++ = info->link_id;
		status = info->status != WLAN_STATUS_SUCCESS ? info->status :
			WLAN_STATUS_UNSPECIFIED_FAILURE;
		WPA_PUT_LE16(pos, status);

		if (info->status == WLAN_STATUS_SUCCESS) {
			lhapd = hostapd_mld_get_link_bss(hapd, info->link_id);
			if (lhapd)
				lsta = ap_get_sta(lhapd,
						  req_list->sta_mld_addr);

			if (lsta)
				ap_free_sta(lhapd, lsta);

			info->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		wpa_printf(MSG_DEBUG, "MLD: Reject add-link=%u with status=%u",
			   info->link_id, status);
		pos += 2;
	}

	dl_list_for_each(info, &req_list->del_req, struct link_reconf_req_info,
			 list) {
		*pos++ = info->link_id;
		status = info->status != WLAN_STATUS_SUCCESS ? info->status :
			WLAN_STATUS_UNSPECIFIED_FAILURE;
		WPA_PUT_LE16(pos, status);

		if (info->status == WLAN_STATUS_SUCCESS)
			info->status = WLAN_STATUS_UNSPECIFIED_FAILURE;

		wpa_printf(MSG_DEBUG, "MLD: Reject del-link=%u with status=%u",
			   info->link_id, status);
		pos += 2;
	}

	return pos - buf;
}


static int
hostapd_send_link_reconf_resp(struct hostapd_data *hapd,
			      struct sta_info *assoc_sta,
			      struct link_reconf_req_list *req_list)
{
	u8 *buf, *orig_pos, *pos;
	struct ieee80211_mgmt *mgmt;
	struct link_reconf_req_info *info;
	struct mld_info mld;
	int ret;
	unsigned int count;
	u8 dialog_token;
	bool reject_all = false;
	size_t len, pos_len, kde_len, mle_len;

	count = dl_list_len(&req_list->add_req) +
		dl_list_len(&req_list->del_req);
	if (!count)
		return 0;

	os_memset(&mld, 0, sizeof(mld));

	dialog_token = req_list->dialog_token;

	/*
	 * Link Reconfiguration Response:
	 *
	 * IEEE80211 Header (24B) +
	 * Category (1B) + Action code (1B) + Dialog Token (1B) +
	 * Count (1B) + Status list (count * 3B) +
	 * Optional: Group Key Data field (variable) +
	 * Optional: OCI element (6B) +
	 * Optional: Basic Multi-Link element (variable)
	 */
	len = IEEE80211_HDRLEN + 3 + 1 + count * 3;
	kde_len = mle_len = 0;

	if (req_list->links_add_ok) {
		kde_len = wpa_auth_ml_group_kdes_len(
			assoc_sta->wpa_sm, req_list->links_add_ok) + 1;
		len += kde_len;

		if (wpa_auth_uses_ocv(assoc_sta->wpa_sm))
			len += OCV_OCI_EXTENDED_LEN;

		mld.mld_sta = true;
		dl_list_for_each(info, &req_list->add_req,
				 struct link_reconf_req_info, list) {
			struct mld_link_info *link = &mld.links[info->link_id];
			struct hostapd_data *lhapd = NULL;

			if (info->status != WLAN_STATUS_SUCCESS)
				continue;

			link->status = info->status;

			lhapd = hostapd_mld_get_link_bss(hapd, info->link_id);
			if (!lhapd)
				continue;

			link->valid = true;
			ieee80211_ml_build_assoc_resp(lhapd, link);
		}
		/* TODO: Basic MLE is not supposed to include BPCC in Link
		 * Reconfiguration Response, but mac80211 implementation for
		 * processing this frame requires that to be present. For now,
		 * include that subfield as a workaround. This should be removed
		 * once mac80211 is fixed to match the standard (or this comment
		 * be removed if the standard is modified to match
		 * implementation). */
		mle_len = hostapd_eid_eht_ml_len(&mld, false, true, hapd->iconf->eml_disable);
		len += mle_len;
	}

	buf = os_zalloc(len);
	if (!buf) {
		wpa_printf(MSG_INFO,
			   "MLD: Failed to allocate Link Reconf Response buffer (%zu bytes)",
			   len);
		return -1;
	}

	mgmt = (struct ieee80211_mgmt *) buf;
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	os_memcpy(mgmt->da, assoc_sta->addr, ETH_ALEN);
	os_memcpy(mgmt->sa, hapd->mld->mld_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, hapd->mld->mld_addr, ETH_ALEN);

	mgmt->u.action.category = WLAN_ACTION_PROTECTED_EHT;
	mgmt->u.action.u.link_reconf_resp.action =
		WLAN_PROT_EHT_LINK_RECONFIG_RESPONSE;
	mgmt->u.action.u.link_reconf_resp.dialog_token = dialog_token;
	mgmt->u.action.u.link_reconf_resp.count = count;

	orig_pos = pos = mgmt->u.action.u.link_reconf_resp.variable;
	pos_len = 28; /* IEEE80211 Header, category, code, token, count */

	dl_list_for_each(info, &req_list->add_req, struct link_reconf_req_info,
			 list) {
		*pos++ = info->link_id;
		WPA_PUT_LE16(pos, info->status);
		pos += 2;
		pos_len += 3;
	}

	dl_list_for_each(info, &req_list->del_req, struct link_reconf_req_info,
			 list) {
		/* Mark the status as INVALID for rejected link to recover */
		if (!(req_list->links_del_ok & BIT(info->link_id)) &&
		    info->status == WLAN_STATUS_SUCCESS)
			info->status = WLAN_STATUS_UNSPECIFIED_FAILURE;

		*pos++ = info->link_id;
		WPA_PUT_LE16(pos, info->status);
		pos += 2;
		pos_len += 3;
	}

	if (!req_list->links_add_ok)
		goto send_resp;

	/* Key Data for add links */
	if (kde_len) {
		u8 *kde_pos = pos;

		kde_pos = wpa_auth_ml_group_kdes(assoc_sta->wpa_sm, ++kde_pos,
						 req_list->links_add_ok);
		*pos = kde_pos - pos - 1;
		if (kde_len - 1 != *pos) {
			reject_all = true;
			goto reject_all_req;
		}

		wpa_hexdump_key(MSG_DEBUG, "MLD: Group KDE", pos + 1, *pos);

		pos += kde_len;
		pos_len += kde_len;
	}

#ifdef CONFIG_OCV
	/* OCI element for add links */
	if (wpa_auth_uses_ocv(assoc_sta->wpa_sm)) {
		struct wpa_channel_info ci;

		if (hostapd_drv_channel_info(hapd, &ci)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Failed to fetch OCI; reject all requests");
			reject_all = true;
			goto reject_all_req;
		}

		if (ocv_insert_extended_oci(&ci, pos)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Failed to add OCI element; reject all requests");
			reject_all = true;
			goto reject_all_req;
		}

		pos += OCV_OCI_EXTENDED_LEN;
		pos_len += OCV_OCI_EXTENDED_LEN;
	}
#endif

	/* Basic Multi-Link element for add links */
	if (mle_len) {
		u8 *mle_pos = pos;

		/* TODO: Basic MLE is not supposed to include BPCC in Link
		 * Reconfiguration Response, but mac80211 implementation for
		 * processing this frame requires that to be present. For now,
		 * include that subfield as a workaround. This should be removed
		 * once mac80211 is fixed to match the standard (or this comment
		 * be removed if the standard is modified to match
		 * implementation). */
		mle_pos = hostapd_eid_eht_basic_ml_common(hapd, mle_pos, &mld,
							  false, true);
		if ((size_t) (mle_pos - pos) != mle_len) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Unexpected MLE length: %ld != %zu",
				   mle_pos - pos, mle_len);
			reject_all = true;
			goto reject_all_req;
		}

		pos += mle_len;
		pos_len += mle_len;
	}

reject_all_req:
	if (reject_all) {
		pos = orig_pos;
		pos_len = 28; /* reset pos_len */
		pos += hostapd_reject_all_reconf_req(hapd, orig_pos, req_list);
		pos_len += pos - orig_pos;

		req_list->links_add_ok = req_list->links_del_ok = 0;
		req_list->new_valid_links = 0;
	}

send_resp:
	ret = hostapd_drv_send_mlme(hapd, mgmt, pos_len, 0, NULL, 0, 0);
	os_free(buf);

	if (mld.mld_sta)
		ap_sta_free_sta_profile(&mld);

	return ret;
}


static int
hostapd_ml_check_sta_entry_by_link_addr_iter(struct hostapd_data *hapd,
					     struct sta_info *sta, void *ctx)
{
	const u8 *link_addr = ctx;
	struct mld_link_info li;

	if (!link_addr)
		return 0;

	if (sta->mld_info.mld_sta) {
		li = sta->mld_info.links[hapd->mld_link_id];
		if (!li.valid || !ether_addr_equal(li.peer_addr, link_addr))
			return 0;

		wpa_printf(MSG_DEBUG, "MLD: STA with address " MACSTR
			   " exists for AP (link_id=%u) as a non-AP STA affiliated with non-AP MLD "
			   MACSTR, MAC2STR(link_addr),
			   hapd->mld_link_id, MAC2STR(sta->addr));
		return 1;
	}

	if (ether_addr_equal(sta->addr, link_addr)) {
		wpa_printf(MSG_DEBUG, "MLD: STA with address " MACSTR
			   " exists for AP (link_id=%u) as a legacy STA",
			   MAC2STR(link_addr), hapd->mld_link_id);
		return 1;
	}

	return 0;
}


/* Returns:
 * 0 = successful parsing
 * 1 = per-STA profile (subelement) skipped or rejected
 * -1 = fail due to fatal errors
 */
static int
hostapd_parse_link_reconf_req_sta_profile(struct hostapd_data *hapd,
					    struct link_reconf_req_list *req,
					    const u8 *buf, size_t len)
{
	struct link_reconf_req_info *info = NULL;
	const struct ieee80211_eht_per_sta_profile *per_sta_prof;
	const struct element *elem;
	struct hostapd_data *lhapd = NULL;
	struct sta_info *lsta;
	size_t sta_info_len, sta_prof_len = 0;
	u16 sta_control, reconf_type_mask;
	u8 link_id, reconf_type;
	const u8 *sta_info = NULL, *end;
	u8 sta_addr[ETH_ALEN];
	size_t nstr_bitmap_size = 0;
	int ret = -1;
	u16 status;

	if (len < sizeof(*elem) + 2UL)
		goto out;

	elem = (const struct element *) buf;
	end = buf + len;

	os_memset(sta_addr, 0, ETH_ALEN);

	if (elem->id != EHT_ML_SUB_ELEM_PER_STA_PROFILE) {
		wpa_printf(MSG_DEBUG, "MLD: Unexpected subelement (%u) found",
			   elem->id);
		ret = 1; /* skip this subelement */
		goto out;
	}

	status = WLAN_STATUS_UNSPECIFIED_FAILURE;

	per_sta_prof = (const struct ieee80211_eht_per_sta_profile *)
		elem->data;
	sta_control = le_to_host16(per_sta_prof->sta_control);
	sta_info_len = 1;

	link_id = sta_control & EHT_PER_STA_RECONF_CTRL_LINK_ID_MSK;
	wpa_printf(MSG_DEBUG, "MLD: Per-STA profile for link=%u", link_id);

	reconf_type_mask =
		sta_control & EHT_PER_STA_RECONF_CTRL_OP_UPDATE_TYPE_MSK;
	reconf_type =
		EHT_PER_STA_RECONF_CTRL_OP_UPDATE_TYPE_VAL(reconf_type_mask);

	switch (reconf_type) {
	case EHT_RECONF_TYPE_ADD_LINK:
	case EHT_RECONF_TYPE_DELETE_LINK:
		break;
	default:
		wpa_printf(MSG_ERROR,
			   "MLD: Unsupported Reconfiguration type %u",
			   reconf_type);
		ret = 1; /* skip this per-STA profile */
		goto out;
	}

	if (!(sta_control & EHT_PER_STA_RECONF_CTRL_MAC_ADDR)) {
		wpa_printf(MSG_DEBUG,
			   "MLD: STA MAC address not set in STA control");
		ret = 1; /* reject this per-STA profile */
		goto add_to_list;
	}
	sta_info_len += ETH_ALEN;

	if (sta_control & EHT_PER_STA_RECONF_CTRL_AP_REMOVAL_TIMER) {
		wpa_printf(MSG_DEBUG,
			   "MLD: AP removal timer set in STA control");
		sta_info_len += 2;
	}

	if (sta_control & EHT_PER_STA_RECONF_CTRL_OP_PARAMS) {
		wpa_printf(MSG_DEBUG, "MLD: Op params set in STA control");
		sta_info_len += 3;
	}

	if (!(sta_control & EHT_PER_STA_RECONF_CTRL_COMPLETE_PROFILE)) {
		if (reconf_type == EHT_RECONF_TYPE_ADD_LINK) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Complete profile not set in STA control");
			ret = 1; /* reject this per-STA profile */
			goto add_to_list;
		}
	} else {
		if (reconf_type == EHT_RECONF_TYPE_DELETE_LINK)
			wpa_printf(MSG_DEBUG,
				   "MLD: Complete profile set in STA control");
	}

	if (sta_control & EHT_PER_STA_RECONF_CTRL_NSTR_INDICATION) {
		nstr_bitmap_size = 1;
		if (sta_control &
		    EHT_PER_STA_RECONF_CTRL_NSTR_BITMAP_SIZE)
			nstr_bitmap_size = 2;

		if (reconf_type == EHT_RECONF_TYPE_DELETE_LINK)
			wpa_printf(MSG_DEBUG,
				   "MLD: NSTR Indication set in STA control");
	}
	sta_info_len += nstr_bitmap_size;

	sta_info = per_sta_prof->variable;
	if (*sta_info > end - sta_info) {
		wpa_printf(MSG_DEBUG, "MLD: Not enough room for STA Info");
		goto out;
	}

	if (*sta_info < sta_info_len) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Invalid Reconf STA Info len (%u); min expected=%zu",
			   *sta_info, sta_info_len);
		goto out;
	}

	sta_info_len = *sta_info;

	os_memcpy(sta_addr, sta_info + 1, ETH_ALEN);
	wpa_printf(MSG_DEBUG, "MLD: Link STA addr=" MACSTR, MAC2STR(sta_addr));

	sta_info += sta_info_len;

	lhapd = hostapd_mld_get_link_bss(hapd, link_id);
	if (!lhapd) {
		wpa_printf(MSG_DEBUG, "MLD: No AP link found for link id=%u",
			   link_id);
		ret = 1; /* reject this per-STA profile */
		goto add_to_list;
	}

	lsta = ap_get_sta(lhapd, req->sta_mld_addr);

	if (reconf_type == EHT_RECONF_TYPE_DELETE_LINK) {
		/* DELETE_LINK request shall not have STA profile */
		if (len != sizeof(sta_control) + sta_info_len)
			wpa_printf(MSG_DEBUG,
				   "MLD: Delete link request has STA profile");

		if (!lsta || !ap_sta_is_mld(lhapd, lsta) ||
		    !lsta->mld_info.links[link_id].valid) {
			wpa_printf(MSG_DEBUG,
				   "MLD: STA invalid for link id=%u peer addr="
				   MACSTR, link_id, MAC2STR(sta_addr));
			ret = 1; /* reject this per-STA profile */
			goto add_to_list;
		}

		if (!ether_addr_equal(lsta->mld_info.links[link_id].peer_addr,
				      sta_addr)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: STA invalid for addr=" MACSTR,
				   MAC2STR(sta_addr));
			ret = 1; /* reject this per-STA profile */
			goto add_to_list;
		}

		status = WLAN_STATUS_SUCCESS;
		ret = 0;
		goto add_to_list;
	}

	/* EHT_RECONF_TYPE_ADD_LINK */
	if (len < sizeof(sta_control) + sta_info_len + 2)
		goto out;
	sta_prof_len = len - sizeof(sta_control) - sta_info_len - 2;
	if (sta_prof_len > (size_t) (end - sta_info)) {
		wpa_printf(MSG_DEBUG, "MLD: STA Profile with excess length");
		goto out;
	}

	if (lsta) {
		wpa_printf(MSG_DEBUG,
			   "MLD: STA exists for link id=%u MLD addr=" MACSTR,
			   link_id, MAC2STR(req->sta_mld_addr));
		ret = 1; /* reject this per-STA profile */
		goto add_to_list;
	}

	/* Check if link address is already used by any connected legacy
	 * non-AP STA or non-AP STA affiliated with a non-AP MLD.
	 */
	if (ap_for_each_sta(lhapd, hostapd_ml_check_sta_entry_by_link_addr_iter,
			    sta_addr)) {
		ret = 1; /* Reject this per-STA profile */
		goto add_to_list;
	}

	status = WLAN_STATUS_SUCCESS; /* IE validations done later */
	ret = 0;

add_to_list:
	info = os_zalloc(sizeof(struct link_reconf_req_info) + sta_prof_len);
	if (!info) {
		wpa_printf(MSG_DEBUG, "MLD: Failed to allocate request info");
		ret = 1; /* skip this per-STA profile */
		goto out;
	}

	info->link_id = link_id;
	info->status = status;
	os_memcpy(info->peer_addr, sta_addr, ETH_ALEN);
	if (lhapd)
		os_memcpy(info->local_addr, lhapd->own_addr, ETH_ALEN);

	if (reconf_type == EHT_RECONF_TYPE_DELETE_LINK) {
		dl_list_add_tail(&req->del_req, &info->list);
	} else if (sta_info) {
		os_memcpy(info->sta_prof, sta_info, sta_prof_len);
		info->sta_prof_len = sta_prof_len;

		dl_list_add_tail(&req->add_req, &info->list);
	} else {
		os_free(info);
	}
	wpa_printf(MSG_INFO, "MLD: Link (%d) parsed to %s request; status=%u",
		   link_id,
		   reconf_type == EHT_RECONF_TYPE_DELETE_LINK ? "del" : "add",
		   status);

out:
	if (ret < 0)
		wpa_printf(MSG_DEBUG,
			   "MLD: Failed to parse reconf req STA profile");
	return ret;
}


static int
hostapd_parse_link_reconf_req_reconf_mle(
		struct hostapd_data *hapd, const u8 *mle, size_t mle_len,
		struct link_reconf_req_list **req_list_ptr)
{
	struct link_reconf_req_list *req_list;
	struct wpabuf *mlbuf = NULL;
	struct sta_info *sta;
	const struct ieee80211_eht_ml *ml;
	const struct eht_ml_reconf_common_info *ml_common_info;
	size_t len, ml_common_len;
	u16 ml_control;
	const u8 *pos, *end;
	int ret = -1;

	mlbuf = ieee802_11_defrag(mle, mle_len, true);
	if (!mlbuf) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Failed to defrag Reconfiguration MLE");
		goto fail;
	}

	ml = (const struct ieee80211_eht_ml *) wpabuf_head(mlbuf);
	len = wpabuf_len(mlbuf);
	end = ((const u8 *) ml) + len;

	wpa_hexdump(MSG_DEBUG, "MLD: Defragged Reconfiguration MLE",
		    (const void *) ml, len);

	if (len < sizeof(*ml) + ETH_ALEN + 1UL)
		goto fail;

	ml_control = WPA_GET_LE16((const u8 *) ml) >> 4;
	ml_common_len = 1;
	if (!(ml_control & RECONF_MULTI_LINK_CTRL_PRES_MLD_MAC_ADDR))
		goto fail;
	ml_common_len += ETH_ALEN;

	if (ml_control & RECONF_MULTI_LINK_CTRL_PRES_EML_CAPA)
		ml_common_len += 2;

	if (ml_control & RECONF_MULTI_LINK_CTRL_PRES_MLD_CAPA)
		ml_common_len += 2;

	if (ml_control & RECONF_MULTI_LINK_CTRL_PRES_EXT_MLD_CAP)
		ml_common_len += 2;

	ml_common_info =
		(const struct eht_ml_reconf_common_info *) ml->variable;
	if (len < sizeof(*ml) + ml_common_info->len) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Unexpected Reconfiguration ML element length (%zu < %zu)",
			   len, sizeof(*ml) + ml_common_info->len);
		goto fail;
	}

	if (ml_common_info->len < ml_common_len) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Invalid Reconf common info len (%u); min expected=%zu",
			   ml_common_info->len, ml_common_len);
		goto fail;
	}

	pos = (const u8 *) ml_common_info->variable;

	sta = ap_get_sta(hapd, pos);
	if (!sta || !ap_sta_is_mld(hapd, sta)) {
		wpa_printf(MSG_DEBUG, "MLD: STA invalid%s for " MACSTR,
			   sta ? "" : " (NULL)", MAC2STR(pos));
		goto fail;
	}

	*req_list_ptr = os_zalloc(sizeof(struct link_reconf_req_list));
	if (!(*req_list_ptr)) {
		wpa_printf(MSG_ERROR, "MLD: Failed to allocate request list");
		goto fail;
	}
	req_list = *req_list_ptr;

	os_memcpy(req_list->sta_mld_addr, pos, ETH_ALEN);
	dl_list_init(&req_list->del_req);
	dl_list_init(&req_list->add_req);

	pos = ml->variable + ml_common_info->len;

	while (end - pos > 2) {
		size_t sub_elem_len;
		int num_frag_subelems;

		num_frag_subelems =
			ieee802_11_defrag_mle_subelem(mlbuf, pos,
						      &sub_elem_len);
		if (num_frag_subelems < 0) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Failed to parse Reconfiguration MLE subelem");
			goto fail;
		}

		len -= num_frag_subelems * 2;
		end = ((const u8 *) ml) + len;

		if (sub_elem_len + 2 > (size_t) (end - pos))
			goto fail;

		if (hostapd_parse_link_reconf_req_sta_profile(
			    hapd, req_list, pos, sub_elem_len + 2) < 0)
			goto fail;

		pos += sub_elem_len + 2;
	}

	ret = 0;

fail:
	if (ret)
		ml_deinit_link_reconf_req(req_list_ptr);

	wpabuf_free(mlbuf);
	return ret;
}


static bool
hostapd_validate_link_reconf_req(struct hostapd_data *hapd,
				 struct sta_info *sta,
				 struct link_reconf_req_list *req_list)
{
	struct hostapd_data *assoc_hapd, *lhapd;
	struct link_reconf_req_info *info;
	struct sta_info *assoc_sta, *lsta;
	struct mld_info *mld_info;
	u8 recovery_link;
	u16 valid_links = 0, links_add_ok = 0, links_del_ok = 0, status;
	size_t link_kde_len, total_kde_len = 0;
	int i;

	assoc_sta = hostapd_ml_get_assoc_sta(hapd, sta, &assoc_hapd);
	if (!assoc_sta)
		return false;

	if (dl_list_empty(&req_list->add_req) &&
	    dl_list_empty(&req_list->del_req)) {
		wpa_printf(MSG_DEBUG, "MLD: No add or delete request found");
		return false;
	}

	mld_info = &assoc_sta->mld_info;
	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
		if (mld_info->links[i].valid &&
		    mld_info->links[i].status == WLAN_STATUS_SUCCESS)
			valid_links |= BIT(i);
	}

	/* Check IEs for add-link STA profiles */
	dl_list_for_each(info, &req_list->add_req, struct link_reconf_req_info,
			 list) {
		lhapd = NULL;
		lsta = NULL;

		wpa_printf(MSG_DEBUG,
			   "MLD: Add Link Reconf STA for link id=%u status=%u",
			   info->link_id, info->status);
		if (info->status != WLAN_STATUS_SUCCESS ||
		    info->sta_prof_len < 2)
			continue;

		/* Offset 2 bytes for Capabilities in STA Profile */
		status = hostapd_ml_process_reconf_link(hapd, assoc_sta,
							info->sta_prof + 2,
							info->sta_prof_len - 2,
							info->link_id,
							info->peer_addr);
		if (status != WLAN_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Add link IE validation failed for link=%u",
				   info->link_id);
			info->status = status;
			continue;
		}

		link_kde_len = wpa_auth_ml_group_kdes_len(assoc_sta->wpa_sm,
							  BIT(info->link_id));

		/* Since Group KDE element Length subfield is one byte,
		 * accept as many add-link requests as can be fit.
		 */
		if (total_kde_len + link_kde_len >
		    LINK_RECONF_GROUP_KDE_MAX_LEN) {
			wpa_printf(MSG_INFO,
				   "MLD: Group KDEs cannot fit (%zu > %u) for link=%u",
				   total_kde_len + link_kde_len,
				   LINK_RECONF_GROUP_KDE_MAX_LEN,
				   info->link_id);
			status = WLAN_STATUS_UNSPECIFIED_FAILURE;

			lhapd = hostapd_mld_get_link_bss(hapd, info->link_id);
			if (lhapd)
				lsta = ap_get_sta(lhapd,
						  req_list->sta_mld_addr);

			if (lsta)
				ap_free_sta(lhapd, lsta);
		} else {
			total_kde_len += link_kde_len;
			links_add_ok |= BIT(info->link_id);
			wpa_msg(hapd->msg_ctx, MSG_INFO,
				WPA_EVENT_LINK_STA_ADDED "sta=" MACSTR
				" link_id=%u", MAC2STR(req_list->sta_mld_addr),
				info->link_id);
		}

		info->status = status;
	}

	dl_list_for_each(info, &req_list->del_req, struct link_reconf_req_info,
			list) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Del Link Reconf STA for link id=%u status=%u",
			   info->link_id, info->status);
		if (info->status == WLAN_STATUS_SUCCESS)
			links_del_ok |= BIT(info->link_id);
	}

	wpa_printf(MSG_INFO, "MLD: valid_links=0x%x add_ok=0x%x del_ok=0x%x",
		   valid_links, links_add_ok, links_del_ok);

	if ((links_add_ok && (valid_links & links_add_ok)) ||
	    (links_del_ok && !(valid_links & links_del_ok))) {
		wpa_printf(MSG_INFO,
			   "MLD: Links requested failed to satisfy valid links");
		return false;
	}

	if (links_add_ok & links_del_ok) {
		wpa_printf(MSG_INFO,
			   "MLD: Links (0x%x) present in both valid add and delete requests",
			   links_add_ok & links_del_ok);
		return false;
	}

	valid_links |= links_add_ok;
	valid_links &= ~links_del_ok;
	if (!valid_links) {
		if (!recover_from_zero_links(&links_del_ok, &recovery_link)) {
			wpa_printf(MSG_INFO,
				   "MLD: Total-links validation failed");
			return false;
		}
		/* Add the recovery link back to valid_links */
		valid_links |= BIT(recovery_link);
	}

	req_list->new_valid_links = valid_links;
	req_list->links_add_ok = links_add_ok;
	req_list->links_del_ok = links_del_ok;

	/* TODO: Add support to handle multiple requests from the non-AP MLD */
	assoc_sta->reconf_req = req_list;

	return true;
}


static int
hostapd_handle_link_reconf_req(struct hostapd_data *hapd, const u8 *buf,
			       size_t len)
{
	struct ieee802_11_elems elems;
	struct hostapd_data *assoc_hapd;
	struct sta_info *sta, *assoc_sta = NULL;
	u8 dialog_token;
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	struct link_reconf_req_list *req_list = NULL;
	const u8 *pos = NULL;
	int ret = -1;

	wpa_printf(MSG_DEBUG,
		   "MLD: Link Reconfiguration Request frame from " MACSTR,
		   MAC2STR(mgmt->sa));

	/* Min length: IEEE80211 Header (24B) + Category (1B) + Action (1B) +
	 *	       Dialog token (1B) +
	 *	       Reconfiguration MLE header and extension ID (3B)
	 */
	if (len < IEEE80211_HDRLEN + 3 + 3) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Invalid minimum length (%zu) for Link Reconfiguration Request",
			   len);
		goto out;
	}

	dialog_token = mgmt->u.action.u.link_reconf_req.dialog_token;
	pos = mgmt->u.action.u.link_reconf_req.variable;

	sta = ap_get_sta(hapd, mgmt->sa);
	if (!sta) {
		wpa_printf(MSG_DEBUG, "MLD: No STA found for " MACSTR
			   "; drop Link Reconfiguration Request",
			   MAC2STR(mgmt->sa));
		goto out;
	}

	if (!ap_sta_is_mld(hapd, sta)) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Not an MLD connection; drop Link Reconfiguration Request");
		goto out;
	}

	assoc_sta = hostapd_ml_get_assoc_sta(hapd, sta, &assoc_hapd);
	if (!assoc_sta) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Not able to get assoc link STA; drop Link Reconfiguration Request");
		goto out;
	}

	if (assoc_sta->reconf_req) {
		wpa_printf(MSG_INFO,
			   "MLD: Link Reconfiguration Request from this STA with token=%u is already in progress",
			   assoc_sta->reconf_req->dialog_token);
		goto out;
	}

	/* Parse Reconfiguration Multi-Link element and OCI elements */
	if (ieee802_11_parse_elems(pos, len - (pos - buf), &elems, 1) ==
	    ParseFailed) {
		wpa_printf(MSG_DEBUG,
			   "MLD: Could not parse Link Reconfiguration Request");
		goto out;
	}

	if (!elems.reconf_mle || !elems.reconf_mle_len) {
		wpa_printf(MSG_DEBUG, "MLD: No Reconfiguration ML element");
		goto out;
	}

	/* Process Reconfiguration MLE */
	if (hostapd_parse_link_reconf_req_reconf_mle(hapd, elems.reconf_mle,
						     elems.reconf_mle_len,
						     &req_list)) {
		wpa_printf(MSG_INFO,
			   "MLD: Reconfiguration MLE parsing failed; drop Link Reconfiguration Request");
		goto out;
	}

	/* Do OCI element validation */
	if (dl_list_empty(&req_list->add_req))
		goto skip_oci_validation;

	if (!elems.oci || !elems.oci_len) {
		if (wpa_auth_uses_ocv(assoc_sta->wpa_sm) == 1) {
			wpa_printf(MSG_INFO,
				   "MLD: No OCI element present; drop Link Reconfiguration Request");
			goto out;
		}
	} else {
		struct wpa_channel_info ci;

		if (!wpa_auth_uses_ocv(assoc_sta->wpa_sm)) {
			wpa_printf(MSG_INFO,
				   "MLD: Unexpected OCI element found; drop Link Reconfiguration Request");
			goto out;
		}

		if (hostapd_drv_channel_info(hapd, &ci)) {
			wpa_printf(MSG_DEBUG,
				   "MLD: Failed to get channel info to verify OCI element");
			goto out;
		}

#ifdef CONFIG_OCV
		if (!ocv_verify_tx_params(elems.oci, elems.oci_len, &ci,
					  channel_width_to_int(ci.chanwidth),
					  ci.seg1_idx)) {
			wpa_printf(MSG_INFO,
				   "MLD: OCI verification failed; drop Link Reconfiguration Request");
			goto out;
		}
#endif
	}

skip_oci_validation:
	/* Do STA profile validation */
	if (!hostapd_validate_link_reconf_req(hapd, assoc_sta, req_list))
		goto out;

	req_list->dialog_token = dialog_token;
	ret = hostapd_send_link_reconf_resp(hapd, assoc_sta, req_list);
	if (ret)
		wpa_printf(MSG_INFO,
			   "MLD: Failed to send Link Reconfiguration Response (%d)",
			   ret);

out:
	if (ret) {
		ml_deinit_link_reconf_req(&req_list);
		if (assoc_sta && assoc_sta->reconf_req)
			assoc_sta->reconf_req = NULL;
	}
	return ret;
}

static void ieee802_11_send_eml_omn(struct hostapd_data *hapd,
				    const u8 *addr,
				    struct eml_omn_element *omn_ie,
				    size_t len)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(2 + len);
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_EHT);
	wpabuf_put_u8(buf, WLAN_PROT_EHT_EML_OPMODE_NOTIF);
	wpabuf_put_data(buf, omn_ie, len);

	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
				wpabuf_head(buf), wpabuf_len(buf));

	wpabuf_free(buf);
}

static void ieee802_11_rx_eml_omn(struct hostapd_data *hapd,
				  const u8 *addr, const u8 *frm,
				  size_t len)
{
	struct eml_omn_element *omn_ie;

	if (hapd->iconf->eml_disable) {
		wpa_printf(MSG_ERROR,
			   "Ignore EML Operating Mode Notification from "
			   MACSTR
			   " since EML Capabilities is disabled",
			   MAC2STR(addr));
		return;
	}

	/* EML Operating Mode Notification IE */
	omn_ie = os_zalloc(sizeof(struct eml_omn_element));
	if (omn_ie == NULL)
		return;

	os_memcpy(omn_ie, frm, len);

	if (omn_ie->control & EHT_EML_OMN_CONTROL_EMLMR_MODE) {
		wpa_printf(MSG_ERROR,
			   "EML: Ignore EML Operating Mode Fotification from "
			   MACSTR
			   " since doesn't support EMLMR",
			   MAC2STR(addr));
		goto out;
	}

	hostapd_drv_set_eml_omn(hapd, addr, omn_ie);

	omn_ie->control &= ~(EHT_EML_OMN_CONTROL_EMLSR_PARA_UPDATE_COUNT |
			     EHT_EML_OMN_CONTROL_INDEV_COEX_ACTIVITIES);

	if (hapd->iconf->eml_resp) {
		ieee802_11_send_eml_omn(hapd, addr, omn_ie, len);
		wpa_printf(MSG_ERROR, "EML: AP send EML Operating Mode Fotification to "
				       MACSTR,
				       MAC2STR(addr));
	}
out:
	os_free(omn_ie);
	return;
}

static u16 ieee80211_get_link_map(u8 bm_size, const u8 *data)
{
	if (bm_size == 1)
		return *data;
	else
		return WPA_GET_LE16(data);
}

static int ieee802_11_parse_neg_ttlm(struct hostapd_data *hapd,
				     const u8 *ttlm_ie, size_t ttlm_ie_len,
				     struct ieee80211_neg_ttlm *neg_ttlm,
				     u8 *direction)
{
	u8 control, link_map_presence, map_size, tid;
	const u8 *pos = ttlm_ie;
	const size_t fixed_length = 1; /* Control Feild */

	if (ttlm_ie_len < fixed_length)
		return -EINVAL;

	os_memset(neg_ttlm, 0, sizeof(*neg_ttlm));

	control = *pos++;
	ttlm_ie_len--;

	/* mapping switch time and expected duration fields are not expected
	 * in case of negotiated TTLM
	 */
	if (control & (IEEE80211_TTLM_CONTROL_SWITCH_TIME_PRESENT |
		       IEEE80211_TTLM_CONTROL_EXPECTED_DUR_PRESENT)) {
		wpa_printf(MSG_ERROR,
			   "Invalid TTLM element in negotiated TTLM request\n");
		return -EINVAL;
	}

	if (control & IEEE80211_TTLM_CONTROL_DEF_LINK_MAP) {
		for (tid = 0; tid < IEEE80211_TTLM_NUM_TIDS; tid++) {
			neg_ttlm->dlink[tid] = hapd->mld->active_links;
			neg_ttlm->ulink[tid] = hapd->mld->active_links;
		}
		*direction = IEEE80211_TTLM_DIRECTION_BOTH;
		neg_ttlm->valid = true;
		return 0;
	}

	*direction = (control & IEEE80211_TTLM_CONTROL_DIRECTION);

	/* Link Mapping Presence Bitmap */
	if (ttlm_ie_len < 1)
		return -EINVAL;

	link_map_presence = *pos;
	pos++;
	ttlm_ie_len--;

	if (control & IEEE80211_TTLM_CONTROL_LINK_MAP_SIZE)
		map_size = 1;
	else
		map_size = 2;

	for (tid = 0; tid < IEEE80211_TTLM_NUM_TIDS; tid++) {
		u16 map;

		if (!(link_map_presence & BIT(tid)))
			continue;

		if (ttlm_ie_len < map_size)
			return -EINVAL;

		map = ieee80211_get_link_map(map_size, pos);
		if (!map) {
			wpa_printf(MSG_ERROR, "No active links for TID %d", tid);
			return -EINVAL;
		}

		switch (*direction) {
		case IEEE80211_TTLM_DIRECTION_BOTH:
			neg_ttlm->dlink[tid] = map;
			neg_ttlm->ulink[tid] = map;
			break;
		case IEEE80211_TTLM_DIRECTION_DOWN:
			neg_ttlm->dlink[tid] = map;
			break;
		case IEEE80211_TTLM_DIRECTION_UP:
			neg_ttlm->ulink[tid] = map;
			break;
		default:
			return -EINVAL;
		}

		pos += map_size;
		ttlm_ie_len -= map_size;
	}

	neg_ttlm->valid = true;
	return 0;
}

static int ieee802_11_send_neg_ttlm_resp(struct hostapd_data *hapd,
					  const u8 *addr, u8 dialog_token,
					  u16 status_code)
{
	struct wpabuf *buf;
	size_t len = 5;
	int ret;

	/* TODO currently do not support suggest another mapping */
	if (status_code == WLAN_STATUS_PREFERRED_TID_TO_LINK_MAPPING_SUGGESTED)
		return -1;

	buf = wpabuf_alloc(len);
	if (!buf)
		return -1;

	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_EHT);
	wpabuf_put_u8(buf, WLAN_PROT_EHT_T2L_MAPPING_RESPONSE);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_le16(buf, status_code);

	ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
				      wpabuf_head(buf), wpabuf_len(buf));
	wpabuf_free(buf);

	return ret;
}

static void ieee802_11_rx_neg_ttlm_req(struct hostapd_data *hapd, const u8 *addr,
				       const u8 *frm, size_t len)
{
	struct hostapd_data *assoc_hapd;
	struct neg_ttlm_req *neg_ttlm_req;
	struct ieee802_11_elems elems;
	struct ieee80211_neg_ttlm *neg_ttlm;
	struct sta_info *sta;
	u8 direction;
	u16 status_code = WLAN_STATUS_DENIED_TID_TO_LINK_MAPPING;
	int ret = 0;

	/* TODO Check if AP MLD support Neg-TTLM */
	if (!hostapd_is_mld_ap(hapd))
		goto fail;

	sta = ap_get_sta(hapd, addr);
	if (!sta || !ap_sta_is_mld(hapd, sta))
		goto fail;

	sta = hostapd_ml_get_assoc_sta(hapd, sta, &assoc_hapd);
	if (!sta)
		goto fail;

	/* TODO check the relationship between Adv-TTLM and Neg-TTLM */
	if (hostapd_is_attlm_active(hapd))
		goto fail;

	neg_ttlm_req = (struct neg_ttlm_req *)frm;
	if (ieee802_11_parse_elems(neg_ttlm_req->variable, len - 1, &elems, 1) ==
	    ParseFailed || elems.ttlm_num == 0) {
		wpa_printf(MSG_ERROR, "Invalid neg-TTLM request format\n");
		goto fail;
	}

	/* TODO add support for handling more than one TTLM in the Neg-TTLM
	 * request.
	 */
	if (elems.ttlm_num != 1) {
		wpa_printf(MSG_ERROR, "Error: Only support Neg-TTLM in bi-direction");
		goto fail;
	}

	neg_ttlm = &sta->neg_ttlm;
	ret = ieee802_11_parse_neg_ttlm(hapd, elems.ttlm[0], elems.ttlm_len[0],
					neg_ttlm, &direction);

	if (ret) {
		wpa_printf(MSG_ERROR, "Invalid TTLM format");
		goto fail;
	}

	if (direction != IEEE80211_TTLM_DIRECTION_BOTH) {
		wpa_printf(MSG_ERROR, "Error: Only support Neg-TTLM in bi-direction");
		goto fail;
	}

	status_code = WLAN_STATUS_SUCCESS;
fail:
	ieee802_11_send_neg_ttlm_resp(hapd, addr, neg_ttlm_req->dialog_token,
				      status_code);

	if (status_code == WLAN_STATUS_SUCCESS) {
		ret = hostapd_drv_set_sta_ttlm(assoc_hapd, addr, neg_ttlm);
	} else {
		os_memset(neg_ttlm, 0, sizeof(*neg_ttlm));
		return;
	}

	if (ret) {
		ieee802_11_send_neg_ttlm_teardown(hapd, addr);
		hostapd_teardown_neg_ttlm(assoc_hapd, sta);
		os_memset(neg_ttlm, 0, sizeof(*neg_ttlm));
	}
}

static void ieee802_11_rx_neg_ttlm_teardown(struct hostapd_data *hapd, const u8 *addr)
{
	struct hostapd_data *assoc_hapd;
	struct sta_info *sta;

	if (!hostapd_is_mld_ap(hapd))
		return;

	sta = ap_get_sta(hapd, addr);
	if (!sta || !ap_sta_is_mld(hapd, sta))
		return;

	sta = hostapd_ml_get_assoc_sta(hapd, sta, &assoc_hapd);
	if (!sta || !sta->neg_ttlm.valid)
		return;

	os_memset(&sta->neg_ttlm, 0, sizeof(sta->neg_ttlm));

	hostapd_teardown_neg_ttlm(assoc_hapd, sta);
	return;
}

int ieee802_11_send_neg_ttlm_teardown(struct hostapd_data *hapd, const u8 *addr)
{
	struct wpabuf *buf;
	size_t len = 2;
	int ret;

	buf = wpabuf_alloc(len);
	if (!buf)
		return -1;

	if (hostapd_is_attlm_active(hapd) &&
	    hapd->mld->new_attlm.disabled_links & BIT(hapd->mld_link_id)) {
		wpa_printf(MSG_ERROR,
			   "Request Neg-TTLM teardown on disabled link");
		return -1;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_EHT);
	wpabuf_put_u8(buf, WLAN_PROT_EHT_T2L_MAPPING_TEARDOWN);

	ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
				      wpabuf_head(buf), wpabuf_len(buf));
	wpabuf_free(buf);

	return ret;

}

void hostapd_teardown_neg_ttlm(struct hostapd_data *hapd, struct sta_info *sta)
{
	const u8 *addr = sta->addr;

	sta->neg_ttlm.valid = false;

	if (hostapd_is_attlm_active(hapd) && !hapd->mld->new_attlm.switch_time) {
		struct attlm_settings *attlm = &hapd->mld->new_attlm;
		struct ieee80211_neg_ttlm ttlm;
		int tid;
		u16 map;

		ttlm.valid = true;
		for (tid = 0; tid < IEEE80211_TTLM_NUM_TIDS; tid++) {
			map = ~attlm->disabled_links & hapd->mld->active_links;
			ttlm.dlink[tid] = map;
			ttlm.ulink[tid] = map;
		}

		hostapd_drv_set_sta_ttlm(hapd, addr, &ttlm);
		return;
	}

	hostapd_drv_set_sta_ttlm(hapd, addr, NULL);
	return;
}


void ieee802_11_rx_protected_eht_action(struct hostapd_data *hapd,
					const struct ieee80211_mgmt *mgmt,
					size_t len)
{
	struct sta_info *sta;
	struct mld_info *info = NULL;
	const u8 *payload;
	u8 action;
	size_t plen;

	if (!hapd->conf->mld_ap)
		return;

	if (len < IEEE80211_HDRLEN + 2)
		return;

	sta = ap_get_sta(hapd, mgmt->sa);
	if (sta)
		info = &sta->mld_info;

	payload = ((const u8 *) mgmt) + IEEE80211_HDRLEN + 1;
	action = *payload++;
	plen = len - IEEE80211_HDRLEN - 2;

	switch (action) {
	case WLAN_PROT_EHT_LINK_RECONFIG_REQUEST:
		if (hostapd_handle_link_reconf_req(hapd, (const u8 *) mgmt,
						   len))
			wpa_printf(MSG_INFO,
				   "MLD: Link Reconf Request processing failed");
		return;
	case WLAN_PROT_EHT_EML_OPMODE_NOTIF:
		if (!info) {
			wpa_printf(MSG_DEBUG, "EHT: Station " MACSTR
				   " not found for received Protected EHT Action",
				   MAC2STR(mgmt->sa));
			return;
		}

		if (!info->common_info.eml_capa & EHT_ML_EML_CAPA_EMLSR_SUPP) {
			wpa_printf(MSG_ERROR, "EHT: Fail, Station does not support EMLSR!");
			return;
		}

		ieee802_11_rx_eml_omn(hapd, mgmt->sa, payload, plen);
		return;
	case WLAN_PROT_EHT_T2L_MAPPING_REQUEST:
		wpa_printf(MSG_INFO, "EHT: TTLM request");
		ieee802_11_rx_neg_ttlm_req(hapd, mgmt->sa, payload, plen);
		return;
	case WLAN_PROT_EHT_T2L_MAPPING_RESPONSE:
		wpa_printf(MSG_INFO, "EHT: TTLM response");
		return;
	case WLAN_PROT_EHT_T2L_MAPPING_TEARDOWN:
		wpa_printf(MSG_INFO, "EHT: TTLM teardown");
		ieee802_11_rx_neg_ttlm_teardown(hapd, mgmt->sa);
		return;
	}

	wpa_printf(MSG_DEBUG,
		   "MLD: Unsupported Protected EHT Action %u from " MACSTR
		   " discarded", action, MAC2STR(mgmt->sa));
}
