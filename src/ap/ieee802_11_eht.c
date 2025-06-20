/*
 * hostapd / IEEE 802.11be EHT
 * Copyright (c) 2021-2022, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/crypto.h"
#include "crypto/dh_groups.h"
#include "hostapd.h"
#include "sta_info.h"
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
u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
				     u8 *eid, struct mld_info *mld_info,
				     bool include_mld_id)
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
		struct hostapd_data *link_bss;

		/*
		 * control (2) + station info length (1) + MAC address (6) +
		 * beacon interval (2) + TSF offset (8) + DTIM info (2) + BSS
		 * parameters change counter (1) + station profile length.
		 */
		size_t sta_info_len = include_mld_id ? 21 : 22;
		size_t total_len = sta_info_len +
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

		if (!include_mld_id)
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
		if (!include_mld_id)
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


/*
 * control (2) + station info length (1) + MAC address (6) +
 * beacon interval (2) + TSF offset (8) + DTIM info (2) + BSS
 * parameters change counter (1)
 */
#define EHT_ML_STA_INFO_LENGTH 22
size_t hostapd_eid_eht_basic_ml_len(struct hostapd_data *hapd,
				    struct sta_info *info,
				    bool include_mld_id)
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
		size_t sta_prof_len = EHT_ML_STA_INFO_LENGTH +
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
				     bool include_mld_id,
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
		size_t sta_len = include_mld_id ? 21 : 22;

		link = &info->links[link_id];
		if (!link->valid)
			continue;

		sta_len += link->resp_sta_profile_len;

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


u8 * hostapd_eid_eht_ml_beacon(struct hostapd_data *hapd,
			       struct mld_info *info,
			       u8 *eid, bool include_mld_id)
{
	eid = hostapd_eid_eht_basic_ml_common(hapd, eid, info, include_mld_id);
	return hostapd_eid_eht_reconf_ml(hapd, eid);
}



u8 * hostapd_eid_eht_ml_assoc(struct hostapd_data *hapd, struct sta_info *info,
			      u8 *eid)
{
	if (!ap_sta_is_mld(hapd, info))
		return eid;

	eid = hostapd_eid_eht_basic_ml_common(hapd, eid, &info->mld_info,
					      false);
	ap_sta_free_sta_profile(&info->mld_info);
	return hostapd_eid_eht_reconf_ml(hapd, eid);
}


size_t hostapd_eid_eht_ml_beacon_len(struct hostapd_data *hapd,
				     struct mld_info *info,
				     bool include_mld_id)
{
	return hostapd_eid_eht_ml_len(info,
				      include_mld_id && hostapd_get_mld_id(hapd),
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

void ieee802_11_rx_prot_eht(struct hostapd_data *hapd,
			    const struct ieee80211_mgmt *mgmt,
			    size_t len)
{
	struct sta_info *sta;
	struct mld_info *info;
	u8 action;
	const u8 *payload;
	size_t plen;

	if (!hapd->conf->mld_ap)
		return;

	if (len < IEEE80211_HDRLEN + 2)
		return;

	sta = ap_get_sta(hapd, mgmt->sa);
	if (!sta) {
		wpa_printf(MSG_DEBUG, "EHT: Station " MACSTR
			   " not found for received Protected EHT Action",
			   MAC2STR(mgmt->sa));
		return;
	}

	info = &sta->mld_info;

	payload = mgmt->u.action.u.eht_prot.variable;
	action = mgmt->u.action.u.eht_prot.action;
	plen = len - IEEE80211_HDRLEN - 2;

	switch (action) {
	case WLAN_PROT_EHT_EML_OPMODE_NOTIF:
		if (!info->common_info.eml_capa & EHT_ML_EML_CAPA_EMLSR_SUPP) {
			wpa_printf(MSG_ERROR, "EHT: Fail, Station does not support EMLSR!");
			return;
		}

		ieee802_11_rx_eml_omn(hapd, mgmt->sa, payload, plen);
		return;
	}

	wpa_printf(MSG_ERROR, "EHT: Unsupported Protected EHT Action %u from " MACSTR,
		   action, MAC2STR(mgmt->sa));

	return;

}

