/*
 * Received Data frame processing for EAPOL messages
 * Copyright (c) 2010-2020, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "crypto/aes_wrap.h"
#include "crypto/crypto.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/eapol_common.h"
#include "common/wpa_common.h"
#include "rsn_supp/wpa_ie.h"
#include "wlantest.h"


static int is_zero(const u8 *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i])
			return 0;
	}
	return 1;
}


static size_t determine_mic_len(struct wlantest_sta *sta)
{
	size_t pmk_len = PMK_LEN;
	int group = 0;

	if (sta && wpa_key_mgmt_sae_ext_key(sta->key_mgmt))
		group = sta->sae_group;
	else if (sta && sta->key_mgmt == WPA_KEY_MGMT_OWE)
		group = sta->owe_group;

	switch (group) {
	case 20:
		pmk_len = 48;
		break;
	case 21:
		pmk_len = 64;
		break;
	}

	return wpa_mic_len(sta->key_mgmt, pmk_len);
}


static int check_mic(struct wlantest_sta *sta, const u8 *kck, size_t kck_len,
		     int ver, const u8 *data, size_t len)
{
	u8 *buf;
	int ret = -1;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	u8 rx_mic[WPA_EAPOL_KEY_MIC_MAX_LEN];
	size_t mic_len = determine_mic_len(sta);

	buf = os_memdup(data, len);
	if (buf == NULL)
		return -1;
	hdr = (struct ieee802_1x_hdr *) buf;
	key = (struct wpa_eapol_key *) (hdr + 1);

	os_memcpy(rx_mic, key + 1, mic_len);
	os_memset(key + 1, 0, mic_len);

	if (wpa_eapol_key_mic(kck, kck_len, sta->key_mgmt, ver, buf, len,
			      (u8 *) (key + 1)) == 0 &&
	    os_memcmp(rx_mic, key + 1, mic_len) == 0)
		ret = 0;

	os_free(buf);

	return ret;
}


static void rx_data_eapol_key_1_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *bssid,
				     const u8 *data, size_t len)
{
	struct wlantest_bss *bss, *bss_mld;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data, *mic;
	size_t mic_len, left;
	u16 key_data_len;
	struct wpa_eapol_ie_parse ie;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 1/4 " MACSTR " -> " MACSTR " (BSSID "
		   MACSTR ")",
		   MAC2STR(src), MAC2STR(dst), MAC2STR(bssid));
	if (ether_addr_equal(src, bssid)) {
		bss = bss_get(wt, src);
	} else {
		bss = bss_find(wt, bssid);
		bss_mld = bss_find(wt, src);
		if (bss_mld && (!bss || sta_find(bss_mld, src)))
			bss = bss_get(wt, src);
		else
			bss = bss_get(wt, bssid);
	}
	if (bss == NULL)
		return;
	sta = sta_get(bss, dst);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	left = len - sizeof(*hdr);
	mic_len = determine_mic_len(sta);
	if (mic_len > left) {
		add_note(wt, MSG_INFO, "EAPOL-Key 1/4 from " MACSTR
			 " has a truncated MIC field", MAC2STR(src));
		return;
	}
	left -= mic_len;
	mic = (const u8 *) (hdr + 1);
	if (is_zero(hdr->key_nonce, WPA_NONCE_LEN)) {
		add_note(wt, MSG_INFO, "EAPOL-Key 1/4 from " MACSTR
			 " used zero nonce", MAC2STR(src));
	}
	if (!is_zero(hdr->key_rsc, 8)) {
		add_note(wt, MSG_INFO, "EAPOL-Key 1/4 from " MACSTR
			 " used non-zero Key RSC", MAC2STR(src));
	}
	os_memcpy(sta->anonce, hdr->key_nonce, WPA_NONCE_LEN);
	if (left < 2) {
		add_note(wt, MSG_INFO, "EAPOL-Key 1/4 from " MACSTR
			 " has a truncated Key Data Length field",
			 MAC2STR(src));
		return;
	}
	left -= 2;
	key_data = mic + mic_len + 2;
	key_data_len = WPA_GET_BE16(mic + mic_len);
	if (key_data_len > left) {
		add_note(wt, MSG_INFO, "EAPOL-Key 1/4 from " MACSTR
			 " has a truncated Key Data field",
			 MAC2STR(src));
		return;
	}

	if (wpa_parse_kde_ies(key_data, key_data_len, &ie) < 0) {
		add_note(wt, MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		return;
	}

	if (ie.mac_addr) {
		if (is_zero_ether_addr(bss->mld_mac_addr)) {
			wpa_printf(MSG_DEBUG,
				   "Learned AP MLD MAC Address from EAPOL-Key 1/4: "
				   MACSTR, MAC2STR(ie.mac_addr));
		} else if (!ether_addr_equal(bss->mld_mac_addr, ie.mac_addr)) {
			wpa_printf(MSG_DEBUG,
				   "Updated AP MLD MAC Address from EAPOL-Key 1/4: "
				   MACSTR " --> " MACSTR,
				   MAC2STR(bss->mld_mac_addr),
				   MAC2STR(ie.mac_addr));
		}
		os_memcpy(bss->mld_mac_addr, ie.mac_addr, ETH_ALEN);
	}
}


static int try_pmk(struct wlantest *wt, struct wlantest_bss *bss,
		   struct wlantest_sta *sta, u16 ver,
		   const u8 *data, size_t len,
		   struct wlantest_pmk *pmk)
{
	struct wpa_ptk ptk;
	const u8 *sa, *aa;
	bool mlo;
	size_t kdk_len;
	const u8 *rsnxe;
	size_t rsnxe_len;

	mlo = !is_zero_ether_addr(sta->mld_mac_addr) &&
		!is_zero_ether_addr(bss->mld_mac_addr);
	sa = mlo ? sta->mld_mac_addr : sta->addr;
	aa = mlo ? bss->mld_mac_addr : bss->bssid;

	if ((sta->rsn_selection == RSN_SELECTION_RSNE_OVERRIDE ||
	     sta->rsn_selection == RSN_SELECTION_RSNE_OVERRIDE_2) &&
	    bss->rsnxoe_len) {
		rsnxe = bss->rsnxoe;
		rsnxe_len = bss->rsnxoe_len;
	} else {
		rsnxe = bss->rsnxe;
		rsnxe_len = bss->rsnxe_len;
	}
	if (ieee802_11_rsnx_capab_len(rsnxe, rsnxe_len,
				      WLAN_RSNX_CAPAB_SECURE_LTF) &&
	    ieee802_11_rsnx_capab_len(sta->rsnxe, sta->rsnxe_len,
				      WLAN_RSNX_CAPAB_SECURE_LTF))
		kdk_len = WPA_KDK_MAX_LEN;
	else
		kdk_len = 0;

	if (wpa_key_mgmt_ft(sta->key_mgmt)) {
		u8 ptk_name[WPA_PMK_NAME_LEN];
		int use_sha384 = wpa_key_mgmt_sha384(sta->key_mgmt);

		if (wpa_derive_pmk_r0(pmk->pmk, pmk->pmk_len,
				      bss->ssid, bss->ssid_len, bss->mdid,
				      bss->r0kh_id, bss->r0kh_id_len,
				      sa, sta->pmk_r0, sta->pmk_r0_name,
				      sta->key_mgmt) < 0)
			return -1;
		if (wpa_key_mgmt_sae_ext_key(sta->key_mgmt))
			sta->pmk_r0_len = pmk->pmk_len;
		else
			sta->pmk_r0_len = use_sha384 ? PMK_LEN_SUITE_B_192 :
				PMK_LEN;
		if (wpa_derive_pmk_r1(sta->pmk_r0, sta->pmk_r0_len,
				      sta->pmk_r0_name,
				      bss->r1kh_id, sa,
				      sta->pmk_r1, sta->pmk_r1_name) < 0)
			return -1;
		sta->pmk_r1_len = sta->pmk_r0_len;
		if (wpa_pmk_r1_to_ptk(sta->pmk_r1, sta->pmk_r1_len,
				      sta->snonce, sta->anonce, sa,
				      aa, sta->pmk_r1_name,
				      &ptk, ptk_name, sta->key_mgmt,
				      sta->pairwise_cipher, kdk_len) < 0 ||
		    check_mic(sta, ptk.kck, ptk.kck_len, ver, data, len) < 0)
			return -1;
	} else if (wpa_pmk_to_ptk(pmk->pmk, pmk->pmk_len,
				  "Pairwise key expansion",
				  aa, sa, sta->anonce,
				  sta->snonce, &ptk, sta->key_mgmt,
				  sta->pairwise_cipher, NULL, 0, kdk_len) < 0 ||
		   check_mic(sta, ptk.kck, ptk.kck_len, ver, data, len) < 0) {
		return -1;
	}

	if (mlo) {
		wpa_printf(MSG_INFO, "Derived PTK for STA " MACSTR " (MLD "
			   MACSTR ") BSSID " MACSTR " (MLD " MACSTR ")",
			   MAC2STR(sta->addr), MAC2STR(sta->mld_mac_addr),
			   MAC2STR(bss->bssid), MAC2STR(bss->mld_mac_addr));
	} else {
		wpa_printf(MSG_INFO, "Derived PTK for STA " MACSTR
			   " BSSID " MACSTR,
			   MAC2STR(sta->addr), MAC2STR(bss->bssid));
	}
	sta->counters[WLANTEST_STA_COUNTER_PTK_LEARNED]++;
	if (sta->ptk_set) {
		/*
		 * Rekeying - use new PTK for EAPOL-Key frames, but continue
		 * using the old PTK for frame decryption.
		 */
		add_note(wt, MSG_DEBUG, "Derived PTK during rekeying");
		os_memcpy(&sta->tptk, &ptk, sizeof(ptk));
		wpa_hexdump(MSG_DEBUG, "TPTK:KCK",
			    sta->tptk.kck, sta->tptk.kck_len);
		wpa_hexdump(MSG_DEBUG, "TPTK:KEK",
			    sta->tptk.kek, sta->tptk.kek_len);
		wpa_hexdump(MSG_DEBUG, "TPTK:TK",
			    sta->tptk.tk, sta->tptk.tk_len);
		sta->tptk_set = 1;
		return 0;
	}
	sta_new_ptk(wt, sta, &ptk);
	return 0;
}


static void derive_ptk(struct wlantest *wt, struct wlantest_bss *bss,
		       struct wlantest_sta *sta, u16 ver,
		       const u8 *data, size_t len)
{
	struct wlantest_pmk *pmk;

	wpa_printf(MSG_DEBUG, "Trying to derive PTK for " MACSTR " (MLD " MACSTR
		   ") (ver %u)",
		   MAC2STR(sta->addr), MAC2STR(sta->mld_mac_addr), ver);
	dl_list_for_each(pmk, &bss->pmk, struct wlantest_pmk, list) {
		wpa_printf(MSG_DEBUG, "Try per-BSS PMK");
		if (try_pmk(wt, bss, sta, ver, data, len, pmk) == 0)
			return;
	}

	dl_list_for_each(pmk, &wt->pmk, struct wlantest_pmk, list) {
		wpa_printf(MSG_DEBUG, "Try global PMK");
		if (try_pmk(wt, bss, sta, ver, data, len, pmk) == 0)
			return;
	}

	if (!sta->ptk_set) {
		struct wlantest_ptk *ptk;
		int prev_level = wpa_debug_level;

		wpa_debug_level = MSG_WARNING;
		dl_list_for_each(ptk, &wt->ptk, struct wlantest_ptk, list) {
			if (check_mic(sta, ptk->ptk.kck, ptk->ptk.kck_len,
				      ver, data, len) < 0)
				continue;
			wpa_printf(MSG_INFO, "Pre-set PTK matches for STA "
				   MACSTR " BSSID " MACSTR,
				   MAC2STR(sta->addr), MAC2STR(bss->bssid));
			add_note(wt, MSG_DEBUG, "Using pre-set PTK");
			ptk->ptk_len = 32 +
				wpa_cipher_key_len(sta->pairwise_cipher);
			os_memcpy(&sta->ptk, &ptk->ptk, sizeof(ptk->ptk));
			wpa_hexdump(MSG_DEBUG, "PTK:KCK",
				    sta->ptk.kck, sta->ptk.kck_len);
			wpa_hexdump(MSG_DEBUG, "PTK:KEK",
				    sta->ptk.kek, sta->ptk.kek_len);
			wpa_hexdump(MSG_DEBUG, "PTK:TK",
				    sta->ptk.tk, sta->ptk.tk_len);
			sta->ptk_set = 1;
			os_memset(sta->rsc_tods, 0, sizeof(sta->rsc_tods));
			os_memset(sta->rsc_fromds, 0, sizeof(sta->rsc_fromds));
		}
		wpa_debug_level = prev_level;
	}

	add_note(wt, MSG_DEBUG, "No matching PMK found to derive PTK");
}


static void elems_from_eapol_ie(struct ieee802_11_elems *elems,
				struct wpa_eapol_ie_parse *ie)
{
	os_memset(elems, 0, sizeof(*elems));
	if (ie->wpa_ie) {
		elems->wpa_ie = ie->wpa_ie + 2;
		elems->wpa_ie_len = ie->wpa_ie_len - 2;
	}
	if (ie->rsn_ie) {
		elems->rsn_ie = ie->rsn_ie + 2;
		elems->rsn_ie_len = ie->rsn_ie_len - 2;
	}
}


static void rx_data_eapol_key_2_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *bssid,
				     const u8 *data, size_t len)
{
	struct wlantest_bss *bss, *bss_mld;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data, *kck, *mic;
	size_t kck_len, mic_len, left;
	u16 key_info, key_data_len;
	struct wpa_eapol_ie_parse ie;
	int link_id;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 2/4 " MACSTR " -> " MACSTR " (BSSID "
		   MACSTR ")",
		   MAC2STR(src), MAC2STR(dst), MAC2STR(bssid));
	if (ether_addr_equal(dst, bssid)) {
		bss = bss_get(wt, dst);
	} else {
		bss = bss_find(wt, bssid);
		bss_mld = bss_find(wt, dst);
		if (bss_mld && (!bss || sta_find(bss_mld, src)))
			bss = bss_get(wt, dst);
		else
			bss = bss_get(wt, bssid);
	}
	if (bss == NULL)
		return;
	sta = sta_get(bss, src);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	left = len - sizeof(*hdr);
	mic_len = determine_mic_len(sta);
	if (mic_len > left) {
		add_note(wt, MSG_INFO, "EAPOL-Key 2/4 from " MACSTR
			 " has a truncated MIC field", MAC2STR(src));
		return;
	}
	left -= mic_len;
	mic = (const u8 *) (hdr + 1);
	if (!is_zero(hdr->key_rsc, 8)) {
		add_note(wt, MSG_INFO, "EAPOL-Key 2/4 from " MACSTR
			 " used non-zero Key RSC", MAC2STR(src));
	}
	os_memcpy(sta->snonce, hdr->key_nonce, WPA_NONCE_LEN);
	key_info = WPA_GET_BE16(hdr->key_info);
	if (left < 2) {
		add_note(wt, MSG_INFO, "EAPOL-Key 2/4 from " MACSTR
			 " has a truncated Key Data Length field",
			 MAC2STR(src));
		return;
	}
	left -= 2;
	key_data = mic + mic_len + 2;
	key_data_len = WPA_GET_BE16(mic + mic_len);
	if (key_data_len > left) {
		add_note(wt, MSG_INFO, "EAPOL-Key 2/4 from " MACSTR
			 " has a truncated Key Data field",
			 MAC2STR(src));
		return;
	}

	if (wpa_parse_kde_ies(key_data, key_data_len, &ie) < 0) {
		add_note(wt, MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		return;
	}

	if (!sta->assocreq_seen) {
		struct ieee802_11_elems elems;

		elems_from_eapol_ie(&elems, &ie);
		wpa_printf(MSG_DEBUG,
			   "Update STA data based on IEs in EAPOL-Key 2/4");
		sta_update_assoc(sta, &elems);
	}

	if (ie.mac_addr) {
		if (is_zero_ether_addr(sta->mld_mac_addr)) {
			wpa_printf(MSG_DEBUG,
				   "Learned non-AP STA MLD MAC Address from EAPOL-Key 2/4: "
				   MACSTR, MAC2STR(ie.mac_addr));
		} else {
			wpa_printf(MSG_DEBUG,
				   "Updated non-AP STA MLD MAC Address from EAPOL-Key 2/4: "
				   MACSTR " --> " MACSTR,
				   MAC2STR(sta->mld_mac_addr),
				   MAC2STR(ie.mac_addr));
		}
		os_memcpy(sta->mld_mac_addr, ie.mac_addr, ETH_ALEN);
	}

	derive_ptk(wt, bss, sta, key_info & WPA_KEY_INFO_TYPE_MASK, data, len);

	if (!sta->ptk_set && !sta->tptk_set) {
		add_note(wt, MSG_DEBUG,
			 "No PTK known to process EAPOL-Key 2/4");
		return;
	}

	kck = sta->ptk.kck;
	kck_len = sta->ptk.kck_len;
	if (sta->tptk_set) {
		add_note(wt, MSG_DEBUG,
			 "Use TPTK for validation EAPOL-Key MIC");
		kck = sta->tptk.kck;
		kck_len = sta->tptk.kck_len;
	}
	if (check_mic(sta, kck, kck_len,
		      key_info & WPA_KEY_INFO_TYPE_MASK, data, len) < 0) {
		add_note(wt, MSG_INFO, "Mismatch in EAPOL-Key 2/4 MIC");
		return;
	}
	add_note(wt, MSG_DEBUG, "Valid MIC found in EAPOL-Key 2/4");

	if (ie.wpa_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - WPA IE",
			    ie.wpa_ie, ie.wpa_ie_len);
		if (os_memcmp(ie.wpa_ie, sta->rsnie, ie.wpa_ie_len) != 0) {
			add_note(wt, MSG_INFO,
				 "Mismatch in WPA IE between EAPOL-Key 2/4 "
				 "and (Re)Association Request from " MACSTR,
				 MAC2STR(sta->addr));
			wpa_hexdump(MSG_INFO, "WPA IE in EAPOL-Key",
				    ie.wpa_ie, ie.wpa_ie_len);
			wpa_hexdump(MSG_INFO, "WPA IE in (Re)Association "
				    "Request",
				    sta->rsnie,
				    sta->rsnie[0] ? 2 + sta->rsnie[1] : 0);
		}
	}

	if (ie.rsn_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - RSN IE",
			    ie.rsn_ie, ie.rsn_ie_len);
		if (os_memcmp(ie.rsn_ie, sta->rsnie, ie.rsn_ie_len) != 0) {
			add_note(wt, MSG_INFO,
				 "Mismatch in RSN IE between EAPOL-Key 2/4 "
				 "and (Re)Association Request from " MACSTR,
				 MAC2STR(sta->addr));
			wpa_hexdump(MSG_INFO, "RSN IE in EAPOL-Key",
				    ie.rsn_ie, ie.rsn_ie_len);
			wpa_hexdump(MSG_INFO, "RSN IE in (Re)Association "
				    "Request",
				    sta->rsnie,
				    sta->rsnie[0] ? 2 + sta->rsnie[1] : 0);
		}
	}

	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		const u8 *addr;

		if (!ie.mlo_link[link_id])
			continue;
		addr = &ie.mlo_link[link_id][RSN_MLO_LINK_KDE_LINK_MAC_INDEX];
		wpa_printf(MSG_DEBUG,
			   "Learned Link ID %u MAC address " MACSTR
			   " from EAPOL-Key 2/4",
			   link_id, MAC2STR(addr));
		os_memcpy(sta->link_addr[link_id], addr, ETH_ALEN);
	}
}


static u8 * decrypt_eapol_key_data_rc4(struct wlantest *wt, const u8 *kek,
				       const struct wpa_eapol_key *hdr,
				       const u8 *keydata, u16 keydatalen,
				       size_t *len)
{
	u8 ek[32], *buf;

	buf = os_memdup(keydata, keydatalen);
	if (buf == NULL)
		return NULL;

	os_memcpy(ek, hdr->key_iv, 16);
	os_memcpy(ek + 16, kek, 16);
	if (rc4_skip(ek, 32, 256, buf, keydatalen)) {
		add_note(wt, MSG_INFO, "RC4 failed");
		os_free(buf);
		return NULL;
	}

	*len = keydatalen;
	return buf;
}


static u8 * decrypt_eapol_key_data_aes(struct wlantest *wt, const u8 *kek,
				       size_t kek_len,
				       const struct wpa_eapol_key *hdr,
				       const u8 *keydata, u16 keydatalen,
				       size_t *len)
{
	u8 *buf;

	if (keydatalen % 8) {
		add_note(wt, MSG_INFO, "Unsupported AES-WRAP len %d",
			 keydatalen);
		return NULL;
	}
	keydatalen -= 8; /* AES-WRAP adds 8 bytes */
	buf = os_malloc(keydatalen);
	if (buf == NULL)
		return NULL;
	if (aes_unwrap(kek, kek_len, keydatalen / 8, keydata, buf)) {
		os_free(buf);
		add_note(wt, MSG_INFO,
			 "AES unwrap failed - could not decrypt EAPOL-Key "
			 "key data");
		return NULL;
	}

	*len = keydatalen;
	return buf;
}


static u8 * decrypt_eapol_key_data(struct wlantest *wt,
				   struct wlantest_sta *sta, const u8 *kek,
				   size_t kek_len, u16 ver,
				   const struct wpa_eapol_key *hdr,
				   const u8 *end, size_t *len)
{
	size_t mic_len;
	u16 keydatalen;
	const u8 *mic, *keydata;

	mic = (const u8 *) (hdr + 1);
	mic_len = determine_mic_len(sta);
	if (mic_len + 2 > end - mic)
		return NULL;
	keydata = mic + mic_len + 2;
	keydatalen = WPA_GET_BE16(mic + mic_len);
	if (keydatalen > end - keydata)
		return NULL;

	switch (ver) {
	case WPA_KEY_INFO_TYPE_HMAC_MD5_RC4:
		if (kek_len != 16)
			return NULL;
		return decrypt_eapol_key_data_rc4(wt, kek, hdr, keydata,
						  keydatalen, len);
	case WPA_KEY_INFO_TYPE_HMAC_SHA1_AES:
	case WPA_KEY_INFO_TYPE_AES_128_CMAC:
		return decrypt_eapol_key_data_aes(wt, kek, kek_len, hdr,
						  keydata, keydatalen, len);
	case WPA_KEY_INFO_TYPE_AKM_DEFINED:
		return decrypt_eapol_key_data_aes(wt, kek, kek_len, hdr,
						  keydata, keydatalen, len);
	default:
		add_note(wt, MSG_INFO,
			 "Unsupported EAPOL-Key Key Descriptor Version %u",
			 ver);
		return NULL;
	}
}


static void learn_kde_keys_mlo(struct wlantest *wt, struct wlantest_bss *bss,
			       struct wlantest_sta *sta, int link_id,
			       struct wpa_eapol_ie_parse *ie)
{
	const u8 *key, *pn;
	size_t key_len;
	unsigned int key_id;
	bool tx;

	if (ie->mlo_gtk[link_id]) {
		pn = ie->mlo_gtk[link_id] + 1;
		key = ie->mlo_gtk[link_id] + RSN_MLO_GTK_KDE_PREFIX_LENGTH;
		key_len = ie->mlo_gtk_len[link_id] -
			RSN_MLO_GTK_KDE_PREFIX_LENGTH;
		key_id = ie->mlo_gtk[link_id][0] &
			RSN_MLO_GTK_KDE_PREFIX0_KEY_ID_MASK;
		tx = ie->mlo_gtk[link_id][0] & RSN_MLO_GTK_KDE_PREFIX0_TX;
		if (key_len <= WPA_GTK_MAX_LEN) {
			add_note(wt, MSG_DEBUG, "GTK KeyID=%u tx=%u",
				 key_id, tx);
			if (ie->mlo_gtk[link_id][0] & BIT(3)) {
				add_note(wt, MSG_INFO,
					 "MLO GTK KDE: Reserved field set");
			}
			wpa_hexdump(MSG_DEBUG, "GTK", key, key_len);
			bss->gtk_len[key_id] = key_len;
			if (sta)
				sta->gtk_len = key_len;
			os_memcpy(bss->gtk[key_id], key, key_len);
			if (sta)
				os_memcpy(sta->gtk, key, key_len);
			bss->rsc[key_id][0] = pn[5];
			bss->rsc[key_id][1] = pn[4];
			bss->rsc[key_id][2] = pn[3];
			bss->rsc[key_id][3] = pn[2];
			bss->rsc[key_id][4] = pn[1];
			bss->rsc[key_id][5] = pn[0];
			bss->gtk_idx = key_id;
			if (sta)
				sta->gtk_idx = key_id;
			wpa_hexdump(MSG_DEBUG, "RSC", bss->rsc[key_id], 6);
		} else {
			add_note(wt, MSG_INFO,
				 "Invalid MLO GTK KDE key length %zu",
				 key_len);
		}
	}

	if (ie->mlo_igtk[link_id]) {
		pn = ie->mlo_igtk[link_id] + 2;
		key = ie->mlo_igtk[link_id] + RSN_MLO_IGTK_KDE_PREFIX_LENGTH;
		key_len = ie->mlo_igtk_len[link_id] -
			RSN_MLO_IGTK_KDE_PREFIX_LENGTH;
		key_id = WPA_GET_LE16(ie->mlo_igtk[link_id]);
		if (key_len <= WPA_IGTK_MAX_LEN && key_id >= 4 && key_id <= 5) {
			add_note(wt, MSG_DEBUG, "IGTK KeyID=%u", key_id);
			if (ie->mlo_igtk[link_id][2 + 6] & 0x0f) {
				add_note(wt, MSG_INFO,
					 "MLO IGTK KDE: Reserved field set");
			}
			wpa_hexdump(MSG_DEBUG, "IGTK", key, key_len);
			wpa_hexdump(MSG_DEBUG, "IPN", pn, 6);
			bss->igtk_len[key_id] = key_len;
			os_memcpy(bss->igtk[key_id], key, key_len);
			bss->ipn[key_id] = WPA_GET_LE48(pn);
			bss->igtk_idx = key_id;
		} else {
			add_note(wt, MSG_INFO,
				 "Invalid MLO IGTK KDE ID %u or key length %zu",
				 key_id, key_len);
		}
	}

	if (ie->mlo_bigtk[link_id]) {
		pn = ie->mlo_bigtk[link_id] + 2;
		key = ie->mlo_bigtk[link_id] + RSN_MLO_BIGTK_KDE_PREFIX_LENGTH;
		key_len = ie->mlo_bigtk_len[link_id] -
			RSN_MLO_BIGTK_KDE_PREFIX_LENGTH;
		key_id = WPA_GET_LE16(ie->mlo_bigtk[link_id]);
		if (key_len <= WPA_BIGTK_MAX_LEN &&
		    key_id >= 6 && key_id <= 7) {
			add_note(wt, MSG_DEBUG, "BIGTK KeyID=%u", key_id);
			if (ie->mlo_bigtk[link_id][2 + 6] & 0x0f) {
				add_note(wt, MSG_INFO,
					 "MLO BIGTK KDE: Reserved field set");
			}
			wpa_hexdump(MSG_DEBUG, "BIGTK", key, key_len);
			wpa_hexdump(MSG_DEBUG, "BIPN", pn, 6);
			bss->igtk_len[key_id] = key_len;
			os_memcpy(bss->igtk[key_id], key, key_len);
			bss->ipn[key_id] = WPA_GET_LE48(pn);
			bss->bigtk_idx = key_id;
		} else {
			add_note(wt, MSG_INFO,
				 "Invalid MLO IGTK KDE ID %u or key length %zu",
				 key_id, key_len);
		}
	}
}


static void learn_kde_keys(struct wlantest *wt, struct wlantest_bss *bss,
			   struct wlantest_sta *sta,
			   const u8 *buf, size_t len, const u8 *rsc)
{
	struct wpa_eapol_ie_parse ie;
	int link_id;

	if (wpa_parse_kde_ies(buf, len, &ie) < 0) {
		add_note(wt, MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		return;
	}

	if (ie.wpa_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - WPA IE",
			    ie.wpa_ie, ie.wpa_ie_len);
	}

	if (ie.rsn_ie) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - RSN IE",
			    ie.rsn_ie, ie.rsn_ie_len);
	}

	if (ie.key_id)
		add_note(wt, MSG_DEBUG, "KeyID %u", ie.key_id[0]);

	if (ie.gtk) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - GTK KDE",
			    ie.gtk, ie.gtk_len);
		if (ie.gtk_len >= 2 && ie.gtk_len <= 2 + 32) {
			int id;
			id = ie.gtk[0] & 0x03;
			add_note(wt, MSG_DEBUG, "GTK KeyID=%u tx=%u",
				 id, !!(ie.gtk[0] & 0x04));
			if ((ie.gtk[0] & 0xf8) || ie.gtk[1]) {
				add_note(wt, MSG_INFO,
					 "GTK KDE: Reserved field set: "
					 "%02x %02x", ie.gtk[0], ie.gtk[1]);
			}
			wpa_hexdump(MSG_DEBUG, "GTK", ie.gtk + 2,
				    ie.gtk_len - 2);
			bss->gtk_len[id] = ie.gtk_len - 2;
			sta->gtk_len = ie.gtk_len - 2;
			os_memcpy(bss->gtk[id], ie.gtk + 2, ie.gtk_len - 2);
			os_memcpy(sta->gtk, ie.gtk + 2, ie.gtk_len - 2);
			bss->rsc[id][0] = rsc[5];
			bss->rsc[id][1] = rsc[4];
			bss->rsc[id][2] = rsc[3];
			bss->rsc[id][3] = rsc[2];
			bss->rsc[id][4] = rsc[1];
			bss->rsc[id][5] = rsc[0];
			bss->gtk_idx = id;
			sta->gtk_idx = id;
			wpa_hexdump(MSG_DEBUG, "RSC", bss->rsc[id], 6);
		} else {
			add_note(wt, MSG_INFO, "Invalid GTK KDE length %u",
				 (unsigned) ie.gtk_len);
		}
	}

	if (ie.igtk) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - IGTK KDE",
			    ie.igtk, ie.igtk_len);
		if (ie.igtk_len == 24) {
			u16 id;
			id = WPA_GET_LE16(ie.igtk);
			if (id > 5) {
				add_note(wt, MSG_INFO,
					 "Unexpected IGTK KeyID %u", id);
			} else {
				const u8 *ipn;
				add_note(wt, MSG_DEBUG, "IGTK KeyID %u", id);
				wpa_hexdump(MSG_DEBUG, "IPN", ie.igtk + 2, 6);
				wpa_hexdump(MSG_DEBUG, "IGTK", ie.igtk + 8,
					    16);
				os_memcpy(bss->igtk[id], ie.igtk + 8, 16);
				bss->igtk_len[id] = 16;
				ipn = ie.igtk + 2;
				bss->ipn[id] = WPA_GET_LE48(ipn);
				bss->igtk_idx = id;
			}
		} else if (ie.igtk_len == 40) {
			u16 id;
			id = WPA_GET_LE16(ie.igtk);
			if (id > 5) {
				add_note(wt, MSG_INFO,
					 "Unexpected IGTK KeyID %u", id);
			} else {
				const u8 *ipn;
				add_note(wt, MSG_DEBUG, "IGTK KeyID %u", id);
				wpa_hexdump(MSG_DEBUG, "IPN", ie.igtk + 2, 6);
				wpa_hexdump(MSG_DEBUG, "IGTK", ie.igtk + 8,
					    32);
				os_memcpy(bss->igtk[id], ie.igtk + 8, 32);
				bss->igtk_len[id] = 32;
				ipn = ie.igtk + 2;
				bss->ipn[id] = WPA_GET_LE48(ipn);
				bss->igtk_idx = id;
			}
		} else {
			add_note(wt, MSG_INFO, "Invalid IGTK KDE length %u",
				 (unsigned) ie.igtk_len);
		}
	}

	if (ie.bigtk) {
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data - BIGTK KDE",
			    ie.bigtk, ie.bigtk_len);
		if (ie.bigtk_len == 24) {
			u16 id;

			id = WPA_GET_LE16(ie.bigtk);
			if (id < 6 || id > 7) {
				add_note(wt, MSG_INFO,
					 "Unexpected BIGTK KeyID %u", id);
			} else {
				const u8 *ipn;

				add_note(wt, MSG_DEBUG, "BIGTK KeyID %u", id);
				wpa_hexdump(MSG_DEBUG, "BIPN", ie.bigtk + 2, 6);
				wpa_hexdump(MSG_DEBUG, "BIGTK", ie.bigtk + 8,
					    16);
				os_memcpy(bss->igtk[id], ie.bigtk + 8, 16);
				bss->igtk_len[id] = 16;
				ipn = ie.bigtk + 2;
				bss->ipn[id] = WPA_GET_LE48(ipn);
				bss->bigtk_idx = id;
			}
		} else if (ie.bigtk_len == 40) {
			u16 id;

			id = WPA_GET_LE16(ie.bigtk);
			if (id < 6 || id > 7) {
				add_note(wt, MSG_INFO,
					 "Unexpected BIGTK KeyID %u", id);
			} else {
				const u8 *ipn;

				add_note(wt, MSG_DEBUG, "BIGTK KeyID %u", id);
				wpa_hexdump(MSG_DEBUG, "BIPN", ie.bigtk + 2, 6);
				wpa_hexdump(MSG_DEBUG, "BIGTK", ie.bigtk + 8,
					    32);
				os_memcpy(bss->igtk[id], ie.bigtk + 8, 32);
				bss->igtk_len[id] = 32;
				ipn = ie.bigtk + 2;
				bss->ipn[id] = WPA_GET_LE48(ipn);
				bss->bigtk_idx = id;
			}
		} else {
			add_note(wt, MSG_INFO, "Invalid BIGTK KDE length %u",
				 (unsigned) ie.bigtk_len);
		}
	}

	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		const u8 *addr;

		if (!ie.mlo_link[link_id])
			continue;
		addr = &ie.mlo_link[link_id][RSN_MLO_LINK_KDE_LINK_MAC_INDEX];
		if (ether_addr_equal(addr, bss->bssid)) {
			wpa_printf(MSG_DEBUG,
				   "Trying to learn keys for the current MLO link (ID %u)",
				   link_id);
			learn_kde_keys_mlo(wt, bss, sta, link_id, &ie);
		} else {
			struct wlantest_bss *obss;

			wpa_printf(MSG_DEBUG,
				   "Trying to learn keys for another MLO link (ID %u addr " MACSTR ")",
				   link_id, MAC2STR(addr));
			obss = bss_get(wt, addr);
			if (!obss) {
				wpa_printf(MSG_DEBUG,
					   "No BSS entry for the other BSS found");
				continue;
			}
			learn_kde_keys_mlo(wt, obss, NULL, link_id, &ie);
		}
	}
}


static void rx_data_eapol_key_3_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *bssid,
				     const u8 *data, size_t len)
{
	struct wlantest_bss *bss, *bss_mld;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data, *kck, *kek, *mic;
	size_t kck_len, kek_len, mic_len;
	int recalc = 0;
	u16 key_info, ver;
	u8 *decrypted_buf = NULL;
	const u8 *decrypted;
	size_t decrypted_len = 0;
	struct wpa_eapol_ie_parse ie;
	struct wpa_ie_data rsn;
	const u8 *rsne;
	size_t rsne_len;
	int link_id;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 3/4 " MACSTR " -> " MACSTR " (BSSID "
		   MACSTR ")",
		   MAC2STR(src), MAC2STR(dst), MAC2STR(bssid));
	if (ether_addr_equal(src, bssid)) {
		bss = bss_get(wt, src);
	} else {
		bss = bss_find(wt, bssid);
		bss_mld = bss_find(wt, src);
		if (bss_mld && (!bss || sta_find(bss_mld, src)))
			bss = bss_get(wt, src);
		else
			bss = bss_get(wt, bssid);
	}
	if (bss == NULL)
		return;
	sta = sta_get(bss, dst);
	if (sta == NULL)
		return;
	mic_len = determine_mic_len(sta);

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	mic = (const u8 *) (hdr + 1);
	key_info = WPA_GET_BE16(hdr->key_info);

	if (os_memcmp(sta->anonce, hdr->key_nonce, WPA_NONCE_LEN) != 0) {
		add_note(wt, MSG_INFO,
			 "EAPOL-Key ANonce mismatch between 1/4 and 3/4");
		recalc = 1;
	}
	os_memcpy(sta->anonce, hdr->key_nonce, WPA_NONCE_LEN);
	if (recalc) {
		derive_ptk(wt, bss, sta, key_info & WPA_KEY_INFO_TYPE_MASK,
			   data, len);
	}

	if (!sta->ptk_set && !sta->tptk_set) {
		add_note(wt, MSG_DEBUG,
			 "No PTK known to process EAPOL-Key 3/4");
		return;
	}

	kek = sta->ptk.kek;
	kek_len = sta->ptk.kek_len;
	kck = sta->ptk.kck;
	kck_len = sta->ptk.kck_len;
	if (sta->tptk_set) {
		add_note(wt, MSG_DEBUG,
			 "Use TPTK for validation EAPOL-Key MIC");
		kck = sta->tptk.kck;
		kck_len = sta->tptk.kck_len;
		kek = sta->tptk.kek;
		kek_len = sta->tptk.kek_len;
	}
	if (check_mic(sta, kck, kck_len,
		      key_info & WPA_KEY_INFO_TYPE_MASK, data, len) < 0) {
		add_note(wt, MSG_INFO, "Mismatch in EAPOL-Key 3/4 MIC");
		return;
	}
	add_note(wt, MSG_DEBUG, "Valid MIC found in EAPOL-Key 3/4");

	key_data = mic + mic_len + 2;
	if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		if (sta->proto & WPA_PROTO_RSN)
			add_note(wt, MSG_INFO,
				 "EAPOL-Key 3/4 without EncrKeyData bit");
		decrypted = key_data;
		decrypted_len = WPA_GET_BE16(mic + mic_len);
	} else {
		ver = key_info & WPA_KEY_INFO_TYPE_MASK;
		decrypted_buf = decrypt_eapol_key_data(wt, sta,
						       kek, kek_len, ver,
						       hdr, data + len,
						       &decrypted_len);
		if (decrypted_buf == NULL) {
			add_note(wt, MSG_INFO,
				 "Failed to decrypt EAPOL-Key Key Data");
			return;
		}
		decrypted = decrypted_buf;
		wpa_hexdump(MSG_DEBUG, "Decrypted EAPOL-Key Key Data",
			    decrypted, decrypted_len);
	}
	if ((wt->write_pcap_dumper || wt->pcapng) && decrypted != key_data) {
		/* Fill in a stub Data frame header */
		u8 buf[24 + 8 + sizeof(*eapol) + sizeof(*hdr) + 64];
		struct ieee80211_hdr *h;
		struct wpa_eapol_key *k;
		const u8 *p;
		u8 *pos;
		size_t plain_len;

		plain_len = decrypted_len;
		p = decrypted;
		while (p + 1 < decrypted + decrypted_len) {
			if (p[0] == 0xdd && p[1] == 0x00) {
				/* Remove padding */
				plain_len = p - decrypted;
				p = NULL;
				break;
			}
			p += 2 + p[1];
		}
		if (p && p > decrypted && p + 1 == decrypted + decrypted_len &&
		    *p == 0xdd) {
			/* Remove padding */
			plain_len = p - decrypted;
		}

		os_memset(buf, 0, sizeof(buf));
		h = (struct ieee80211_hdr *) buf;
		h->frame_control = host_to_le16(0x0208);
		os_memcpy(h->addr1, dst, ETH_ALEN);
		os_memcpy(h->addr2, src, ETH_ALEN);
		os_memcpy(h->addr3, src, ETH_ALEN);
		pos = (u8 *) (h + 1);
		os_memcpy(pos, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
		pos += 8;
		os_memcpy(pos, eapol, sizeof(*eapol));
		pos += sizeof(*eapol);
		os_memcpy(pos, hdr, sizeof(*hdr) + mic_len);
		k = (struct wpa_eapol_key *) pos;
		pos += sizeof(struct wpa_eapol_key) + mic_len;
		WPA_PUT_BE16(k->key_info,
			     key_info & ~WPA_KEY_INFO_ENCR_KEY_DATA);
		WPA_PUT_BE16(pos, plain_len);
		write_pcap_decrypted(wt, buf, 24 + 8 + sizeof(*eapol) +
				     sizeof(*hdr) + mic_len + 2,
				     decrypted, plain_len);
	}

	if (wpa_parse_kde_ies(decrypted, decrypted_len, &ie) < 0) {
		add_note(wt, MSG_INFO, "Failed to parse EAPOL-Key Key Data");
		os_free(decrypted_buf);
		return;
	}

	if (!bss->ies_set) {
		struct ieee802_11_elems elems;

		elems_from_eapol_ie(&elems, &ie);
		wpa_printf(MSG_DEBUG,
			   "Update BSS data based on IEs in EAPOL-Key 3/4");
		bss_update(wt, bss, &elems, 0);
	}

	if ((ie.wpa_ie &&
	     os_memcmp(ie.wpa_ie, bss->wpaie, ie.wpa_ie_len) != 0) ||
	    (ie.wpa_ie == NULL && bss->wpaie[0])) {
		add_note(wt, MSG_INFO,
			 "Mismatch in WPA IE between EAPOL-Key 3/4 and "
			 "Beacon/Probe Response from " MACSTR,
			 MAC2STR(bss->bssid));
		wpa_hexdump(MSG_INFO, "WPA IE in EAPOL-Key",
			    ie.wpa_ie, ie.wpa_ie_len);
		wpa_hexdump(MSG_INFO, "WPA IE in Beacon/Probe "
			    "Response",
			    bss->wpaie,
			    bss->wpaie[0] ? 2 + bss->wpaie[1] : 0);
	}

	rsne = ie.rsn_ie;
	rsne_len = ie.rsn_ie_len;
	for (link_id = 0; !rsne && link_id < MAX_NUM_MLD_LINKS; link_id++) {
		const u8 *addr, *pos, *end;

		if (!ie.mlo_link[link_id])
			continue;
		addr = &ie.mlo_link[link_id][RSN_MLO_LINK_KDE_LINK_MAC_INDEX];
		if (!ether_addr_equal(addr, bss->bssid))
			continue;
		if (!(ie.mlo_link[link_id][0] & RSN_MLO_LINK_KDE_LI_RSNE_INFO))
			continue;
		pos = ie.mlo_link[link_id] + RSN_MLO_LINK_KDE_FIXED_LENGTH;
		end = ie.mlo_link[link_id] + ie.mlo_link_len[link_id];
		if (end - pos < 2 || pos[0] != WLAN_EID_RSN ||
		    end - pos < 2 + pos[1]) {
			add_note(wt, MSG_INFO, "Invalid MLO Link KDE from "
				 MACSTR " - RSNE info missing",
				 MAC2STR(bss->bssid));
			break;
		}
		wpa_printf(MSG_DEBUG,
			   "Using RSNE from MLO Link KDE for Link ID %u",
			   link_id);
		rsne = pos;
		rsne_len = 2 + pos[1];
		break;
	}

	if ((rsne &&
	     wpa_compare_rsn_ie(wpa_key_mgmt_ft(sta->key_mgmt),
				rsne, rsne_len,
				bss->rsnie, 2 + bss->rsnie[1])) ||
	    (!rsne && bss->rsnie[0])) {
		add_note(wt, MSG_INFO, "Mismatch in RSN IE between EAPOL-Key "
			 "3/4 and Beacon/Probe Response from " MACSTR,
			 MAC2STR(bss->bssid));
		wpa_hexdump(MSG_INFO, "RSN IE in EAPOL-Key",
			    rsne, rsne_len);
		wpa_hexdump(MSG_INFO, "RSN IE in Beacon/Probe Response",
			    bss->rsnie,
			    bss->rsnie[0] ? 2 + bss->rsnie[1] : 0);
	}

	if (wpa_key_mgmt_ft(sta->key_mgmt) &&
	    (wpa_parse_wpa_ie_rsn(rsne, rsne_len, &rsn) < 0 ||
	     rsn.num_pmkid != 1 || !rsn.pmkid ||
	     os_memcmp_const(rsn.pmkid, sta->pmk_r1_name,
			     WPA_PMK_NAME_LEN) != 0))
		add_note(wt, MSG_INFO,
			 "FT: No matching PMKR1Name in FT 4-way handshake message 3/4");

	/* TODO: validate MDE and FTE match */

	learn_kde_keys(wt, bss, sta, decrypted, decrypted_len, hdr->key_rsc);
	os_free(decrypted_buf);
}


static void rx_data_eapol_key_4_of_4(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *bssid,
				     const u8 *data, size_t len)
{
	struct wlantest_bss *bss, *bss_mld;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	u16 key_info;
	const u8 *kck;
	size_t kck_len;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 4/4 " MACSTR " -> " MACSTR " (BSSID "
		   MACSTR ")",
		   MAC2STR(src), MAC2STR(dst), MAC2STR(bssid));
	if (ether_addr_equal(dst, bssid)) {
		bss = bss_get(wt, dst);
	} else {
		bss = bss_find(wt, bssid);
		bss_mld = bss_find(wt, dst);
		if (bss_mld && (!bss || sta_find(bss_mld, src)))
			bss = bss_get(wt, dst);
		else
			bss = bss_get(wt, bssid);
	}
	if (bss == NULL)
		return;
	sta = sta_get(bss, src);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	if (!is_zero(hdr->key_rsc, 8)) {
		add_note(wt, MSG_INFO, "EAPOL-Key 4/4 from " MACSTR " used "
			 "non-zero Key RSC", MAC2STR(src));
	}
	key_info = WPA_GET_BE16(hdr->key_info);

	if (!sta->ptk_set && !sta->tptk_set) {
		add_note(wt, MSG_DEBUG,
			 "No PTK known to process EAPOL-Key 4/4");
		return;
	}

	kck = sta->ptk.kck;
	kck_len = sta->ptk.kck_len;
	if (sta->tptk_set) {
		add_note(wt, MSG_DEBUG,
			 "Use TPTK for validation EAPOL-Key MIC");
		kck = sta->tptk.kck;
		kck_len = sta->tptk.kck_len;
	}
	if (check_mic(sta, kck, kck_len,
		      key_info & WPA_KEY_INFO_TYPE_MASK, data, len) < 0) {
		add_note(wt, MSG_INFO, "Mismatch in EAPOL-Key 4/4 MIC");
		return;
	}
	add_note(wt, MSG_DEBUG, "Valid MIC found in EAPOL-Key 4/4");
	if (sta->tptk_set) {
		add_note(wt, MSG_DEBUG, "Update PTK (rekeying)");
		os_memcpy(&sta->ptk, &sta->tptk, sizeof(sta->ptk));
		sta->ptk_set = 1;
		sta->tptk_set = 0;
		os_memset(sta->rsc_tods, 0, sizeof(sta->rsc_tods));
		os_memset(sta->rsc_fromds, 0, sizeof(sta->rsc_fromds));
	}
}


static void rx_data_eapol_key_1_of_2(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *bssid,
				     const u8 *data, size_t len)
{
	struct wlantest_bss *bss, *bss_mld;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	u16 key_info, ver;
	u8 *decrypted;
	size_t decrypted_len = 0;
	size_t mic_len;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 1/2 " MACSTR " -> " MACSTR " (BSSID "
		   MACSTR ")",
		   MAC2STR(src), MAC2STR(dst), MAC2STR(bssid));
	if (ether_addr_equal(src, bssid)) {
		bss = bss_get(wt, src);
	} else {
		bss = bss_find(wt, bssid);
		bss_mld = bss_find(wt, src);
		if (bss_mld && (!bss || sta_find(bss_mld, src)))
			bss = bss_get(wt, src);
		else
			bss = bss_get(wt, bssid);
	}
	if (bss == NULL)
		return;
	sta = sta_get(bss, dst);
	if (sta == NULL)
		return;
	mic_len = determine_mic_len(sta);

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	key_info = WPA_GET_BE16(hdr->key_info);

	if (!sta->ptk_set) {
		add_note(wt, MSG_DEBUG,
			 "No PTK known to process EAPOL-Key 1/2");
		return;
	}

	if (sta->ptk_set &&
	    check_mic(sta, sta->ptk.kck, sta->ptk.kck_len,
		      key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		add_note(wt, MSG_INFO, "Mismatch in EAPOL-Key 1/2 MIC");
		return;
	}
	add_note(wt, MSG_DEBUG, "Valid MIC found in EAPOL-Key 1/2");

	if (sta->proto & WPA_PROTO_RSN &&
	    !(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		add_note(wt, MSG_INFO, "EAPOL-Key 1/2 without EncrKeyData bit");
		return;
	}
	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	decrypted = decrypt_eapol_key_data(wt, sta,
					   sta->ptk.kek, sta->ptk.kek_len,
					   ver, hdr, data + len,
					   &decrypted_len);
	if (decrypted == NULL) {
		add_note(wt, MSG_INFO, "Failed to decrypt EAPOL-Key Key Data");
		return;
	}
	wpa_hexdump(MSG_DEBUG, "Decrypted EAPOL-Key Key Data",
		    decrypted, decrypted_len);
	if (wt->write_pcap_dumper || wt->pcapng) {
		/* Fill in a stub Data frame header */
		u8 buf[24 + 8 + sizeof(*eapol) + sizeof(*hdr) + 64];
		struct ieee80211_hdr *h;
		struct wpa_eapol_key *k;
		u8 *pos;
		size_t plain_len;

		plain_len = decrypted_len;
		pos = decrypted;
		while (pos + 1 < decrypted + decrypted_len) {
			if (pos[0] == 0xdd && pos[1] == 0x00) {
				/* Remove padding */
				plain_len = pos - decrypted;
				break;
			}
			pos += 2 + pos[1];
		}

		os_memset(buf, 0, sizeof(buf));
		h = (struct ieee80211_hdr *) buf;
		h->frame_control = host_to_le16(0x0208);
		os_memcpy(h->addr1, dst, ETH_ALEN);
		os_memcpy(h->addr2, src, ETH_ALEN);
		os_memcpy(h->addr3, src, ETH_ALEN);
		pos = (u8 *) (h + 1);
		os_memcpy(pos, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
		pos += 8;
		os_memcpy(pos, eapol, sizeof(*eapol));
		pos += sizeof(*eapol);
		os_memcpy(pos, hdr, sizeof(*hdr) + mic_len);
		k = (struct wpa_eapol_key *) pos;
		pos += sizeof(struct wpa_eapol_key) + mic_len;
		WPA_PUT_BE16(k->key_info,
			     key_info & ~WPA_KEY_INFO_ENCR_KEY_DATA);
		WPA_PUT_BE16(pos, plain_len);
		write_pcap_decrypted(wt, buf, 24 + 8 + sizeof(*eapol) +
				     sizeof(*hdr) + mic_len + 2,
				     decrypted, plain_len);
	}
	if (sta->proto & WPA_PROTO_RSN)
		learn_kde_keys(wt, bss, sta, decrypted, decrypted_len,
			       hdr->key_rsc);
	else {
		int klen = bss->group_cipher == WPA_CIPHER_TKIP ? 32 : 16;
		if (decrypted_len == klen) {
			const u8 *rsc = hdr->key_rsc;
			int id;
			id = (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) >>
				WPA_KEY_INFO_KEY_INDEX_SHIFT;
			add_note(wt, MSG_DEBUG, "GTK key index %d", id);
			wpa_hexdump(MSG_DEBUG, "GTK", decrypted,
				    decrypted_len);
			bss->gtk_len[id] = decrypted_len;
			os_memcpy(bss->gtk[id], decrypted, decrypted_len);
			bss->rsc[id][0] = rsc[5];
			bss->rsc[id][1] = rsc[4];
			bss->rsc[id][2] = rsc[3];
			bss->rsc[id][3] = rsc[2];
			bss->rsc[id][4] = rsc[1];
			bss->rsc[id][5] = rsc[0];
			wpa_hexdump(MSG_DEBUG, "RSC", bss->rsc[id], 6);
		} else {
			add_note(wt, MSG_INFO, "Unexpected WPA Key Data length "
				 "in Group Key msg 1/2 from " MACSTR,
				 MAC2STR(src));
		}
	}
	os_free(decrypted);
}


static void rx_data_eapol_key_2_of_2(struct wlantest *wt, const u8 *dst,
				     const u8 *src, const u8 *bssid,
				     const u8 *data, size_t len)
{
	struct wlantest_bss *bss, *bss_mld;
	struct wlantest_sta *sta;
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	u16 key_info;

	wpa_printf(MSG_DEBUG, "EAPOL-Key 2/2 " MACSTR " -> " MACSTR " (BSSID "
		   MACSTR ")",
		   MAC2STR(src), MAC2STR(dst), MAC2STR(bssid));
	if (ether_addr_equal(dst, bssid)) {
		bss = bss_get(wt, dst);
	} else {
		bss = bss_find(wt, bssid);
		bss_mld = bss_find(wt, dst);
		if (bss_mld && (!bss || sta_find(bss_mld, src)))
			bss = bss_get(wt, dst);
		else
			bss = bss_get(wt, bssid);
	}
	if (bss == NULL)
		return;
	sta = sta_get(bss, src);
	if (sta == NULL)
		return;

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);
	if (!is_zero(hdr->key_rsc, 8)) {
		add_note(wt, MSG_INFO, "EAPOL-Key 2/2 from " MACSTR " used "
			 "non-zero Key RSC", MAC2STR(src));
	}
	key_info = WPA_GET_BE16(hdr->key_info);

	if (!sta->ptk_set) {
		add_note(wt, MSG_DEBUG,
			 "No PTK known to process EAPOL-Key 2/2");
		return;
	}

	if (sta->ptk_set &&
	    check_mic(sta, sta->ptk.kck, sta->ptk.kck_len,
		      key_info & WPA_KEY_INFO_TYPE_MASK,
		      data, len) < 0) {
		add_note(wt, MSG_INFO, "Mismatch in EAPOL-Key 2/2 MIC");
		return;
	}
	add_note(wt, MSG_DEBUG, "Valid MIC found in EAPOL-Key 2/2");
}


static void rx_data_eapol_key(struct wlantest *wt, const u8 *bssid,
			      const u8 *sta_addr, const u8 *dst,
			      const u8 *src, const u8 *data, size_t len,
			      int prot)
{
	const struct ieee802_1x_hdr *eapol;
	const struct wpa_eapol_key *hdr;
	const u8 *key_data, *alt_key_data;
	u16 key_info, key_length, ver, key_data_length, alt_key_data_length;
	size_t mic_len = 16, alt_mic_len;
	const u8 *mic;
	struct wlantest_bss *bss;
	struct wlantest_sta *sta = NULL;

	bss = bss_get(wt, bssid);
	if (bss) {
		if (sta_addr)
			sta = sta_get(bss, sta_addr);
		else
			sta = NULL;
		mic_len = determine_mic_len(sta);
	}

	eapol = (const struct ieee802_1x_hdr *) data;
	hdr = (const struct wpa_eapol_key *) (eapol + 1);

	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key",
		    (const u8 *) hdr, len - sizeof(*eapol));
	if (len < sizeof(*hdr) + mic_len + 2) {
		add_note(wt, MSG_INFO, "Too short EAPOL-Key frame from " MACSTR,
			 MAC2STR(src));
		return;
	}
	mic = (const u8 *) (hdr + 1);

	if (hdr->type == EAPOL_KEY_TYPE_RC4) {
		/* TODO: EAPOL-Key RC4 for WEP */
		wpa_printf(MSG_INFO, "EAPOL-Key Descriptor Type RC4 from "
			   MACSTR, MAC2STR(src));
		return;
	}

	if (hdr->type != EAPOL_KEY_TYPE_RSN &&
	    hdr->type != EAPOL_KEY_TYPE_WPA) {
		wpa_printf(MSG_INFO, "Unsupported EAPOL-Key Descriptor Type "
			   "%u from " MACSTR, hdr->type, MAC2STR(src));
		return;
	}

	key_info = WPA_GET_BE16(hdr->key_info);
	key_length = WPA_GET_BE16(hdr->key_length);
	key_data_length = WPA_GET_BE16(mic + mic_len);
	key_data = mic + mic_len + 2;

	if (key_data + key_data_length != data + len && sta &&
	    ((wpa_key_mgmt_sae_ext_key(sta->key_mgmt) && sta->sae_group == 0) ||
	     (sta->key_mgmt == WPA_KEY_MGMT_OWE && sta->owe_group == 0))) {
		/* We do not know which group was used (e.g., due to use of
		 * PMKSA caching without the initial association included in
		 * the capture file), so the MIC length might not be correct.
		 * Try the other options to see if matching EAPOL-Key length
		 * can be determined. */

		/* Group 20 */
		alt_mic_len = wpa_mic_len(sta->key_mgmt, 48);
		alt_key_data_length = WPA_GET_BE16(mic + alt_mic_len);
		alt_key_data = mic + alt_mic_len + 2;
		if (len >= sizeof(*hdr) + alt_mic_len + 2 &&
		    alt_key_data + alt_key_data_length == data + len) {
			add_note(wt, MSG_INFO,
				 "Assume group 20 was used to get matching Key MIC length for EAPOL-Key");
			if (wpa_key_mgmt_sae_ext_key(sta->key_mgmt))
				sta->sae_group = 20;
			else
				sta->owe_group = 20;
			mic_len = alt_mic_len;
			key_data_length = alt_key_data_length;
			key_data = alt_key_data;
			goto group_determined;
		}

		/* Group 21 */
		alt_mic_len = wpa_mic_len(sta->key_mgmt, 64);
		alt_key_data_length = WPA_GET_BE16(mic + alt_mic_len);
		alt_key_data = mic + alt_mic_len + 2;
		if (len >= sizeof(*hdr) + alt_mic_len + 2 &&
		    alt_key_data + alt_key_data_length == data + len) {
			add_note(wt, MSG_INFO,
				 "Assume group 21 was used to get matching Key MIC length for EAPOL-Key");
			if (wpa_key_mgmt_sae_ext_key(sta->key_mgmt))
				sta->sae_group = 21;
			else
				sta->owe_group = 21;
			mic_len = alt_mic_len;
			key_data_length = alt_key_data_length;
			key_data = alt_key_data;
			goto group_determined;
		}
	}

group_determined:
	if (key_data + key_data_length > data + len) {
		add_note(wt, MSG_INFO, "Truncated EAPOL-Key from " MACSTR,
			 MAC2STR(src));
		return;
	}
	if (key_data + key_data_length < data + len) {
		wpa_hexdump(MSG_DEBUG, "Extra data after EAPOL-Key Key Data "
			    "field", key_data + key_data_length,
			data + len - key_data - key_data_length);
	}


	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	wpa_printf(MSG_DEBUG, "EAPOL-Key ver=%u %c idx=%u%s%s%s%s%s%s%s%s "
		   "datalen=%u",
		   ver, key_info & WPA_KEY_INFO_KEY_TYPE ? 'P' : 'G',
		   (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) >>
		   WPA_KEY_INFO_KEY_INDEX_SHIFT,
		   (key_info & WPA_KEY_INFO_INSTALL) ? " Install" : "",
		   (key_info & WPA_KEY_INFO_ACK) ? " ACK" : "",
		   (key_info & WPA_KEY_INFO_MIC) ? " MIC" : "",
		   (key_info & WPA_KEY_INFO_SECURE) ? " Secure" : "",
		   (key_info & WPA_KEY_INFO_ERROR) ? " Error" : "",
		   (key_info & WPA_KEY_INFO_REQUEST) ? " Request" : "",
		   (key_info & WPA_KEY_INFO_ENCR_KEY_DATA) ? " Encr" : "",
		   (key_info & WPA_KEY_INFO_SMK_MESSAGE) ? " SMK" : "",
		   key_data_length);

	if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES &&
	    ver != WPA_KEY_INFO_TYPE_AES_128_CMAC &&
	    ver != WPA_KEY_INFO_TYPE_AKM_DEFINED) {
		wpa_printf(MSG_INFO, "Unsupported EAPOL-Key Key Descriptor "
			   "Version %u from " MACSTR, ver, MAC2STR(src));
		return;
	}

	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Replay Counter",
		    hdr->replay_counter, WPA_REPLAY_COUNTER_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Nonce",
		    hdr->key_nonce, WPA_NONCE_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key IV",
		    hdr->key_iv, 16);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key RSC",
		    hdr->key_rsc, WPA_KEY_RSC_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key MIC",
		    mic, mic_len);
	wpa_hexdump(MSG_MSGDUMP, "EAPOL-Key Key Data",
		    key_data, key_data_length);

	if (hdr->type == EAPOL_KEY_TYPE_RSN &&
	    (key_info & (WPA_KEY_INFO_KEY_INDEX_MASK | BIT(14) | BIT(15))) !=
	    0) {
		wpa_printf(MSG_INFO, "RSN EAPOL-Key with non-zero reserved "
			   "Key Info bits 0x%x from " MACSTR,
			   key_info, MAC2STR(src));
	}

	if (hdr->type == EAPOL_KEY_TYPE_WPA &&
	    (key_info & (WPA_KEY_INFO_ENCR_KEY_DATA |
			 WPA_KEY_INFO_SMK_MESSAGE |BIT(14) | BIT(15))) != 0) {
		wpa_printf(MSG_INFO, "WPA EAPOL-Key with non-zero reserved "
			   "Key Info bits 0x%x from " MACSTR,
			   key_info, MAC2STR(src));
	}

	if (key_length > 32) {
		wpa_printf(MSG_INFO, "EAPOL-Key with invalid Key Length %d "
			   "from " MACSTR, key_length, MAC2STR(src));
	}

	if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
	    !is_zero(hdr->key_iv, 16)) {
		wpa_printf(MSG_INFO, "EAPOL-Key with non-zero Key IV "
			   "(reserved with ver=%d) field from " MACSTR,
			   ver, MAC2STR(src));
		wpa_hexdump(MSG_INFO, "EAPOL-Key Key IV (reserved)",
			    hdr->key_iv, 16);
	}

	if (!is_zero(hdr->key_id, 8)) {
		wpa_printf(MSG_INFO, "EAPOL-Key with non-zero Key ID "
			   "(reserved) field from " MACSTR, MAC2STR(src));
		wpa_hexdump(MSG_INFO, "EAPOL-Key Key ID (reserved)",
			    hdr->key_id, 8);
	}

	if (hdr->key_rsc[6] || hdr->key_rsc[7]) {
		wpa_printf(MSG_INFO, "EAPOL-Key with non-zero Key RSC octets "
			   "(last two are unused)" MACSTR, MAC2STR(src));
	}

	if (key_info & (WPA_KEY_INFO_ERROR | WPA_KEY_INFO_REQUEST))
		return;

	if (key_info & WPA_KEY_INFO_SMK_MESSAGE)
		return;

	if (key_info & WPA_KEY_INFO_KEY_TYPE) {
		/* 4-Way Handshake */
		switch (key_info & (WPA_KEY_INFO_SECURE |
				    WPA_KEY_INFO_MIC |
				    WPA_KEY_INFO_ACK |
				    WPA_KEY_INFO_INSTALL)) {
		case WPA_KEY_INFO_ACK:
			rx_data_eapol_key_1_of_4(wt, dst, src, bssid,
						 data, len);
			break;
		case WPA_KEY_INFO_MIC:
			if (key_data_length == 0 ||
			    is_zero(hdr->key_nonce, WPA_NONCE_LEN))
				rx_data_eapol_key_4_of_4(wt, dst, src, bssid,
							 data, len);
			else
				rx_data_eapol_key_2_of_4(wt, dst, src, bssid,
							 data, len);
			break;
		case WPA_KEY_INFO_MIC | WPA_KEY_INFO_ACK |
			WPA_KEY_INFO_INSTALL:
			/* WPA does not include Secure bit in 3/4 */
			rx_data_eapol_key_3_of_4(wt, dst, src, bssid,
						 data, len);
			break;
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC |
			WPA_KEY_INFO_ACK | WPA_KEY_INFO_INSTALL:
		case WPA_KEY_INFO_SECURE |
			WPA_KEY_INFO_ACK | WPA_KEY_INFO_INSTALL:
			rx_data_eapol_key_3_of_4(wt, dst, src, bssid,
						 data, len);
			break;
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC:
		case WPA_KEY_INFO_SECURE:
			if (key_data_length == 0 ||
			    is_zero(hdr->key_nonce, WPA_NONCE_LEN))
				rx_data_eapol_key_4_of_4(wt, dst, src, bssid,
							 data, len);
			else
				rx_data_eapol_key_2_of_4(wt, dst, src, bssid,
							 data, len);
			break;
		default:
			wpa_printf(MSG_DEBUG, "Unsupported EAPOL-Key frame");
			break;
		}
	} else {
		/* Group Key Handshake */
		switch (key_info & (WPA_KEY_INFO_SECURE |
				    WPA_KEY_INFO_MIC |
				    WPA_KEY_INFO_ACK)) {
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC |
			WPA_KEY_INFO_ACK:
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_ACK:
			rx_data_eapol_key_1_of_2(wt, dst, src, bssid,
						 data, len);
			break;
		case WPA_KEY_INFO_SECURE | WPA_KEY_INFO_MIC:
		case WPA_KEY_INFO_SECURE:
			rx_data_eapol_key_2_of_2(wt, dst, src, bssid,
						 data, len);
			break;
		default:
			wpa_printf(MSG_DEBUG, "Unsupported EAPOL-Key frame");
			break;
		}
	}
}


void rx_data_eapol(struct wlantest *wt, const u8 *bssid, const u8 *sta_addr,
		   const u8 *dst, const u8 *src,
		   const u8 *data, size_t len, int prot)
{
	const struct ieee802_1x_hdr *hdr;
	u16 length;
	const u8 *p;

	wpa_hexdump(MSG_EXCESSIVE, "EAPOL", data, len);
	if (len < sizeof(*hdr)) {
		wpa_printf(MSG_INFO, "Too short EAPOL frame from " MACSTR,
			   MAC2STR(src));
		return;
	}

	hdr = (const struct ieee802_1x_hdr *) data;
	length = be_to_host16(hdr->length);
	wpa_printf(MSG_DEBUG, "RX EAPOL: " MACSTR " -> " MACSTR "%s ver=%u "
		   "type=%u len=%u #%u",
		   MAC2STR(src), MAC2STR(dst), prot ? " Prot" : "",
		   hdr->version, hdr->type, length, wt->frame_num);
	if (hdr->version < 1 || hdr->version > 3) {
		wpa_printf(MSG_INFO, "Unexpected EAPOL version %u from "
			   MACSTR, hdr->version, MAC2STR(src));
	}
	if (sizeof(*hdr) + length > len) {
		wpa_printf(MSG_INFO, "Truncated EAPOL frame from " MACSTR,
			   MAC2STR(src));
		return;
	}

	if (sizeof(*hdr) + length < len) {
		wpa_printf(MSG_INFO, "EAPOL frame with %d extra bytes",
			   (int) (len - sizeof(*hdr) - length));
	}
	p = (const u8 *) (hdr + 1);

	switch (hdr->type) {
	case IEEE802_1X_TYPE_EAP_PACKET:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL - EAP packet", p, length);
		break;
	case IEEE802_1X_TYPE_EAPOL_START:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Start", p, length);
		break;
	case IEEE802_1X_TYPE_EAPOL_LOGOFF:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL-Logoff", p, length);
		break;
	case IEEE802_1X_TYPE_EAPOL_KEY:
		rx_data_eapol_key(wt, bssid, sta_addr, dst, src, data,
				  sizeof(*hdr) + length, prot);
		break;
	case IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT:
		wpa_hexdump(MSG_MSGDUMP, "EAPOL - Encapsulated ASF alert",
			    p, length);
		break;
	default:
		wpa_hexdump(MSG_MSGDUMP, "Unknown EAPOL payload", p, length);
		break;
	}
}
