/*
 * STA list
 * Copyright (c) 2010-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "wlantest.h"


struct wlantest_sta * sta_find(struct wlantest_bss *bss, const u8 *addr)
{
	struct wlantest_sta *sta;

	dl_list_for_each(sta, &bss->sta, struct wlantest_sta, list) {
		if (ether_addr_equal(sta->addr, addr))
			return sta;
	}

	return NULL;
}


struct wlantest_sta * sta_find_mlo(struct wlantest *wt,
				   struct wlantest_bss *bss, const u8 *addr)
{
	struct wlantest_sta *sta;
	struct wlantest_bss *obss;
	int link_id;

	dl_list_for_each(sta, &bss->sta, struct wlantest_sta, list) {
		if (ether_addr_equal(sta->addr, addr))
			return sta;
		if (ether_addr_equal(sta->mld_mac_addr, addr))
			return sta;
	}

	if (is_zero_ether_addr(addr))
		return NULL;

	dl_list_for_each(sta, &bss->sta, struct wlantest_sta, list) {
		for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
			if (ether_addr_equal(sta->link_addr[link_id], addr))
				return sta;
		}
	}

	dl_list_for_each(obss, &wt->bss, struct wlantest_bss, list) {
		if (obss == bss)
			continue;
		if (!is_zero_ether_addr(bss->mld_mac_addr) &&
		    !ether_addr_equal(obss->mld_mac_addr, bss->mld_mac_addr))
			continue;
		dl_list_for_each(sta, &obss->sta, struct wlantest_sta, list) {
			if (ether_addr_equal(sta->addr, addr))
				return sta;
			if (ether_addr_equal(sta->mld_mac_addr, addr))
				return sta;
			for (link_id = 0; link_id < MAX_NUM_MLD_LINKS;
			     link_id++) {
				if (ether_addr_equal(sta->link_addr[link_id],
						     addr))
					return sta;
			}
		}
	}

	return NULL;
}


struct wlantest_sta * sta_get(struct wlantest_bss *bss, const u8 *addr)
{
	struct wlantest_sta *sta;

	if (addr[0] & 0x01)
		return NULL; /* Skip group addressed frames */

	sta = sta_find(bss, addr);
	if (sta)
		return sta;

	sta = os_zalloc(sizeof(*sta));
	if (sta == NULL)
		return NULL;
	os_memset(sta->seq_ctrl_to_sta, 0xff, sizeof(sta->seq_ctrl_to_sta));
	os_memset(sta->seq_ctrl_to_ap, 0xff, sizeof(sta->seq_ctrl_to_ap));
	sta->bss = bss;
	os_memcpy(sta->addr, addr, ETH_ALEN);
	dl_list_add(&bss->sta, &sta->list);
	wpa_printf(MSG_DEBUG, "Discovered new STA " MACSTR " in BSS " MACSTR
		   " (MLD " MACSTR ")",
		   MAC2STR(sta->addr),
		   MAC2STR(bss->bssid), MAC2STR(bss->mld_mac_addr));
	return sta;
}


void sta_deinit(struct wlantest_sta *sta)
{
	dl_list_del(&sta->list);
	os_free(sta->assocreq_ies);
	os_free(sta);
}


static void sta_update_assoc_ml(struct wlantest_sta *sta,
				struct ieee802_11_elems *elems)
{
	const u8 *mld_addr;

	if (!elems->basic_mle)
		return;

	mld_addr = get_basic_mle_mld_addr(elems->basic_mle,
					  elems->basic_mle_len);
	if (!mld_addr) {
		wpa_printf(MSG_INFO, "MLO: Invalid Basic Multi-Link element");
		return;
	}

	wpa_printf(MSG_DEBUG, "STA MLD Address: " MACSTR, MAC2STR(mld_addr));
	os_memcpy(sta->mld_mac_addr, mld_addr, ETH_ALEN);
}


void sta_update_assoc(struct wlantest_sta *sta, struct ieee802_11_elems *elems)
{
	struct wpa_ie_data data;
	struct wlantest_bss *bss = sta->bss;

	if (elems->wpa_ie && !bss->wpaie[0] &&
	    (bss->beacon_seen || bss->proberesp_seen)) {
		wpa_printf(MSG_INFO, "WPA IE included in Association Request "
			   "frame from " MACSTR " even though BSS does not "
			   "use WPA - ignore IE",
			   MAC2STR(sta->addr));
		elems->wpa_ie = NULL;
	}

	if (elems->rsn_ie && !bss->rsnie[0] &&
	    (bss->beacon_seen || bss->proberesp_seen)) {
		wpa_printf(MSG_INFO, "RSN IE included in Association Request "
			   "frame from " MACSTR " even though BSS does not "
			   "use RSN - ignore IE",
			   MAC2STR(sta->addr));
		elems->rsn_ie = NULL;
	}

	if (elems->wpa_ie && elems->rsn_ie) {
		wpa_printf(MSG_INFO, "Both WPA IE and RSN IE included in "
			   "Association Request frame from " MACSTR,
			   MAC2STR(sta->addr));
	}

	if (elems->rsn_ie) {
		wpa_hexdump(MSG_DEBUG, "RSN IE", elems->rsn_ie - 2,
			    elems->rsn_ie_len + 2);
		os_memcpy(sta->rsnie, elems->rsn_ie - 2,
			  elems->rsn_ie_len + 2);
		if (wpa_parse_wpa_ie_rsn(sta->rsnie, 2 + sta->rsnie[1], &data)
		    < 0) {
			wpa_printf(MSG_INFO, "Failed to parse RSN IE from "
				   MACSTR, MAC2STR(sta->addr));
		}
	} else if (elems->wpa_ie) {
		wpa_hexdump(MSG_DEBUG, "WPA IE", elems->wpa_ie - 2,
			    elems->wpa_ie_len + 2);
		os_memcpy(sta->rsnie, elems->wpa_ie - 2,
			  elems->wpa_ie_len + 2);
		if (wpa_parse_wpa_ie_wpa(sta->rsnie, 2 + sta->rsnie[1], &data)
		    < 0) {
			wpa_printf(MSG_INFO, "Failed to parse WPA IE from "
				   MACSTR, MAC2STR(sta->addr));
		}
	} else {
		sta->rsnie[0] = 0;
		sta->proto = 0;
		sta->pairwise_cipher = 0;
		sta->key_mgmt = 0;
		sta->rsn_capab = 0;
		if (sta->assocreq_capab_info & WLAN_CAPABILITY_PRIVACY)
			sta->pairwise_cipher = WPA_CIPHER_WEP40;
		goto skip_rsn_wpa;
	}

	sta->proto = data.proto;
	sta->pairwise_cipher = data.pairwise_cipher;
	sta->key_mgmt = data.key_mgmt;
	sta->rsn_capab = data.capabilities;
	if (bss->proto && (sta->proto & bss->proto) == 0) {
		wpa_printf(MSG_INFO, "Mismatch in WPA/WPA2 proto: STA "
			   MACSTR " 0x%x  BSS " MACSTR " 0x%x",
			   MAC2STR(sta->addr), sta->proto,
			   MAC2STR(bss->bssid), bss->proto);
	}
	if (bss->pairwise_cipher &&
	    (sta->pairwise_cipher & bss->pairwise_cipher) == 0) {
		wpa_printf(MSG_INFO, "Mismatch in pairwise cipher: STA "
			   MACSTR " 0x%x  BSS " MACSTR " 0x%x",
			   MAC2STR(sta->addr), sta->pairwise_cipher,
			   MAC2STR(bss->bssid), bss->pairwise_cipher);
	}
	if (sta->proto && data.group_cipher != bss->group_cipher &&
	    bss->ies_set) {
		wpa_printf(MSG_INFO, "Mismatch in group cipher: STA "
			   MACSTR " 0x%x != BSS " MACSTR " 0x%x",
			   MAC2STR(sta->addr), data.group_cipher,
			   MAC2STR(bss->bssid), bss->group_cipher);
	}
	if ((bss->rsn_capab & WPA_CAPABILITY_MFPR) &&
	    !(sta->rsn_capab & WPA_CAPABILITY_MFPC)) {
		wpa_printf(MSG_INFO, "STA " MACSTR " tries to associate "
			   "without MFP to BSS " MACSTR " that advertises "
			   "MFPR", MAC2STR(sta->addr), MAC2STR(bss->bssid));
	}
	if ((sta->rsn_capab & WPA_CAPABILITY_OCVC) &&
	    !(sta->rsn_capab & WPA_CAPABILITY_MFPC)) {
		wpa_printf(MSG_INFO, "STA " MACSTR " tries to associate "
			   "without MFP to BSS " MACSTR " while supporting "
			   "OCV", MAC2STR(sta->addr), MAC2STR(bss->bssid));
	}

skip_rsn_wpa:
	wpa_printf(MSG_INFO, "STA " MACSTR
		   " proto=%s%s%s"
		   "pairwise=%s%s%s%s%s%s%s"
		   "key_mgmt=%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
		   "rsn_capab=%s%s%s%s%s%s%s%s%s%s",
		   MAC2STR(sta->addr),
		   sta->proto == 0 ? "OPEN " : "",
		   sta->proto & WPA_PROTO_WPA ? "WPA " : "",
		   sta->proto & WPA_PROTO_RSN ? "WPA2 " : "",
		   sta->pairwise_cipher == 0 ? "N/A " : "",
		   sta->pairwise_cipher & WPA_CIPHER_NONE ? "NONE " : "",
		   sta->pairwise_cipher & WPA_CIPHER_TKIP ? "TKIP " : "",
		   sta->pairwise_cipher & WPA_CIPHER_CCMP ? "CCMP " : "",
		   bss->pairwise_cipher & WPA_CIPHER_CCMP_256 ? "CCMP-256 " :
		   "",
		   bss->pairwise_cipher & WPA_CIPHER_GCMP ? "GCMP " : "",
		   bss->pairwise_cipher & WPA_CIPHER_GCMP_256 ? "GCMP-256 " :
		   "",
		   sta->key_mgmt == 0 ? "N/A " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_IEEE8021X ? "EAP " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_PSK ? "PSK " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_WPA_NONE ? "WPA-NONE " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X ? "FT-EAP " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_PSK ? "FT-PSK " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256 ?
		   "EAP-SHA256 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_PSK_SHA256 ?
		   "PSK-SHA256 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_SAE ? "SAE " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_SAE ? "FT-SAE " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_FILS_SHA256 ? "FILS-SHA256 " :
		   "",
		   sta->key_mgmt & WPA_KEY_MGMT_FILS_SHA384 ? "FILS-SHA384 " :
		   "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256 ?
		   "FILS-FT-SHA256 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384 ?
		   "FILS-FT-SHA384 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_OWE ? "OWE " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_PASN ? "PASN " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_DPP ? "DPP " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B ?
		   "EAP-SUITE-B " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192 ?
		   "EAP-SUITE-B-192 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA384 ?
		   "EAP-SHA384 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X_SHA384 ?
		   "FT-EAP-SHA384 " : "",
		   sta->key_mgmt & WPA_KEY_MGMT_SAE_EXT_KEY ? "SAE-EXT-KEY " :
		   "",
		   sta->key_mgmt & WPA_KEY_MGMT_FT_SAE_EXT_KEY ?
		   "FT-SAE-EXT-KEY " : "",
		   sta->rsn_capab & WPA_CAPABILITY_PREAUTH ? "PREAUTH " : "",
		   sta->rsn_capab & WPA_CAPABILITY_NO_PAIRWISE ?
		   "NO_PAIRWISE " : "",
		   sta->rsn_capab & WPA_CAPABILITY_MFPR ? "MFPR " : "",
		   sta->rsn_capab & WPA_CAPABILITY_MFPC ? "MFPC " : "",
		   sta->rsn_capab & WPA_CAPABILITY_PEERKEY_ENABLED ?
		   "PEERKEY " : "",
		   sta->rsn_capab & WPA_CAPABILITY_SPP_A_MSDU_CAPABLE ?
		   "SPP-A-MSDU-CAPAB " : "",
		   sta->rsn_capab & WPA_CAPABILITY_SPP_A_MSDU_REQUIRED ?
		   "SPP-A-MSDU-REQUIRED " : "",
		   sta->rsn_capab & WPA_CAPABILITY_PBAC ? "PBAC " : "",
		   sta->rsn_capab & WPA_CAPABILITY_OCVC ? "OCVC " : "",
		   sta->rsn_capab & WPA_CAPABILITY_EXT_KEY_ID_FOR_UNICAST ?
		   "ExtKeyID " : "");

	sta_update_assoc_ml(sta, elems);
}


static void sta_copy_ptk(struct wlantest_sta *sta, struct wpa_ptk *ptk)
{
	os_memcpy(&sta->ptk, ptk, sizeof(*ptk));
	sta->ptk_set = 1;
	os_memset(sta->rsc_tods, 0, sizeof(sta->rsc_tods));
	os_memset(sta->rsc_fromds, 0, sizeof(sta->rsc_fromds));
}


void sta_new_ptk(struct wlantest *wt, struct wlantest_sta *sta,
		 struct wpa_ptk *ptk)
{
	struct wlantest_bss *bss;
	struct wlantest_sta *osta;

	add_note(wt, MSG_DEBUG, "Derived new PTK");
	sta_copy_ptk(sta, ptk);
	wpa_hexdump(MSG_DEBUG, "PTK:KCK", sta->ptk.kck, sta->ptk.kck_len);
	wpa_hexdump(MSG_DEBUG, "PTK:KEK", sta->ptk.kek, sta->ptk.kek_len);
	wpa_hexdump(MSG_DEBUG, "PTK:TK", sta->ptk.tk, sta->ptk.tk_len);

	dl_list_for_each(bss, &wt->bss, struct wlantest_bss, list) {
		dl_list_for_each(osta, &bss->sta, struct wlantest_sta, list) {
			bool match = false;
			int link_id;

			if (osta == sta)
				continue;
			if (ether_addr_equal(sta->addr, osta->addr))
				match = true;
			for (link_id = 0; !match && link_id < MAX_NUM_MLD_LINKS;
			     link_id++) {
				if (ether_addr_equal(osta->link_addr[link_id],
						     sta->addr))
					match = true;
			}

			if (!match)
				continue;
			if (!ether_addr_equal(sta->bss->mld_mac_addr,
					      osta->bss->mld_mac_addr))
				continue;
			wpa_printf(MSG_DEBUG,
				   "Add PTK to another MLO STA entry " MACSTR
				   " (MLD " MACSTR " --> " MACSTR ") in BSS "
				   MACSTR " (MLD " MACSTR " --> " MACSTR ")",
				   MAC2STR(osta->addr),
				   MAC2STR(osta->mld_mac_addr),
				   MAC2STR(sta->mld_mac_addr),
				   MAC2STR(bss->bssid),
				   MAC2STR(bss->mld_mac_addr),
				   MAC2STR(sta->bss->mld_mac_addr));
			sta_copy_ptk(osta, ptk);
			os_memcpy(osta->mld_mac_addr, sta->mld_mac_addr,
				  ETH_ALEN);
		}
	}
}
