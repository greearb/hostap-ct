# Test cases for Enhanced Privacy Protection Key Exchange (EPPKE)
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import time

import hostapd
from wpasupplicant import WpaSupplicant
from utils import *
from hwsim import HWSimRadio
from test_eht import eht_mld_ap_wpa2_params, eht_mld_enable_ap, traffic_test, eht_verify_status

def check_eppke_capab(dev):
    if "EPPKE" not in dev.get_capability("auth_alg"):
        raise HwsimSkip("EPPKE not supported")

def test_eppke_akm_suite_and_rsnxe_feature_flags(dev, apdev):
    """AP EPPKE AKM Advertisement with SAE base AKM and EPPKE related feature flags"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    params = hostapd.wpa3_params(ssid=ssid,
                                 password = "1234567890")
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'

    hapd = hostapd.add_ap(apdev[0], params)
    time.sleep(2)
    #TODO: Add pcap file checks to validate correct
    #RSNXE bits and AKM suite presence in Beacon frames

    #Disable all EPPKE related RSNXE flags and test
    params['assoc_frame_encryption'] = '0'
    params['pmksa_caching_privacy'] = '0'
    params['eap_using_authentication_frames'] = '0'
    hapd = hostapd.add_ap(apdev[0], params)
    time.sleep(2)

def run_eppke_sae_ext_key(dev, apdev, group):
    """EPPKE authentication with a Non-MLO AP with base AKM SAE-EXT-KEY and non-MLD client"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    params['pasn_groups'] = str(group)
    params['sae_groups'] = str(group)
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", str(group))
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_ap_with_base_akm_sae_ext_non_mld_client_19(dev, apdev):
    """EPPKE authentication with a Non-MLO AP with base AKM SAE-EXT-KEY and non-MLD client, group 19"""
    run_eppke_sae_ext_key(dev, apdev, 19)

def test_eppke_ap_with_base_akm_sae_ext_non_mld_client_20(dev, apdev):
    """EPPKE authentication with a Non-MLO AP with base AKM SAE-EXT-KEY and non-MLD client, group 20"""
    run_eppke_sae_ext_key(dev, apdev, 20)

def test_eppke_ap_with_base_akm_sae_ext_non_mld_client_21(dev, apdev):
    """EPPKE authentication with a Non-MLO AP with base AKM SAE-EXT-KEY and non-MLD client, group 21"""
    run_eppke_sae_ext_key(dev, apdev, 21)

def test_eppke_mld_ap_with_base_akm_sae_ext_non_mld_client(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and non-MLD client"""
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface):
        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY", mfp="2", pwe='1')
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        try:
            dev[0].set("pasn_groups", "")
            dev[0].set("sae_pwe", "1")
            dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                           key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                           beacon_prot="1", pairwise="CCMP GCMP-256")
            bssid = dev[0].get_status_field("bssid")
            if hapd0.own_addr() == bssid:
                hapd0.wait_sta();
                sta = hapd0.get_sta(dev[0].own_addr())
                if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
                    raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
            elif hapd1.own_addr() == bssid:
                hapd1.wait_sta();
                sta = hapd1.get_sta(dev[0].own_addr())
                if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
                    raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
            else:
                raise Exception("Unknown BSSID: " + bssid)
            hwsim_utils.test_connectivity(dev[0], hapd0)
        finally:
            dev[0].set("pasn_groups", "")
            dev[0].set("sae_pwe", "0")

def run_eppke_mld_three_links(dev, apdev, key_mgmt):
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt=key_mgmt, mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        params['channel'] = '11'
        hapd1 = eht_mld_enable_ap(hapd_iface, 2, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437 2462",
                     key_mgmt=key_mgmt, ieee80211w="2", beacon_prot="1",
                     pairwise="CCMP GCMP-256")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=7, active_links=7)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)

def run_eppke_mld_two_links(dev, apdev, key_mgmt):
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt=key_mgmt, mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt=key_mgmt, ieee80211w="2", beacon_prot="1",
                     pairwise="CCMP GCMP-256")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)

def run_eppke_mld_one_link(dev, apdev, key_mgmt):
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt=key_mgmt, mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                     key_mgmt=key_mgmt, ieee80211w="2", beacon_prot="1",
                     pairwise="CCMP GCMP-256")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_eppke_with_base_akm_sae_ext_single_link(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and MLD client using single link"""
    run_eppke_mld_one_link(dev, apdev, key_mgmt="SAE-EXT-KEY EPPKE")

def test_eppke_with_base_akm_sae_ext_two_link(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and MLD client using two links"""
    run_eppke_mld_two_links(dev, apdev, key_mgmt="SAE-EXT-KEY EPPKE")

def test_eppke_with_base_akm_sae_three_link(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and MLD client using two links"""
    run_eppke_mld_three_links(dev, apdev, key_mgmt="SAE-EXT-KEY EPPKE")

def test_eppke_ap_with_base_akm_sae_ext_non_mld_client_pmksa_cached(dev, apdev):
    """EPPKE authentication with a Non-MLO AP with base AKM SAE-EXT-KEY and non-MLD client"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP", pmksa_privacy="1")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15, error="Reconnect timed out")
        val = dev[0].get_status_field('sae_group')
        if val is not None:
            raise Exception("SAE group claimed to have been used: " + val)
        sta = hapd.get_sta(dev[0].own_addr())
        if sta['auth_alg'] != '9' or sta['AKMSuiteSelector'] != '00-0f-ac-24':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value after PMKSA caching")
        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_mld_ap_with_base_akm_sae_ext_non_mld_client_pmksa_cached(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and non-MLD client"""
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface):
        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY", mfp="2", pwe='1')
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        try:
            dev[0].set("pasn_groups", "")
            dev[0].set("sae_pwe", "1")
            dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                           key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                           beacon_prot="1", pairwise="CCMP GCMP-256",
                           pmksa_privacy="1")
            bssid = dev[0].get_status_field("bssid")
            if hapd0.own_addr() == bssid:
                hapd0.wait_sta();
                sta = hapd0.get_sta(dev[0].own_addr())
                if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
                    raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
            elif hapd1.own_addr() == bssid:
                hapd1.wait_sta();
                sta = hapd1.get_sta(dev[0].own_addr())
                if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
                    raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
            else:
                raise Exception("Unknown BSSID: " + bssid)
            hwsim_utils.test_connectivity(dev[0], hapd0)

            dev[0].request("DISCONNECT")
            dev[0].wait_disconnected()
            dev[0].request("RECONNECT")
            dev[0].wait_connected(timeout=15, error="Reconnect timed out")
            val = dev[0].get_status_field('sae_group')
            if val is not None:
                raise Exception("SAE group claimed to have been used: " + val)

            bssid = dev[0].get_status_field("bssid")
            if hapd0.own_addr() == bssid:
                hapd0.wait_sta();
                sta = hapd0.get_sta(dev[0].own_addr())
            elif hapd1.own_addr() == bssid:
                hapd1.wait_sta();
                sta = hapd1.get_sta(dev[0].own_addr())
            else:
                raise Exception("Unknown BSSID: " + bssid)

            if sta['auth_alg'] != '9' or sta['AKMSuiteSelector'] != '00-0f-ac-24':
                raise Exception("Incorrect Auth Algo/AKMSuiteSelector value after PMKSA caching")
            hwsim_utils.test_connectivity(dev[0], hapd0)

        finally:
            dev[0].set("pasn_groups", "")
            dev[0].set("sae_pwe", "0")

def run_eppke_mld_one_link_pmksa_cached(dev, apdev, key_mgmt):
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt=key_mgmt, mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                     key_mgmt=key_mgmt, ieee80211w="2", beacon_prot="1",
                     pairwise="CCMP GCMP-256", pmksa_privacy="1")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)

        wpas.request("DISCONNECT")
        wpas.wait_disconnected()
        wpas.request("RECONNECT")
        wpas.wait_connected(timeout=15, error="Reconnect timed out")
        val = wpas.get_status_field('sae_group')
        if val is not None:
            raise Exception("SAE group claimed to have been used: " + val)
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_eppke_with_base_akm_sae_ext_single_link_pmksa_cached(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and MLD client using single link"""
    run_eppke_mld_one_link_pmksa_cached(dev, apdev, key_mgmt="SAE-EXT-KEY EPPKE")

def run_eppke_mld_two_links_pmksa_cached(dev, apdev, key_mgmt):
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt=key_mgmt, mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt=key_mgmt, ieee80211w="2", beacon_prot="1",
                     pairwise="CCMP GCMP-256", pmksa_privacy="1")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)

        wpas.request("DISCONNECT")
        wpas.wait_disconnected()
        wpas.request("RECONNECT")
        wpas.wait_connected(timeout=15, error="Reconnect timed out")
        val = wpas.get_status_field('sae_group')
        if val is not None:
            raise Exception("SAE group claimed to have been used: " + val)
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_eppke_with_base_akm_sae_ext_two_link_pmksa_cached(dev, apdev):
    """EPPKE authentication with an MLD AP with base AKM SAE-EXT and MLD client using two links"""
    run_eppke_mld_two_links_pmksa_cached(dev, apdev, key_mgmt="SAE-EXT-KEY EPPKE")

def test_eppke_ap_gtk_rekey_with_base_akm_sae_ext_non_mld_client(dev, apdev):
    """EPPKE AP and GTK rekey"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    params['wpa_group_rekey'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)

        ev = dev[0].wait_event(["RSN: Group rekeying completed"], timeout=11)
        if ev is None:
            raise Exception("GTK rekey timed out")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_ap_gtk_rekey_with_base_akm_sae_ext_key_one_link(dev, apdev):
    """EPPKE AP and GTK rekey with MLO AP with 1 link"""
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY", mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        params['wpa_group_rekey'] = '1'
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                     key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                     beacon_prot="1", pairwise="CCMP GCMP-256")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)
        ev = wpas.wait_event(["RSN: Group rekeying completed"], timeout=11)
        if ev is None:
            raise Exception("GTK rekey timed out")
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_eppke_ap_gtk_rekey_with_base_akm_sae_ext_key_two_link(dev, apdev):
    """EPPKE AP and GTK rekey with MLO AP with 2 links"""
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY", mfp="2", pwe='1',
                                        beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['eap_using_authentication_frames'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        params['wpa_group_rekey'] = '1'
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                     beacon_prot="1", pairwise="CCMP GCMP-256")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hapd0.wait_sta();
        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(wpas, hapd0)
        ev = wpas.wait_event(["RSN: Group rekeying completed"], timeout=11)
        if ev is None:
            raise Exception("GTK rekey timed out")
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_eppke_ap_ptk_rekey_with_base_akm_sae_ext_non_mld_client(dev, apdev):
    """EPPKE AP and PTK rekey"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    params['wpa_ptk_rekey'] = '2'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)

        ev = dev[0].wait_event(["WPA: Key negotiation completed"])
        if ev is None:
            raise Exception("PTK rekey timed out")
        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_ap_with_non_eppke_non_mld_client(dev, apdev):
    """Negative test: SAE authentication with an EPPKE AP and non-EPPKE non-MLD client"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY", ieee80211w="2", beacon_prot="1",
                       pairwise="CCMP")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '3':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_client_with_non_eppke_ap(dev, apdev):
    """Negative test: SAE authentication with a non-EPPKE AP and EPPKE client"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2", beacon_prot="1",
                       pairwise="CCMP")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '3':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_authentication_pmkid_in_assoc(dev, apdev):
    """EPPKE authentication (PMKID in Association Request after EPPKE)"""
    try:
        dev[0].set("sae_pmkid_in_assoc", "1")
        run_eppke_sae_ext_key(dev, apdev, 19)
    finally:
        dev[0].set("sae_pmkid_in_assoc", "0")

def test_eppke_fallback_no_sae_ext_key_in_ap_rsne(dev, apdev):
    """EPPKE fallback to SAE: AP does not advertise SAE-EXT-KEY in its RSNE"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-fb-no-sae-ext-key"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password = passphrase)
    # AP advertises EPPKE but only SAE (not SAE-EXT-KEY) as the base AKM.
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['sae_pwe'] = '2'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP")
        hapd.wait_sta();
        sta = hapd.get_sta(dev[0].own_addr())
        # Must fall back to SAE (auth_alg=3), not EPPKE (auth_alg=9).
        if sta["AKMSuiteSelector"] != '00-0f-ac-8' or sta["auth_alg"] != '3':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def _eppke_sae_pw_id_change_params(ssid, passphrase):
    """Build hostapd params for EPPKE with SAE changing password identifiers"""
    params = hostapd.wpa3_params(ssid=ssid, password=passphrase)
    params["wpa_key_mgmt"] = params["wpa_key_mgmt"] + " SAE-EXT-KEY EPPKE"
    params["assoc_frame_encryption"] = "1"
    params["pmksa_caching_privacy"] = "1"
    params["sae_pwe"] = "2"
    # Changing SAE password identifier support (IEEE P802.11bi, 12.16.9)
    params["sae_pw_id_key"] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    params["sae_pw_id_num"] = "3"
    return params

def _eppke_connect_and_wait_pw_id_change(dev, ssid, passphrase, pw_id,
                                         extra_kwargs=None):
    """Connect with EPPKE + sae_password_id_change and capture the
    'RSN: Received N SAE Password Identifier(s)' event that is emitted
    during the encrypted association response processing.

    Returns the 'RSN: Received' event string, or raises an exception if
    the connection or the KDE delivery failed.
    """
    kwargs = dict(
        sae_password=passphrase,
        sae_password_id=pw_id,
        sae_password_id_change="1",
        key_mgmt="SAE-EXT-KEY EPPKE",
        ieee80211w="2",
        beacon_prot="1",
        pairwise="CCMP",
        scan_freq="2412",
        wait_connect=False,
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    dev.connect(ssid, **kwargs)

    # The 'RSN: Received' event is emitted before CTRL-EVENT-CONNECTED, so
    # we must capture both in a single wait_event loop.
    pw_id_ev = None
    start = os.times()[4]
    timeout = 15
    while True:
        remaining = start + timeout - os.times()[4]
        if remaining <= 0:
            raise Exception("Connection timed out waiting for EPPKE connect")
        ev = dev.wait_event(["CTRL-EVENT-CONNECTED",
                             "RSN: Received",
                             "CTRL-EVENT-DISCONNECTED",
                             "CTRL-EVENT-SSID-TEMP-DISABLED"],
                            timeout=remaining,
        )
        if ev is None:
            raise Exception("Connection timed out waiting for EPPKE connect")
        if "CTRL-EVENT-CONNECTED" in ev:
            break
        if "CTRL-EVENT-DISCONNECTED" in ev or \
           "CTRL-EVENT-SSID-TEMP-DISABLED" in ev:
            raise Exception("Connection failed: " + ev)
        if "RSN: Received" in ev and "SAE Password Identifier" in ev:
            pw_id_ev = ev

    if pw_id_ev is None:
        raise Exception("SAE Password Identifiers KDE not received in encrypted assoc response")
    return pw_id_ev

def test_eppke_sae_pw_id_change(dev, apdev):
    """EPPKE: SAE password identifier change delivered in encrypted assoc resp"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-pwid-change"
    passphrase = "1234567890"
    pw_id = "eppke-pw-id"

    params = _eppke_sae_pw_id_change_params(ssid, passphrase)
    params["sae_password"] = passphrase + "|id=" + pw_id
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        _eppke_connect_and_wait_pw_id_change(dev[0], ssid, passphrase, pw_id)
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != "00-0f-ac-24" or sta["auth_alg"] != "9":
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_sae_pw_id_change_reconnect(dev, apdev):
    """EPPKE: reconnect using alternative password identifier received via encrypted assoc resp"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-pwid-reconnect"
    passphrase = "1234567890"
    pw_id = "eppke-pw-id"

    params = _eppke_sae_pw_id_change_params(ssid, passphrase)
    params["sae_password"] = passphrase + "|id=" + pw_id
    params["disable_pmksa_caching"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        # First connection: AP delivers SAE PW IDs KDE in encrypted assoc resp
        _eppke_connect_and_wait_pw_id_change(dev[0], ssid, passphrase, pw_id)
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != "00-0f-ac-24" or sta["auth_alg"] != "9":
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)

        # Reconnect: the STA should use one of the alternative password
        # identifiers received in the previous encrypted assoc response.
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()
        dev[0].request("PMKSA_FLUSH")

        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15,
                              error="Reconnect with alt pw id timed out")
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != "00-0f-ac-24" or sta["auth_alg"] != "9":
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector after reconnect")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_sae_pw_id_change_ap_reject(dev, apdev):
    """EPPKE: AP rejects EPPKE auth with UNKNOWN_PASSWORD_IDENTIFIER"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-pwid-reject"
    passphrase = "1234567890"
    pw_id = "eppke-pw-id"

    params = _eppke_sae_pw_id_change_params(ssid, passphrase)
    params["sae_password"] = passphrase + "|id=" + pw_id
    params["disable_pmksa_caching"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        # First connection: AP delivers SAE PW IDs KDE
        _eppke_connect_and_wait_pw_id_change(dev[0], ssid, passphrase, pw_id)
        hapd.wait_sta()

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()
        dev[0].request("PMKSA_FLUSH")

        # Rotate the AP key so it can no longer decrypt the alternative
        # password identifier the STA will present, forcing a rejection with
        # WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER.
        hapd.set("sae_pw_id_key",
                 "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

        dev[0].request("RECONNECT")
        # The STA should receive CTRL-EVENT-SAE-UNKNOWN-PASSWORD-IDENTIFIER
        ev = dev[0].wait_event(["CTRL-EVENT-SAE-UNKNOWN-PASSWORD-IDENTIFIER",
                                "CTRL-EVENT-CONNECTED"],
                               timeout=15)
        if ev is None:
            raise Exception("No event after AP rejection of alt password id")
        if "CTRL-EVENT-SAE-UNKNOWN-PASSWORD-IDENTIFIER" not in ev:
            raise Exception("Expected UNKNOWN_PASSWORD_IDENTIFIER event, got: " + ev)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_sae_pw_id_change_config_file(dev, apdev, params):
    """EPPKE: SAE password identifier change persisted to config file"""
    config = params["prefix"] + ".conf.wlan5"
    with open(config, "w") as f:
        f.write("update_config=1\n")

    wpas = WpaSupplicant(global_iface="/tmp/wpas-wlan5")
    wpas.interface_add("wlan5", config=config)
    check_eppke_capab(wpas)

    ssid = "test-eppke-pwid-cfg"
    passphrase = "1234567890"
    pw_id = "eppke-pw-id"

    ap_params = _eppke_sae_pw_id_change_params(ssid, passphrase)
    ap_params["sae_password"] = passphrase + "|id=" + pw_id
    hapd = hostapd.add_ap(apdev[0], ap_params)

    wpas.set("pasn_groups", "")
    wpas.set("sae_pwe", "1")
    _eppke_connect_and_wait_pw_id_change(wpas, ssid, passphrase, pw_id)
    hapd.wait_sta()
    hwsim_utils.test_connectivity(wpas, hapd)

    wpas.request("DISCONNECT")
    wpas.wait_disconnected()

    # Reload the interface from the config file; the alternative password
    # identifiers written by wpa_supplicant_sae_pw_id_change() must survive
    # the reload and allow a successful reconnect.
    wpas.interface_remove("wlan5")
    wpas.interface_add("wlan5", config=config)
    wpas.wait_connected(timeout=15,
                        error="Reconnect after config reload timed out")

def test_eppke_sae_pw_id_change_rsnxe_capab(dev, apdev):
    """EPPKE: STA advertises SAE_PW_ID_CHANGE capability in RSNXE when configured"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-pwid-rsnxe"
    passphrase = "1234567890"
    pw_id = "eppke-pw-id"

    params = _eppke_sae_pw_id_change_params(ssid, passphrase)
    params["sae_password"] = passphrase + "|id=" + pw_id
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")
        # With sae_password_id_change=1: AP must deliver the KDE (bit 34 set)
        _eppke_connect_and_wait_pw_id_change(dev[0], ssid, passphrase, pw_id)
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != "00-0f-ac-24" or sta["auth_alg"] != "9":
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)

        # Verify that without sae_password_id_change the capability is NOT
        # advertised and the AP does NOT deliver the KDE.
        # Disable sae_password_id_change on the existing network and reconnect.
        net_id = dev[0].get_status_field("id")
        dev[0].set_network(net_id, "sae_password_id_change", "0")
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()
        dev[0].request("PMKSA_FLUSH")
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15, error="Second connection timed out")
        hapd.wait_sta()
        ev = dev[0].wait_event(["RSN: Received"], timeout=3)
        if ev is not None and "SAE Password Identifier" in ev:
            raise Exception("AP delivered SAE PW IDs KDE even though STA did not advertise SAE_PW_ID_CHANGE capability")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_sae_pw_id_change_reconnect_kde(dev, apdev):
    """EPPKE: KDE delivered on reconnect uses decrypted (real) password identifier"""
    # Regression test: when the STA reconnects using an encrypted alternative
    # password identifier, the AP must use the *decrypted* identifier (e.g.,
    # "eppke-pw-id") as the plaintext when generating the next SAE PW IDs KDE,
    # not the raw encrypted blob. If the raw blob were used, add_sae_pw_ids()
    # would encrypt garbage and the STA would not be able to use the resulting
    # KDE on a third connection.
    check_eppke_capab(dev[0])
    ssid = 'test-eppke-pwid-kde'
    passphrase = '1234567890'
    pw_id = 'eppke-pw-id'

    params = _eppke_sae_pw_id_change_params(ssid, passphrase)
    params['sae_password'] = passphrase + '|id=' + pw_id
    params['disable_pmksa_caching'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "1")

        # First connection: AP delivers SAE PW IDs KDE with the plaintext
        # identifier "eppke-pw-id".
        _eppke_connect_and_wait_pw_id_change(dev[0], ssid, passphrase, pw_id)
        hapd.wait_sta()

        # Second connection via RECONNECT: STA uses one of the encrypted
        # alternative identifiers received in the first KDE. The AP must:
        #   1. Decrypt the identifier to recover "eppke-pw-id"
        #   2. Use "eppke-pw-id" (not the encrypted blob) as the plaintext
        #      when generating the next SAE PW IDs KDE.
        # We verify (2) by checking that the AP delivers the KDE again on
        # this second connection (which requires sm->sae_pw_id to be set to
        # the decrypted identifier so the condition in wpa_auth_eid_key_delivery
        # is satisfied).
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()
        dev[0].request("PMKSA_FLUSH")

        # Use wait_connect=False so we can capture the RSN: Received event
        # that is emitted before CTRL-EVENT-CONNECTED.
        dev[0].request("RECONNECT")
        pw_id_ev = None
        start = os.times()[4]
        timeout = 15
        while True:
            remaining = start + timeout - os.times()[4]
            if remaining <= 0:
                raise Exception("Second connection timed out")
            ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                                    "RSN: Received",
                                    "CTRL-EVENT-DISCONNECTED",
                                    "CTRL-EVENT-SSID-TEMP-DISABLED"],
                                   timeout=remaining)
            if ev is None:
                raise Exception("Second connection timed out")
            if "CTRL-EVENT-CONNECTED" in ev:
                break
            if "CTRL-EVENT-DISCONNECTED" in ev or \
               "CTRL-EVENT-SSID-TEMP-DISABLED" in ev:
                raise Exception("Second connection failed: " + ev)
            if "RSN: Received" in ev and "SAE Password Identifier" in ev:
                pw_id_ev = ev
        hapd.wait_sta()
        if pw_id_ev is None:
            raise Exception("AP did not deliver SAE PW IDs KDE on second connection (dec_pw_id not set correctly)")

        # Third connection: STA uses another encrypted alternative identifier
        # from the second KDE. If the second KDE was generated with the raw
        # encrypted blob as plaintext, decryption would fail and the AP would
        # reject the third connection.
        net_id = dev[0].get_status_field("id")
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[0].dump_monitor()
        dev[0].request("PMKSA_FLUSH")

        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15,
                              error="Third connection timed out - second KDE likely used wrong plaintext")
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector on third connection")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def run_eppke_sae_ext_key_group_retry(dev, apdev):
    """EPPKE authentication with PASN group retry - AP supports groups 20 and 21,
    STA starts with group 19, gets rejected, retries with group 20"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-authentication"
    passphrase = '1234567890'
    params = hostapd.wpa3_params(ssid=ssid,
				 password=passphrase)
    params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['sae_pwe'] = '2'
    params['pasn_groups'] = "20 21"
    params['sae_groups'] = "20 21"
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "19 20")
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP")
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-24' or sta["auth_alg"] != '9':
            raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        dev[0].set("pasn_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eppke_ap_with_base_akm_sae_ext_legacy_client_group_retry(dev, apdev):
    """EPPKE Non-MLO AP: PASN group retry from 19 to 20 (AP supports groups 20 and 21)"""
    run_eppke_sae_ext_key_group_retry(dev, apdev)

def run_eppke_mld_ap_mld_sta_group_retry(dev, apdev):
    """EPPKE authentication with MLD AP and MLD STA (single link) with PASN group retry - AP supports groups 20 and 21, STA starts with group 19, gets rejected, retries with group 20"""
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY", mfp="2",
                                        pwe='1', beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        params['pasn_groups'] = "20 21"
        params['sae_groups'] = "20 21"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        try:
            wpas.set("pasn_groups", "19 20")
            wpas.set("sae_pwe", "1")
            wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                         key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                         beacon_prot="1", pairwise="CCMP GCMP-256")
            eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                              valid_links=1, active_links=1)
            hapd0.wait_sta()
            sta = hapd0.get_sta(wpas.own_addr())
            if sta["AKMSuiteSelector"] != '00-0f-ac-24' or \
               sta["auth_alg"] != '9':
                raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
            hwsim_utils.test_connectivity(wpas, hapd0)
        finally:
            wpas.set("pasn_groups", "")
            wpas.set("sae_pwe", "0")

def test_eppke_mld_ap_with_base_akm_sae_ext_mld_sta_group_retry(dev, apdev):
    """EPPKE MLD AP with MLD STA (single link): PASN group retry from 19 to 20 (AP supports groups 20 and 21)"""
    run_eppke_mld_ap_mld_sta_group_retry(dev, apdev)

def run_eppke_mld_sta_group_retry(dev, apdev):
    """EPPKE authentication with MLD AP and MLD STA with PASN group retry - AP supports groups 20 and 21, STA starts with group 19, gets rejected, retries with group 20"""
    check_eppke_capab(dev[0])
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-authentication"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY", mfp="2",
                                        pwe='1', beacon_prot=1)
        params['wpa_key_mgmt'] = params['wpa_key_mgmt'] + ' ' + 'EPPKE'
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        params['pasn_groups'] = "20 21"
        params['sae_groups'] = "20 21"
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        try:
            wpas.set("pasn_groups", "19 20")
            wpas.set("sae_pwe", "1")
            wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                         key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                         beacon_prot="1", pairwise="CCMP GCMP-256")
            hapd0.wait_sta()
            eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                              valid_links=3, active_links=3)
            sta = hapd0.get_sta(wpas.own_addr())
            if sta["AKMSuiteSelector"] != '00-0f-ac-24' or \
               sta["auth_alg"] != '9':
                raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
            hwsim_utils.test_connectivity(wpas, hapd0)
        finally:
            wpas.set("pasn_groups", "")
            wpas.set("sae_pwe", "0")

def test_eppke_mld_sta_with_base_akm_sae_ext_group_retry(dev, apdev):
    """EPPKE MLD AP with MLD STA: PASN group retry from 19 to 20 (AP supports groups 20 and 21)"""
    run_eppke_mld_sta_group_retry(dev, apdev)

def test_eppke_without_base_akm(dev, apdev):
    """EPPKE authentication without a base AKM (eppke_unauth=1)"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-nobaseakm"
    params = hostapd.wpa2_params(ssid=ssid, wpa_key_mgmt="EPPKE",
                                 ieee80211w="2")
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, scan_freq="2412", key_mgmt="EPPKE", ieee80211w="2",
                   beacon_prot="1", pairwise="CCMP")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-29' or sta["auth_alg"] != '9':
        raise Exception("Incorrect Auth Algo/AKMSuiteSelector value")
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_eppke_without_base_akm_noauth_disabled(dev, apdev):
    """Negative test: EPPKE without base AKM when eppke_unauth is disabled"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-nobaseakm-neg"
    params = hostapd.wpa2_params(ssid=ssid, wpa_key_mgmt="EPPKE",
                                 ieee80211w="2")
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '0'
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid, scan_freq="2412", key_mgmt="EPPKE", ieee80211w="2",
                   beacon_prot="1", pairwise="CCMP", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED",
                            "CTRL-EVENT-AUTH-REJECT",
                            "CTRL-EVENT-ASSOC-REJECT"], timeout=10)
    if ev and "CTRL-EVENT-CONNECTED" in ev:
        raise Exception("Unexpected connection succeeded with eppke_unauth=0")

def test_eppke_without_base_akm_mld_ap(dev, apdev):
    """EPPKE authentication without base AKM on an MLD AP (eppke_unauth=1)"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-nobaseakm-mld"

    try:
        with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
             HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
            wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
            wpas.interface_add(wpas_iface)

            params = hostapd.wpa2_params(ssid=ssid, wpa_key_mgmt="EPPKE",
                                         ieee80211w="2")
            params['ieee80211n'] = '1'
            params['ieee80211ax'] = '1'
            params['ieee80211be'] = '1'
            params['channel'] = '1'
            params['hw_mode'] = 'g'
            params['group_mgmt_cipher'] = "AES-128-CMAC"
            params['beacon_prot'] = '1'
            params['assoc_frame_encryption'] = '1'
            params['pmksa_caching_privacy'] = '1'
            params['eppke_unauth'] = '1'

            hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

            params['channel'] = '6'
            hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

            wpas.connect(ssid, scan_freq="2412 2437", key_mgmt="EPPKE",
                         ieee80211w="2", beacon_prot="1", pairwise="CCMP")
            eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                              valid_links=3, active_links=3)
            hapd0.wait_sta()
            sta = hapd0.get_sta(wpas.own_addr())
            if sta["AKMSuiteSelector"] != '00-0f-ac-29' or \
               sta["auth_alg"] != '9':
                raise Exception(
                    "Incorrect Auth Algo/AKMSuiteSelector value")
            hwsim_utils.test_connectivity(wpas, hapd0)
    except Exception as e:
        if "MLD not supported" in str(e) or "Failed to add" in str(e):
            raise HwsimSkip("MLD not supported")
        raise
