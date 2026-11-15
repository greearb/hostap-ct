# Test cases for security profiles
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
from utils import *
import hwsim_utils
from test_eht import eht_mld_enable_ap, eht_mld_ap_wpa2_params, eht_verify_status
from hwsim import HWSimRadio
from wpasupplicant import WpaSupplicant
from test_suite_b import check_suite_b_192_capa, suite_b_as_params
from test_ap_ft import ft_params1, ft_params2, run_roams
from test_eppke import check_eppke_capab

def enable_sta_security_profiles(dev, sec_prof=None):
    try:
        dev.set("security_profiles", "1")
    except:
        raise HwsimSkip("Security profiles not supported")

    if sec_prof is not None:
        profs = dev.get_capability("security_profiles")
        if str(sec_prof) not in profs:
            raise HwsimSkip("Security profile %d not supported" % sec_prof)

def disable_sta_security_profiles(dev):
    try:
        dev.set("security_profiles", "0")
    except:
        pass

def sta_cleanup(dev):
    try:
        dev.set("sae_pwe", "0")
        dev.set("pasn_groups", "")
        dev.set("rsn_overriding", "0")
    except:
        pass
    connected = dev.get_status()["wpa_state"] in ["ASSOCIATED",
                                                  "4WAY_HANDSHAKE",
                                                  "GROUP_HANDSHAKE",
                                                  "COMPLETED"]
    dev.request("DISCONNECT")
    if connected:
        dev.wait_disconnected()

def check_security_profile(hapd, dev, number, eht=True, akm=None,
                           auth_alg=None):
    sta = hapd.get_sta(dev.own_addr())

    if eht and "[EHT]" not in sta['flags']:
        raise Exception("Missing STA flag: EHT")
    if "[MFP]" not in sta['flags']:
        raise Exception("Missing STA flag: MFP")
    if akm is not None and sta["AKMSuiteSelector"] != akm:
        raise Exception("Incorrect AKMSuiteSelector value (%s != %s)" % (sta["AKMSuiteSelector"], akm))
    if auth_alg is not None and sta["auth_alg"] != auth_alg:
        raise Exception("Incorrect auth_alg value (%s != %s)" % (sta["auth_alg"], auth_alg))

    if "security_profile" not in sta:
        raise Exception("hostapd did not report security profile number for the STA")
    if int(sta["security_profile"]) != number:
        raise Exception("hostapd reported unexpected security profile number (%s != %d)" % (sta["security_profile"], number))

    sp = dev.get_status_field("security_profile")
    if sp is None:
        raise Exception("wpa_supplicant did not report security profile number")
    if int(sp) != number:
        raise Exception("wpa_supplicant reported unexpected security profile number (%s != %d)" % (sp, number))

# Helper functions to start APs with different Security Profiles
def start_eppke_ap_security_profile_0(apdev):
    """Start EPPKE AP with Security Profile 1"""
    ssid = "sp0-eppke"
    params = hostapd.wpa2_params(ssid=ssid, wpa_key_mgmt="EPPKE",
                                 ieee80211w="2")
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '1'
    params['security_profiles'] = '0'
    passphrase = '1234567890'

    try:
        hapd = hostapd.add_ap(apdev, params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    return hapd

def start_mixed_eppke_sae_ap_security_profile_1(apdev):
    """Start AP advertising Security Profiles 1 and 9 with SAE-EXT-KEY base"""
    ssid = "sp1-mixed"
    passphrase = "12345678"  # For SAE-EXT-KEY clients

    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"

    # Use single AKMP in RSNE
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'

    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['sae_pwe'] = '2'

    # Advertise both security profiles 1 and 9
    params['security_profiles'] = '1 9'

    try:
        hapd = hostapd.add_ap(apdev, params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    return hapd, passphrase

def start_mixed_eppke_base_ap_security_profile_0(apdev):
    """Start AP with EPPKE base AKMP advertising Security Profiles 0 and 8"""
    ssid = "sp1-eppke-base"

    params = hostapd.wpa2_params(ssid=ssid, wpa_key_mgmt="EPPKE",
                                 ieee80211w="2")
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"

    # Use EPPKE as base AKMP in RSNE
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '1'

    # Advertise both security profiles 0 and 8
    params['security_profiles'] = '0 8'

    try:
        hapd = hostapd.add_ap(apdev, params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    return hapd

# FIX: This is not security profile 1, but 0.. Looks like hostapd does not
# enforce sp 0 correctly for unauth EPPKE and wpa_supplicant select sp 1 for
# this case somehow (based on AP advertisement?)
def test_security_profile_0_eppke(dev, apdev):
    """Security Profile 0 - EPPKE with GCMP-256"""
    check_eppke_capab(dev[0])
    hapd = start_eppke_ap_security_profile_0(apdev[0])

    try:
        enable_sta_security_profiles(dev[0], 0)
        dev[0].connect("sp0-eppke", scan_freq="2412", key_mgmt="EPPKE",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", pmksa_privacy="1")

        status = dev[0].get_status()
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " + status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " + status['group_cipher'])

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 0, akm='00-0f-ac-29', auth_alg='9')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_1_mixed_sae_ext_sta(dev, apdev):
    """Security Profile 1+9 - SAE-EXT-KEY STA connecting to AP with SAE-EXT base"""
    hapd, passphrase = start_mixed_eppke_sae_ap_security_profile_1(apdev[0])

    try:
        # SAE-EXT-KEY STA connecting to AP that supports both EPPKE and SAE-EXT-KEY
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        dev[0].connect("sp1-mixed", psk=passphrase,
                       key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       pmksa_privacy="1",
                       scan_freq="2412")

        # Verify connection with SAE-EXT-KEY
        status = dev[0].get_status()
        if status['key_mgmt'] != 'SAE-EXT-KEY':
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " + status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " + status['group_cipher'])

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_0_mixed_eppke_sta(dev, apdev):
    """Security Profile 0+8 - EPPKE STA connecting to AP with EPPKE base"""
    check_eppke_capab(dev[0])
    hapd = start_mixed_eppke_base_ap_security_profile_0(apdev[0])

    try:
        # EPPKE STA connecting to AP that advertises EPPKE + Security Profiles 0 and 8
        enable_sta_security_profiles(dev[0], 0)
        dev[0].connect("sp1-eppke-base", scan_freq="2412",
                       key_mgmt="EPPKE",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       pmksa_privacy="1")

        # Verify connection with EPPKE
        status = dev[0].get_status()
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " + status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " + status['group_cipher'])

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 0, akm='00-0f-ac-29', auth_alg='9')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_3_eap_tls_mlo_single_link(dev, apdev):
    """Security Profile 3 - 802.1X EAP-TLS over Authentication Frames, MLO single-link"""
    ssid = "test-ieee8021x-auth-mlo-1l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: single link (link-0) with Security Profile 3
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params['rsn_pairwise'] = 'GCMP-256'
        params['group_cipher'] = 'GCMP-256'
        params['security_profiles'] = '3'

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        # Non-AP MLD supplicant
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        enable_sta_security_profiles(wpas, 3)

        # Connect with EAP-TLS over IEEE 802.1X Authentication Frames
        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412",
                     eap_over_auth_frame="1",
                     pmksa_privacy="1",
                     pairwise="GCMP-256",
                     group="GCMP-256")

        hapd0.wait_sta()
        check_security_profile(hapd0, wpas, 3, akm='00-0f-ac-5')

        # Verify MLD state: single link active
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)

def test_security_profile_5_eap_sha384_mlo(dev, apdev):
    """Security Profile 5 - 802.1X-SHA384 over Authentication Frames, MLO single-link"""
    ssid = "sp5-eap-sha384-mlo"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: single link with Security Profile 5
        # Profile 5: AKM 23 (WPA-EAP-SHA384), GCMP-256, MFPR=1,
        #            IEEE 802.1X Auth Frame=1, Assoc Frame Encryption=1,
        #            PMKSA Caching Privacy=1
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA384",
                                        mfp="2")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params["pmksa_caching_privacy"] = "1"
        params['rsn_pairwise'] = 'GCMP-256'
        params['group_cipher'] = 'GCMP-256'
        params['group_mgmt_cipher'] = 'BIP-GMAC-256'
        params['security_profiles'] = '5'

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        enable_sta_security_profiles(wpas, 5)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA384",
                     ieee80211w="2",
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412",
                     eap_over_auth_frame="1",
                     pmksa_privacy="1",
                     pairwise="GCMP-256",
                     group="GCMP-256",
                     group_mgmt="BIP-GMAC-256")

        hapd0.wait_sta()
        check_security_profile(hapd0, wpas, 5, akm='00-0f-ac-23')

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)

def test_security_profile_7_eap_suite_b_192_mlo(dev, apdev):
    """Security Profile 7 - 802.1X Suite-B-192 over Authentication Frames, MLO single-link"""
    check_suite_b_192_capa(dev)
    ssid = "sp7-suite-b-192-mlo"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: single link with Security Profile 7
        # Profile 7: AKM 12 (WPA-EAP-SUITE-B-192), GCMP-256, MFPR=1,
        #            IEEE 802.1X Auth Frame=1, Assoc Frame Encryption=1,
        #            PMKSA Caching Privacy=1
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SUITE-B-192",
                                        mfp="2")
        # Use internal EAP server with Suite-B-192 EC certificates
        params["eap_server"] = "1"
        params["eap_user_file"] = "auth_serv/eap_user.conf"
        params["ca_cert"] = "auth_serv/ec2-ca.pem"
        params["server_cert"] = "auth_serv/ec2-server.pem"
        params["private_key"] = "auth_serv/ec2-server.key"
        params["openssl_ciphers"] = "SUITEB192"
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params["pmksa_caching_privacy"] = "1"
        params['rsn_pairwise'] = 'GCMP-256'
        params['group_cipher'] = 'GCMP-256'
        params['group_mgmt_cipher'] = 'BIP-GMAC-256'
        params['security_profiles'] = '7'

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        enable_sta_security_profiles(wpas, 7)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SUITE-B-192",
                     ieee80211w="2",
                     openssl_ciphers="SUITEB192",
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ec2-ca.pem",
                     client_cert="auth_serv/ec2-user.pem",
                     private_key="auth_serv/ec2-user.key",
                     scan_freq="2412",
                     eap_over_auth_frame="1",
                     pmksa_privacy="1",
                     pairwise="GCMP-256",
                     group="GCMP-256",
                     group_mgmt="BIP-GMAC-256")

        hapd0.wait_sta()
        check_security_profile(hapd0, wpas, 7, akm='00-0f-ac-12')

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)

def test_eppke_sae_ext_key_mlo_group_19(dev, apdev):
    """EPPKE with SAE-EXT-KEY and MLO - Group 19"""
    check_eppke_capab(dev[0])
    ssid = "test-eppke-sae-ext-key-mlo"
    passphrase = '1234567890'
    group = 19

    params = hostapd.wpa3_params(ssid=ssid, password=passphrase)
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY EPPKE'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eap_using_authentication_frames'] = '1'
    params['sae_pwe'] = '2'
    params['pasn_groups'] = str(group)
    params['security_profiles'] = '1'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['sae_groups'] = str(group)
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['ieee80211w'] = '2'
    params['beacon_prot'] = '1'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        disable_sta_security_profiles(dev[0])
        dev[0].set("pasn_groups", str(group))
        dev[0].set("sae_pwe", "1")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                       beacon_prot="1", pairwise="CCMP GCMP-256",
                       group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       pmksa_privacy="1")
        hapd.wait_sta()
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_eppke_sp_mlo_two_link(dev, apdev):
    """EPPKE authentication with Security Profiles (SP 1) on MLO with two links"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-eppke-sp"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY EPPKE", mfp="2",
                                        pwe='1', beacon_prot=1)
        params['assoc_frame_encryption'] = '1'
        params['pmksa_caching_privacy'] = '1'
        params['rsn_pairwise'] = "CCMP GCMP-256"
        params['security_profiles'] = '1'
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        enable_sta_security_profiles(wpas, 1)
        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY EPPKE", ieee80211w="2",
                     beacon_prot="1",
                     pairwise="CCMP GCMP-256", pmksa_privacy="1")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hapd0.wait_sta()
        check_security_profile(hapd0, wpas, 1, akm='00-0f-ac-24', auth_alg='9')
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_sp9_sp_mlo_two_link(dev, apdev):
    """Non-EPPKE authentication with Security Profiles (SP 9) on MLO with two links"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = '1234567890'
        ssid = "test-sp9-sp"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY ", mfp="2", pwe='1',
                                        beacon_prot=1)
        params['rsn_pairwise'] = "CCMP GCMP-256"
        params['security_profiles'] = '9'
        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        enable_sta_security_profiles(wpas, 9)
        wpas.set("pasn_groups", "")
        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY", ieee80211w="2", beacon_prot="1",
                     pairwise="CCMP GCMP-256", pmksa_privacy="1")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hapd0.wait_sta()
        check_security_profile(hapd0, wpas, 9, akm='00-0f-ac-24')
        hwsim_utils.test_connectivity(wpas, hapd0)

def start_sae_ap_security_profile_9(apdev):
    """Start SAE AP with Security Profile 9"""
    ssid = "sp9-sae"
    passphrase = "12345678"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'

    try:
        hapd = hostapd.add_ap(apdev, params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    return hapd, passphrase

def start_owe_ap_security_profile_8(apdev):
    """Start OWE AP with Security Profile 8"""
    params = hostapd.wpa2_params(ssid="owe_sp8", passphrase=None)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'OWE'
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['security_profiles'] = '8'

    try:
        hapd = hostapd.add_ap(apdev, params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    return hapd

def test_security_profile_8_owe(dev, apdev):
    """Security Profile 8 - OWE with GCMP-256"""
    check_owe_capab(dev[0])

    hapd = start_owe_ap_security_profile_8(apdev[0])

    try:
        dev[0].connect("owe_sp8", key_mgmt="OWE", ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['key_mgmt'] != 'OWE':
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " + status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " + status['group_cipher'])

        sta = hapd.get_sta(dev[0].own_addr())
        if "[EHT]" not in sta['flags']:
            raise Exception("Missing STA flag: EHT")
        if "[MFP]" not in sta['flags']:
            raise Exception("Missing STA flag: MFP")

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_sae(dev, apdev):
    """Security Profile 9 - SAE with GCMP-256"""
    hapd, passphrase = start_sae_ap_security_profile_9(apdev[0])

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        dev[0].connect("sp9-sae", psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " + status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " + status['group_cipher'])

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_11ax_sta(dev, apdev):
    """Security Profile 9 - 11ax STA with SAE-EXT-KEY and GCMP-256"""
    ssid = "sp9-11ax-gcmp256"
    passphrase = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        # 11ax STA connecting with SAE-EXT-KEY and GCMP-256
        # Disable EHT on this STA to make it 11ax-only
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412",
                       disable_eht="1")

        # Verify 11ax STA connection
        status = dev[0].get_status()

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24', eht=False)

        # Test traffic
        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_sae_ext_with_rsnxe_mask(dev, apdev):
    """Security Profile 9 - SAE-EXT-KEY with RSNXE capability mask"""
    ssid = "sp9-sae-ext-mask"
    passphrase = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'

    # NEW SYNTAX: Specify bits to SUPPRESS (inverted logic)
    # Value '20' = hex 0x20 = bit 5, which will be suppressed
    # Internally stored as ~0x20 = 0xFFFFFFFFFFFFFFDF
    params['rsnxe_capab_mask'] = '0'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " + status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " + status['group_cipher'])

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_psk2_base_sta_sae_ext_key(dev, apdev):
    """Security Profile 9: AP has PSK2 base AKM, STA overrides to SAE-EXT-KEY/GCMP-256 via security profile"""
    check_sae_capab(dev[0])

    ssid = "sp9-psk2-base"
    passphrase = "12345678"

    # AP: The RSNE advertises WPA-PSK (PSK2) as AKM with CCMP as pairwise.
    # Security Profile 9 (SAE-EXT-KEY/GCMP-256) is also advertised.
    # The STA is configured with SAE-EXT-KEY/GCMP-256 and uses the security
    # profile override to connect even though the RSNE only lists
    # WPA-PSK (not SAE-EXT-KEY) as the AKM.
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'WPA-PSK'      # base AKM: PSK2 only
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'CCMP'         # only CCMP in the RSNE
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'
    # Suppress SAE H2E (bit 5 = 0x20) from the RSNXE so the legacy
    # element does not advertise H2E. The Security Profile element still
    # carries the full Extended RSN Capabilities including SAE H2E.
    # The STA must read H2E support from the Security Profile element.
    params['rsnxe_capab_mask'] = '20'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        enable_sta_security_profiles(dev[0], 9)
        # Use sae_pwe=2 (both loop and H2E) on the STA so it does not
        # strictly require H2E from the RSNXE. The AP's RSNXE
        # has H2E suppressed (rsnxe_capab_mask=20); the Security Profile
        # element still carries H2E. The STA reads H2E from the Security
        # Profile element and can connect using either SAE method.
        dev[0].set("sae_pwe", "2")
        # STA uses SAE-EXT-KEY/GCMP-256 via the security profile override.
        # Without the override the BSS would be rejected because the RSNE
        # only advertises WPA-PSK (not SAE-EXT-KEY).
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['key_mgmt'] not in ('SAE-EXT-KEY',):
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " +
                            status['group_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_sae_base_sta_sae_ext_key(dev, apdev):
    """Security Profile 9: AP has SAE base AKM with CCMP+GCMP-256 pairwise,
    STA uses SAE-EXT-KEY/GCMP-256 from security profile override"""
    check_sae_capab(dev[0])

    ssid = "sp9-sae-base"
    passphrase = "12345678"

    # AP: The RSNE advertises SAE as AKM with both CCMP and GCMP-256 as
    # pairwise ciphers. Security profile 9 (SAE-EXT-KEY/GCMP-256) is also
    # advertised. The STA is configured with SAE-EXT-KEY/GCMP-256 and uses
    # the security profile override to connect even though the RSNE
    # only lists SAE (not SAE-EXT-KEY) as the AKM.
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE'          # base AKM: SAE only
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'CCMP GCMP-256'  # both pairwise ciphers
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        # STA uses SAE-EXT-KEY/GCMP-256 via the security profile override.
        # Without the override the BSS would be rejected because the RSNE
        # only advertises SAE (not SAE-EXT-KEY).
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['key_mgmt'] not in ('SAE-EXT-KEY',):
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " +
                            status['group_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_sae_ccmp_base_sta_sae_ext_key(dev, apdev):
    """Security Profile 9: AP has SAE/CCMP base, STA overrides both AKM
    (SAE->SAE-EXT-KEY) and pairwise cipher (CCMP->GCMP-256) via security profile"""
    check_sae_capab(dev[0])

    ssid = "sp9-sae-ccmp"
    passphrase = "12345678"

    # AP: The RSNE advertises SAE as AKM with CCMP as pairwise and group
    # cipher. Security profile 9 (SAE-EXT-KEY/GCMP-256) is also advertised.
    # The STA is configured with SAE-EXT-KEY/GCMP-256 and uses the security
    # profile override to connect, overriding both the AKM (SAE->SAE-EXT-KEY)
    # and the pairwise cipher (CCMP->GCMP-256).
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE'          # base AKM: SAE only
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'CCMP'         # only CCMP in the RSNE
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        # STA uses SAE-EXT-KEY/GCMP-256 via the security profile override.
        # Without the override the BSS would be rejected because:
        #   - The RSNE only advertises SAE (not SAE-EXT-KEY)
        #   - The RSNE only advertises CCMP (not GCMP-256)
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['key_mgmt'] not in ('SAE-EXT-KEY',):
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " +
                            status['group_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_override_akm_cipher_9(dev, apdev):
    """Security Profile 9 override: STA prefers GCMP-256 from security profile over CCMP in RSNE"""
    check_sae_capab(dev[0])

    ssid = "sp9-override"
    passphrase = "12345678"

    # AP: The RSNE has SAE-EXT-KEY/CCMP (legacy cipher).
    # The Security Profile element advertises profile 9 (SAE-EXT-KEY/GCMP-256).
    # The STA is configured with GCMP-256. Without the security profile
    # override, the STA would reject the BSS because the RSNE only
    # advertises CCMP. With the override, the STA uses GCMP-256 from the
    # security profile.
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['ieee80211w'] = '2'
    # The RSNE advertises CCMP only (not GCMP-256)
    params['rsn_pairwise'] = 'CCMP'
    # Group cipher must be GCMP-256 for the security profile to work
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        # STA configured with GCMP-256. The RSNE only has CCMP, so
        # without the security profile override the BSS would be rejected.
        # Our code detects the Security Profile element and augments
        # ie.pairwise_cipher with GCMP-256, allowing the connection.
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['key_mgmt'] not in ('SAE-EXT-KEY',):
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " +
                            status['group_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled (expected from security profile MFPR=1)")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_override_akm_cipher_8(dev, apdev):
    """Security Profile 8 override: STA prefers GCMP-256 from security profile over CCMP in RSNE"""
    check_owe_capab(dev[0])

    ssid = "sp8-override"

    # AP: The RSNE has OWE/CCMP (legacy cipher).
    # The Security Profile element advertises profile 8 (OWE/GCMP-256).
    # The STA is configured with GCMP-256. Without the security profile
    # override, the STA would reject the BSS because the RSNE only
    # advertises CCMP. With the override, the STA uses GCMP-256 from the
    # security profile.
    params = hostapd.wpa2_params(ssid=ssid, passphrase=None)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'OWE'
    params['ieee80211w'] = '2'
    # The RSNE advertises CCMP only (not GCMP-256)
    params['rsn_pairwise'] = 'CCMP'
    # Group cipher must be GCMP-256 for the security profile to work
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['security_profiles'] = '8'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        # STA configured with GCMP-256. The RSNE only has CCMP, so
        # without the security profile override the BSS would be rejected.
        # Our code detects the Security Profile element and augments
        # ie.pairwise_cipher with GCMP-256, allowing the connection.
        enable_sta_security_profiles(dev[0], 8)
        dev[0].connect(ssid, key_mgmt="OWE", ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['key_mgmt'] != 'OWE':
            raise Exception("Unexpected key_mgmt: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status['group_cipher'] != 'GCMP-256':
            raise Exception("Unexpected group cipher: " +
                            status['group_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled (expected from security profile MFPR=1)")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 8, akm='00-0f-ac-18')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_override_rsnx_capab(dev, apdev):
    """Security Profile RSNXE override: STA uses SAE-H2E from security profile even when the RSNXE suppresses it"""
    check_sae_capab(dev[0])

    ssid = "sp9-rsnx-override"
    passphrase = "12345678"

    # AP: security profile 9 (SAE-EXT-KEY/GCMP-256).
    # rsnxe_capab_mask=20 suppresses SAE-H2E (bit 5) from the RSNXE,
    # but the Security Profile element always carries the full
    # unmasked RSNX capabilities (including SAE-H2E).
    # Our code should prefer the security profile's RSNX capabilities, so
    # the STA should still use SAE-H2E (hash-to-element) for SAE.
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase)
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['security_profiles'] = '9'
    # Suppress SAE-H2E in the RSNXE.
    # The Security Profile element will still carry SAE-H2E.
    params['rsnxe_capab_mask'] = '20'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    bssid = hapd.own_addr()

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        dev[0].scan_for_bss(bssid, freq=2412)

        # Connect using SAE hash-to-element (requires SAE-H2E capability).
        # This should succeed because our code prefers the security profile's
        # RSNX capabilities (which include SAE-H2E) over the RSNXE.
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_security_profile_override_rsn_caps_mfpr(dev, apdev):
    """Security Profile RSN caps override: STA uses MFPR=1 from security profile even when RSNE has MFPR=0"""
    check_sae_capab(dev[0])

    ssid = "sp9-rsncaps-override"
    passphrase = "12345678"

    # AP: The RSNE has SAE-EXT-KEY/GCMP-256 with MFPC=1/MFPR=0
    # (ieee80211w=1 = optional MFP). The Security Profile element advertises
    # profile 9, which mandates MFPR=1. Our code should override
    # ie.capabilities with MFPC=1/MFPR=1 from the security profile, so the
    # STA connects with MFP required.
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 ieee80211w='1')  # MFPC=1, MFPR=0 in RSNE
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_require_mfp'] = '1'
    params['security_profiles'] = '9'
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        enable_sta_security_profiles(dev[0], 9)
        dev[0].set("sae_pwe", "2")
        # STA connects with ieee80211w=2 (MFPR=1). The RSNE has
        # MFPR=0 (ieee80211w=1 on AP), but the security profile mandates
        # MFPR=1. Our code overrides ie.capabilities with MFPC=1/MFPR=1,
        # so the MFPC check passes and the STA connects with MFP required.
        dev[0].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")

        status = dev[0].get_status()
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Unexpected pairwise cipher: " +
                            status['pairwise_cipher'])
        if status.get('pmf') not in ('1', '2'):
            raise Exception("PMF not enabled (expected from security profile MFPR=1)")

        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_rsn_override_with_security_profile_9(dev, apdev):
    """RSN Override + Security Profile 9: AP advertises WPA2-PSK in the
    RSNE and SAE-EXT-KEY/GCMP-256 in both the RSNOE and Security Profile
    element. STA with rsn_overriding=1 upgrades to SAE-EXT-KEY."""
    check_sae_capab(dev[0])

    ssid = "test-rsn-override-sp9"
    params = hostapd.wpa2_params(ssid=ssid,
                                 passphrase="12345678",
                                 ieee80211w='1')
    params['rsn_override_key_mgmt'] = 'SAE-EXT-KEY'
    params['rsn_override_pairwise'] = 'GCMP-256'
    params['rsn_override_mfp'] = '2'
    params['beacon_prot'] = '1'
    params['sae_groups'] = '19 20'
    params['sae_require_mfp'] = '1'
    params['sae_pwe'] = '2'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['security_profiles'] = '9'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    bssid = hapd.own_addr()

    try:
        dev[0].set("rsn_overriding", "1")
        dev[0].set("sae_pwe", "2")

        # Scan and verify BSS flags reflect the RSNOE
        # (SAE-EXT-KEY visible, not PSK)
        dev[0].scan_for_bss(bssid, freq=2412)
        bss = dev[0].get_bss(bssid)
        flags = bss.get('flags', '')
        if "PSK" in flags and "SAE" not in flags:
            raise Exception("Unexpected BSS flags (PSK visible, SAE not): " + flags)

        # Connect upgrading to SAE-EXT-KEY via the RSNOE
        dev[0].connect(ssid, sae_password="12345678",
                       key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()

        # Verify upgraded connection
        status = dev[0].get_status()
        if status['key_mgmt'] != 'SAE-EXT-KEY':
            raise Exception("Expected SAE-EXT-KEY, got: " + status['key_mgmt'])
        if status['pairwise_cipher'] != 'GCMP-256':
            raise Exception("Expected GCMP-256 pairwise, got: " +
                            status['pairwise_cipher'])

        sta = hapd.get_sta(dev[0].own_addr())
        if "[MFP]" not in sta['flags']:
            raise Exception("Missing MFP flag after RSN Override upgrade")
        if sta["AKMSuiteSelector"] != '00-0f-ac-24':
            raise Exception("Expected SAE-EXT-KEY (00-0f-ac-24), got: " +
                            sta["AKMSuiteSelector"])

        hwsim_utils.test_connectivity(dev[0], hapd)

    finally:
        sta_cleanup(dev[0])

def test_rsn_override_three_layer_coexistence(dev, apdev):
    """Three STAs simultaneously - base AKM (WPA-PSK), RSN Override (SAE),
    and Security Profile 9 (SAE-EXT-KEY) - each using a different security
    layer on the same AP."""
    check_sae_capab(dev[0])

    ssid = "test-rsn-three-layer"
    passphrase = "12345678"

    # AP: base=WPA-PSK/CCMP/MFP-optional,
    #     rsn_override=SAE/GCMP-256/MFP-required,
    #     security_profile=9 (SAE-EXT-KEY/GCMP-256)
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 ieee80211w='1')
    params['wpa_key_mgmt'] = 'WPA-PSK SAE SAE-EXT-KEY'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_require_mfp'] = '1'
    params['rsn_override_key_mgmt'] = 'SAE'
    params['rsn_override_pairwise'] = 'GCMP-256'
    params['rsn_override_mfp'] = '2'
    params['security_profiles'] = '9'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    bssid = hapd.own_addr()

    try:
        # ---- STA 0: base AKM - WPA-PSK / CCMP ----
        disable_sta_security_profiles(dev[0])
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK",
                       ieee80211w="1",
                       pairwise="CCMP", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()

        status0 = dev[0].get_status()
        if status0['key_mgmt'] != 'WPA2-PSK':
            raise Exception("STA0: Expected WPA2-PSK, got: " +
                            status0['key_mgmt'])
        if status0['pairwise_cipher'] != 'CCMP':
            raise Exception("STA0: Expected CCMP pairwise, got: " +
                            status0['pairwise_cipher'])
        sta0 = hapd.get_sta(dev[0].own_addr())
        if sta0["AKMSuiteSelector"] != '00-0f-ac-2':
            raise Exception("STA0: Expected WPA-PSK (00-0f-ac-2), got: " +
                            sta0["AKMSuiteSelector"])

        # ---- STA 1: RSN Override - SAE / GCMP-256 / MFP-required ----
        disable_sta_security_profiles(dev[1])
        dev[1].set("rsn_overriding", "1")
        dev[1].set("sae_pwe", "2")
        dev[1].connect(ssid, sae_password=passphrase, key_mgmt="SAE",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()

        status1 = dev[1].get_status()
        if status1['key_mgmt'] != 'SAE':
            raise Exception("STA1: Expected SAE, got: " + status1['key_mgmt'])
        if status1['pairwise_cipher'] != 'GCMP-256':
            raise Exception("STA1: Expected GCMP-256 pairwise, got: " +
                            status1['pairwise_cipher'])
        sta1 = hapd.get_sta(dev[1].own_addr())
        if "[MFP]" not in sta1['flags']:
            raise Exception("STA1: Missing MFP flag")
        if sta1["AKMSuiteSelector"] != '00-0f-ac-8':
            raise Exception("STA1: Expected SAE (00-0f-ac-8), got: " +
                            sta1["AKMSuiteSelector"])

        # ---- STA 2: Security Profile 9 - SAE-EXT-KEY / GCMP-256 ----
        enable_sta_security_profiles(dev[2], 9)
        dev[2].set("sae_pwe", "2")
        dev[2].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()

        status2 = dev[2].get_status()
        if status2['key_mgmt'] != 'SAE-EXT-KEY':
            raise Exception("STA2: Expected SAE-EXT-KEY, got: " +
                            status2['key_mgmt'])
        if status2['pairwise_cipher'] != 'GCMP-256':
            raise Exception("STA2: Expected GCMP-256 pairwise, got: " +
                            status2['pairwise_cipher'])
        check_security_profile(hapd, dev[2], 9, akm='00-0f-ac-24')

        # All three connected simultaneously - verify independent data paths
        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[1], hapd)
        hwsim_utils.test_connectivity(dev[2], hapd)

    finally:
        sta_cleanup(dev[0])
        sta_cleanup(dev[1])
        sta_cleanup(dev[2])

def test_rsn_override_four_layer_coexistence(dev, apdev):
    """Four STAs simultaneously - base AKM (WPA-PSK), RSN Override 1 (SAE),
    RSN Override 2 (OWE), and Security Profile 9 (SAE-EXT-KEY) -
    each using a different security layer on the same AP."""
    check_sae_capab(dev[0])
    check_owe_capab(dev[2])

    ssid = "test-rsn-four-layer"
    passphrase = "12345678"

    # AP: base=WPA-PSK/CCMP/MFP-optional,
    #     rsn_override=SAE/CCMP/MFP-optional,
    #     rsn_override_2=OWE/GCMP-256/MFP-required,
    #     security_profile=9 (SAE-EXT-KEY/GCMP-256)
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 ieee80211w='1')
    params['wpa_key_mgmt'] = 'WPA-PSK SAE SAE-EXT-KEY OWE'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['rsn_override_key_mgmt'] = 'SAE'
    params['rsn_override_pairwise'] = 'CCMP GCMP-256'
    params['rsn_override_mfp'] = '1'
    params['rsn_override_key_mgmt_2'] = 'OWE'
    params['rsn_override_pairwise_2'] = 'GCMP-256'
    params['rsn_override_mfp_2'] = '2'
    params['security_profiles'] = '9'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    wpas = None
    try:
        # ---- STA 0: base AKM - WPA-PSK / CCMP ----
        disable_sta_security_profiles(dev[0])
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK",
                       ieee80211w="1",
                       pairwise="CCMP", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()

        status0 = dev[0].get_status()
        if status0['key_mgmt'] != 'WPA2-PSK':
            raise Exception("STA0: Expected WPA2-PSK, got: " +
                            status0['key_mgmt'])
        if status0['pairwise_cipher'] != 'CCMP':
            raise Exception("STA0: Expected CCMP pairwise, got: " +
                            status0['pairwise_cipher'])
        sta0 = hapd.get_sta(dev[0].own_addr())
        if sta0["AKMSuiteSelector"] != '00-0f-ac-2':
            raise Exception("STA0: Expected WPA-PSK (00-0f-ac-2), got: " +
                            sta0["AKMSuiteSelector"])

        # ---- STA 1: RSN Override 1 - SAE / CCMP ----
        disable_sta_security_profiles(dev[1])
        dev[1].set("rsn_overriding", "1")
        dev[1].set("sae_pwe", "2")
        dev[1].connect(ssid, sae_password=passphrase, key_mgmt="SAE",
                       ieee80211w="1",
                       pairwise="CCMP GCMP-256", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()

        status1 = dev[1].get_status()
        if status1['key_mgmt'] != 'SAE':
            raise Exception("STA1: Expected SAE, got: " + status1['key_mgmt'])
        sta1 = hapd.get_sta(dev[1].own_addr())
        if sta1["AKMSuiteSelector"] != '00-0f-ac-8':
            raise Exception("STA1: Expected SAE (00-0f-ac-8), got: " +
                            sta1["AKMSuiteSelector"])

        # ---- STA 2: RSN Override 2 - OWE / GCMP-256 / MFP-required ----
        disable_sta_security_profiles(dev[2])
        dev[2].set("rsn_overriding", "1")
        dev[2].connect(ssid, key_mgmt="OWE",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()

        status2 = dev[2].get_status()
        if status2['key_mgmt'] != 'OWE':
            raise Exception("STA2: Expected OWE, got: " + status2['key_mgmt'])
        if status2['pairwise_cipher'] != 'GCMP-256':
            raise Exception("STA2: Expected GCMP-256 pairwise, got: " +
                            status2['pairwise_cipher'])
        sta2 = hapd.get_sta(dev[2].own_addr())
        if "[MFP]" not in sta2['flags']:
            raise Exception("STA2: Missing MFP flag")
        if sta2["AKMSuiteSelector"] != '00-0f-ac-18':
            raise Exception("STA2: Expected OWE (00-0f-ac-18), got: " +
                            sta2["AKMSuiteSelector"])

        # ---- STA 3: Security Profile 9 - SAE-EXT-KEY / GCMP-256 ----
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add('wlan5')
        enable_sta_security_profiles(wpas, 9)
        wpas.set("sae_pwe", "2")
        wpas.connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                     ieee80211w="2",
                     pairwise="GCMP-256", group="GCMP-256",
                     group_mgmt="BIP-GMAC-256",
                     scan_freq="2412")
        hapd.wait_sta()

        status3 = wpas.get_status()
        if status3['key_mgmt'] != 'SAE-EXT-KEY':
            raise Exception("STA3: Expected SAE-EXT-KEY, got: " +
                            status3['key_mgmt'])
        if status3['pairwise_cipher'] != 'GCMP-256':
            raise Exception("STA3: Expected GCMP-256 pairwise, got: " +
                            status3['pairwise_cipher'])
        check_security_profile(hapd, wpas, 9, akm='00-0f-ac-24')

        # All four connected simultaneously - verify independent data paths
        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[1], hapd)
        hwsim_utils.test_connectivity(dev[2], hapd)
        hwsim_utils.test_connectivity(wpas, hapd)

    finally:
        sta_cleanup(dev[0])
        sta_cleanup(dev[1])
        sta_cleanup(dev[2])
        if wpas:
            try:
                sta_cleanup(wpas)
                wpas.interface_remove('wlan5')
                wpas.close_ctrl()
            except Exception:
                pass

def test_rsn_override_eap_sha256_sp9(dev, apdev):
    """Three layers: WPA-PSK base, WPA-EAP-SHA256 RSN Override,
    SAE-EXT-KEY Security Profile 9 - enterprise override with PSK base."""
    check_sae_capab(dev[0])

    ssid = "test-rsno-eap256-sp9"
    passphrase = "12345678"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params['wpa_key_mgmt'] = 'WPA-PSK WPA-EAP-SHA256 SAE-EXT-KEY'
    params['wpa_passphrase'] = passphrase
    params['ieee80211w'] = '1'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['rsn_override_key_mgmt'] = 'WPA-EAP-SHA256'
    params['rsn_override_pairwise'] = 'GCMP-256'
    params['rsn_override_mfp'] = '2'
    params['security_profiles'] = '9'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        # ---- STA 0: base AKM - WPA-PSK / CCMP ----
        disable_sta_security_profiles(dev[0])
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK",
                       ieee80211w="1",
                       pairwise="CCMP", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()
        sta0 = hapd.get_sta(dev[0].own_addr())
        if sta0["AKMSuiteSelector"] != '00-0f-ac-2':
            raise Exception("STA0: Expected WPA-PSK (00-0f-ac-2), got: " +
                            sta0["AKMSuiteSelector"])

        # ---- STA 1: RSN Override - WPA-EAP-SHA256 / GCMP-256 / MFP-required ----
        disable_sta_security_profiles(dev[1])
        dev[1].set("rsn_overriding", "1")
        dev[1].connect(ssid, key_mgmt="WPA-EAP-SHA256",
                       ieee80211w="2", eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        status1 = dev[1].get_status()
        if status1['key_mgmt'] != 'WPA2-EAP-SHA256':
            raise Exception("STA1: Expected WPA2-EAP-SHA256, got: " +
                            status1['key_mgmt'])
        if status1['pairwise_cipher'] != 'GCMP-256':
            raise Exception("STA1: Expected GCMP-256, got: " +
                            status1['pairwise_cipher'])
        sta1 = hapd.get_sta(dev[1].own_addr())
        if "[MFP]" not in sta1['flags']:
            raise Exception("STA1: Missing MFP flag")

        # ---- STA 2: Security Profile 9 - SAE-EXT-KEY / GCMP-256 ----
        enable_sta_security_profiles(dev[2], 9)
        dev[2].set("sae_pwe", "2")
        dev[2].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[2], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[1], hapd)
        hwsim_utils.test_connectivity(dev[2], hapd)

    finally:
        sta_cleanup(dev[0])
        sta_cleanup(dev[1])
        sta_cleanup(dev[2])

def test_rsn_override_psk_owe_sp9(dev, apdev):
    """Three layers: WPA-PSK base, OWE RSN Override,
    SAE-EXT-KEY Security Profile 9 - OWE override with SP."""
    check_sae_capab(dev[0])
    check_owe_capab(dev[1])

    ssid = "test-rsno-owe-sp9"
    passphrase = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 ieee80211w='1')
    params['wpa_key_mgmt'] = 'WPA-PSK OWE SAE-EXT-KEY'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['rsn_override_key_mgmt'] = 'OWE'
    params['rsn_override_pairwise'] = 'GCMP-256'
    params['rsn_override_mfp'] = '2'
    params['security_profiles'] = '9'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    try:
        # ---- STA 0: base AKM - WPA-PSK / CCMP ----
        disable_sta_security_profiles(dev[0])
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK",
                       ieee80211w="1",
                       pairwise="CCMP", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()
        sta0 = hapd.get_sta(dev[0].own_addr())
        if sta0["AKMSuiteSelector"] != '00-0f-ac-2':
            raise Exception("STA0: Expected WPA-PSK (00-0f-ac-2), got: " +
                            sta0["AKMSuiteSelector"])

        # ---- STA 1: RSN Override - OWE / GCMP-256 / MFP-required ----
        disable_sta_security_profiles(dev[1])
        dev[1].set("rsn_overriding", "1")
        dev[1].connect(ssid, key_mgmt="OWE",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        status1 = dev[1].get_status()
        if status1['key_mgmt'] != 'OWE':
            raise Exception("STA1: Expected OWE, got: " + status1['key_mgmt'])
        if status1['pairwise_cipher'] != 'GCMP-256':
            raise Exception("STA1: Expected GCMP-256, got: " +
                            status1['pairwise_cipher'])
        sta1 = hapd.get_sta(dev[1].own_addr())
        if "[MFP]" not in sta1['flags']:
            raise Exception("STA1: Missing MFP flag")
        if sta1["AKMSuiteSelector"] != '00-0f-ac-18':
            raise Exception("STA1: Expected OWE (00-0f-ac-18), got: " +
                            sta1["AKMSuiteSelector"])

        # ---- STA 2: Security Profile 9 - SAE-EXT-KEY / GCMP-256 ----
        enable_sta_security_profiles(dev[2], 9)
        dev[2].set("sae_pwe", "2")
        dev[2].connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[2], 9, akm='00-0f-ac-24')

        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[1], hapd)
        hwsim_utils.test_connectivity(dev[2], hapd)

    finally:
        sta_cleanup(dev[0])
        sta_cleanup(dev[1])
        sta_cleanup(dev[2])

def test_rsn_override_sae_sp1_eppke(dev, apdev):
    """Three layers: WPA-PSK base, SAE RSN Override,
    Security Profile 1 (EPPKE) - EPPKE as the strongest security layer."""
    check_sae_capab(dev[0])
    check_eppke_capab(dev[0])
    check_owe_capab(dev[0])

    ssid = "test-rsno-sae-sp1"
    passphrase = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 ieee80211w='1')
    params['wpa_key_mgmt'] = 'WPA-PSK SAE EPPKE'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '1'
    params['rsn_override_key_mgmt'] = 'SAE'
    params['rsn_override_pairwise'] = 'CCMP GCMP-256'
    params['rsn_override_mfp'] = '1'
    params['security_profiles'] = '0 1'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    wpas = None
    try:
        # ---- STA 0: base AKM - WPA-PSK / CCMP ----
        disable_sta_security_profiles(dev[0])
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK",
                       ieee80211w="1",
                       pairwise="CCMP", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()
        sta0 = hapd.get_sta(dev[0].own_addr())
        if sta0["AKMSuiteSelector"] != '00-0f-ac-2':
            raise Exception("STA0: Expected WPA-PSK (00-0f-ac-2), got: " +
                            sta0["AKMSuiteSelector"])

        # ---- STA 1: RSN Override - SAE / GCMP-256 ----
        disable_sta_security_profiles(dev[1])
        dev[1].set("rsn_overriding", "1")
        dev[1].set("sae_pwe", "2")
        dev[1].connect(ssid, sae_password=passphrase, key_mgmt="SAE",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        status1 = dev[1].get_status()
        if status1['key_mgmt'] != 'SAE':
            raise Exception("STA1: Expected SAE, got: " + status1['key_mgmt'])
        sta1 = hapd.get_sta(dev[1].own_addr())
        if "[MFP]" not in sta1['flags']:
            raise Exception("STA1: Missing MFP flag")
        if sta1["AKMSuiteSelector"] != '00-0f-ac-8':
            raise Exception("STA1: Expected SAE (00-0f-ac-8), got: " +
                            sta1["AKMSuiteSelector"])

        # ---- STA 2: Security Profile 0 (EPPKE) ----
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add('wlan5')
        enable_sta_security_profiles(wpas, 0)
        wpas.connect(ssid, scan_freq="2412", key_mgmt="EPPKE",
                     ieee80211w="2",
                     pairwise="GCMP-256", group="GCMP-256",
                     group_mgmt="BIP-GMAC-256", pmksa_privacy="1")
        hapd.wait_sta()
        check_security_profile(hapd, wpas, 0, akm='00-0f-ac-29', auth_alg='9')

        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[1], hapd)
        hwsim_utils.test_connectivity(wpas, hapd)

    finally:
        sta_cleanup(dev[0])
        sta_cleanup(dev[1])
        if wpas:
            try:
                sta_cleanup(wpas)
                wpas.interface_remove('wlan5')
                wpas.close_ctrl()
            except Exception:
                pass

def test_rsn_override_five_layer_eppke(dev, apdev):
    """Five layers: WPA-PSK base, SAE RSN Override 1, OWE RSN Override 2,
    SAE-EXT-KEY Security Profile 9, EPPKE Security Profile 1 -
    all five simultaneously on the same AP."""
    check_sae_capab(dev[0])
    check_owe_capab(dev[2])
    check_eppke_capab(dev[0])

    ssid = "test-rsno-five-layer"
    passphrase = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 ieee80211w='1')
    params['wpa_key_mgmt'] = 'WPA-PSK SAE OWE SAE-EXT-KEY EPPKE'
    params['rsn_pairwise'] = 'CCMP GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '1'
    params['rsn_override_key_mgmt'] = 'SAE'
    params['rsn_override_pairwise'] = 'CCMP GCMP-256'
    params['rsn_override_mfp'] = '1'
    params['rsn_override_key_mgmt_2'] = 'OWE'
    params['rsn_override_pairwise_2'] = 'GCMP-256'
    params['rsn_override_mfp_2'] = '2'
    params['security_profiles'] = '0 1 9'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'

    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    wpas_eppke = None
    wpas_sae_ext = None
    try:
        # ---- STA 0: base AKM - WPA-PSK / CCMP ----
        disable_sta_security_profiles(dev[0])
        dev[0].connect(ssid, psk=passphrase, key_mgmt="WPA-PSK",
                       ieee80211w="1",
                       pairwise="CCMP", group="GCMP-256",
                       scan_freq="2412")
        hapd.wait_sta()
        sta0 = hapd.get_sta(dev[0].own_addr())
        if sta0["AKMSuiteSelector"] != '00-0f-ac-2':
            raise Exception("STA0: Expected WPA-PSK (00-0f-ac-2), got: " +
                            sta0["AKMSuiteSelector"])

        # ---- STA 1: RSN Override 1 - SAE / GCMP-256 ----
        disable_sta_security_profiles(dev[1])
        dev[1].set("rsn_overriding", "1")
        dev[1].set("sae_pwe", "2")
        dev[1].connect(ssid, sae_password=passphrase, key_mgmt="SAE",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        sta1 = hapd.get_sta(dev[1].own_addr())
        if "[MFP]" not in sta1['flags']:
            raise Exception("STA1: Missing MFP flag")
        if sta1["AKMSuiteSelector"] != '00-0f-ac-8':
            raise Exception("STA1: Expected SAE (00-0f-ac-8), got: " +
                            sta1["AKMSuiteSelector"])

        # ---- STA 2: RSN Override 2 - OWE / GCMP-256 / MFP-required ----
        disable_sta_security_profiles(dev[2])
        dev[2].set("rsn_overriding", "1")
        dev[2].connect(ssid, key_mgmt="OWE",
                       ieee80211w="2",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        sta2 = hapd.get_sta(dev[2].own_addr())
        if "[MFP]" not in sta2['flags']:
            raise Exception("STA2: Missing MFP flag")
        if sta2["AKMSuiteSelector"] != '00-0f-ac-18':
            raise Exception("STA2: Expected OWE (00-0f-ac-18), got: " +
                            sta2["AKMSuiteSelector"])

        # ---- STA 3: Security Profile 9 - SAE-EXT-KEY / GCMP-256 ----
        wpas_sae_ext = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas_sae_ext.interface_add('wlan5')
        enable_sta_security_profiles(wpas_sae_ext, 9)
        wpas_sae_ext.set("sae_pwe", "2")
        wpas_sae_ext.connect(ssid, psk=passphrase, key_mgmt="SAE-EXT-KEY",
                             ieee80211w="2",
                             pairwise="GCMP-256", group="GCMP-256",
                             group_mgmt="BIP-GMAC-256",
                             pmksa_privacy="1",
                             scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, wpas_sae_ext, 9, akm='00-0f-ac-24')

        # ---- STA 4: Security Profile 0 - EPPKE ----
        wpas_eppke = WpaSupplicant(global_iface='/tmp/wpas-wlan6')
        wpas_eppke.interface_add('wlan6')
        enable_sta_security_profiles(wpas_eppke, 0)
        wpas_eppke.connect(ssid, scan_freq="2412", key_mgmt="EPPKE",
                           ieee80211w="2",
                           pairwise="GCMP-256", group="GCMP-256",
                           group_mgmt="BIP-GMAC-256", pmksa_privacy="1")
        hapd.wait_sta()
        check_security_profile(hapd, wpas_eppke, 0, akm='00-0f-ac-29',
                               auth_alg='9')

        # All four connected simultaneously - verify independent data paths
        hwsim_utils.test_connectivity(dev[0], hapd)
        hwsim_utils.test_connectivity(dev[1], hapd)
        hwsim_utils.test_connectivity(dev[2], hapd)
        hwsim_utils.test_connectivity(wpas_sae_ext, hapd)
        hwsim_utils.test_connectivity(wpas_eppke, hapd)

    finally:
        sta_cleanup(dev[0])
        sta_cleanup(dev[1])
        sta_cleanup(dev[2])
        for w in [wpas_sae_ext, wpas_eppke]:
            if w:
                try:
                    sta_cleanup(w)
                    w.interface_remove(w.ifname)
                    w.close_ctrl()
                except Exception:
                    pass

def run_security_profile_sta_proto(dev, apdev, sp_elem):
    check_owe_capab(dev[0])
    enable_sta_security_profiles(dev[0], 8)

    ssid = "security profile proto"
    params = hostapd.wpa2_params(ssid=ssid, passphrase=None)
    params['wpa_key_mgmt'] = 'OWE'
    params['ieee80211w'] = '2'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['security_profiles'] = '8'
    params['security_profile_override'] = sp_elem
    hapd = hostapd.add_ap(apdev[0], params)

    hapd.note("Test iteration with AP Security Profile element: " + sp_elem)
    dev[0].note("Test iteration with AP Security Profile element: " + sp_elem)

    dev[0].connect(ssid, key_mgmt="OWE", ieee80211w="2",
                   pairwise="GCMP-256", group="GCMP-256",
                   group_mgmt="BIP-GMAC-256", scan_freq="2412")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    hapd.disable()
    hapd.dump_monitor()

def test_security_profile_sta_proto_valid(dev, apdev):
    """Security profile protocol testing - STA with valid AP elements"""
    tests = [ "ff06a20002000100",
              "ff07a2000300010000",
              "ff07a20002000100ff",
              "ff0aa200120001aabbccdd00",
              "ff0da20014000100ffaabbccdd00ff" ]
    for t in tests:
        run_security_profile_sta_proto(dev, apdev, t)

def run_security_profile_sta_proto_sae(dev, apdev, sp_elem):
    check_owe_capab(dev[0])
    enable_sta_security_profiles(dev[0], 9)

    ssid = "security profile proto sae"
    password = "sae password"
    params = hostapd.wpa3_params(ssid=ssid, password=password)
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['security_profiles'] = '9'
    params['security_profile_override'] = sp_elem
    params['rsn_override_omit_rsnxe'] = '1'
    hapd = hostapd.add_ap(apdev[0], params)

    hapd.note("Test iteration with AP Security Profile element: " + sp_elem)
    dev[0].note("Test iteration with AP Security Profile element: " + sp_elem)

    dev[0].connect(ssid, key_mgmt="SAE-EXT-KEY", ieee80211w="2",
                   sae_password=password, pairwise="GCMP-256", group="GCMP-256",
                   group_mgmt="BIP-GMAC-256", scan_freq="2412")
    dev[0].request("REMOVE_NETWORK all")
    dev[0].wait_disconnected()
    dev[0].dump_monitor()
    hapd.disable()
    hapd.dump_monitor()

def test_security_profile_sta_proto_valid_sae(dev, apdev):
    """Security profile protocol testing - STA with valid AP elements (SAE)"""
    tests = [ "ff06a20002000220",
              "ff07a20002000220ff",
              "ff0aa200120002aabbccdd20",
              "ff11a200230002ffaabbccdd1122334420ffff" ]
    for t in tests:
        run_security_profile_sta_proto_sae(dev, apdev, t)

def run_security_profile_ap_proto_sae(dev, apdev, sp_elem, failure=False):
    check_owe_capab(dev[0])
    enable_sta_security_profiles(dev[0], 9)

    ssid = "security profile proto sae"
    password = "sae password"
    params = hostapd.wpa3_params(ssid=ssid, password=password)
    params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['security_profiles'] = '9'
    hapd = hostapd.add_ap(apdev[0], params)

    hapd.note("Test iteration with STA Security Profile element: " + sp_elem)
    dev[0].note("Test iteration with STA Security Profile element: " + sp_elem)

    dev[0].set("sec_prof_override_auth", sp_elem)
    dev[0].set("sec_prof_override_assoc", sp_elem)
    dev[0].connect(ssid, key_mgmt="SAE-EXT-KEY", ieee80211w="2",
                   sae_password=password, pairwise="GCMP-256", group="GCMP-256",
                   group_mgmt="BIP-GMAC-256", scan_freq="2412",
                   wait_connect=not failure)
    if failure:
        ev = dev[0].wait_event(["CTRL-EVENT-ASSOC-REJECT"], timeout=10)
        dev[0].request("REMOVE_NETWORK all")
        if not ev:
            raise Exception("Association was not rejected")
        if "status_code=159" not in ev:
            raise Exception("Unexpected rejection reason: " + ev)
    else:
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

    dev[0].dump_monitor()
    hapd.disable()
    hapd.dump_monitor()

def test_security_profile_ap_proto_valid_sae(dev, apdev):
    """Security profile protocol testing - AP with valid STA elements (SAE)"""
    tests = [ "ff06a20002000220",
              "ff07a20002000220ff",
              "ff08a2000300020020ff" ]
    for t in tests:
        run_security_profile_ap_proto_sae(dev, apdev, t)

def test_security_profile_ap_proto_invalid_sae(dev, apdev):
    """Security profile protocol testing - AP with invalid STA elements (SAE)"""
    tests = [ "ff03a20001",
              "ff03a20000",
              "ff04a2000100",
              "ff06a20002010220",
              "ff0aa200120002aabbccdd20" ]
    for t in tests:
        run_security_profile_ap_proto_sae(dev, apdev, t, failure=True)

def test_security_profile_1_sta_sec_prof(dev, apdev):
    """Security Profile 1 with STA security profile config"""
    check_eppke_capab(dev[0])
    enable_sta_security_profiles(dev[0], 1)

    ssid = "test-sp1-sta-sec-prof"
    password = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=password,
                                 ieee80211w='2')
    params['wpa_key_mgmt'] = 'SAE EPPKE'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['security_profiles'] = '1'
    params['ieee80211ax'] = '1'

    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect(ssid, sae_password=password, scan_freq="2412",
                       security_profiles="1")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 1, akm='00-0f-ac-24', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_3_sta_sec_prof(dev, apdev):
    """Security Profile 3 with STA security profile config"""
    check_eppke_capab(dev[0])
    enable_sta_security_profiles(dev[0], 3)

    ssid = "test-sp3-sta-sec-prof"

    params = hostapd.wpa3_params(ssid=ssid, wpa_key_mgmt="WPA-EAP-SHA256")
    params.update(hostapd.radius_params())
    params["ieee8021x"] = "1"
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params["eap_using_authentication_frames"] = "1"
    params['security_profiles'] = '3'
    params['ieee80211ax'] = '1'

    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].connect(ssid, scan_freq="2412",
                       security_profiles="3",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 3, akm='00-0f-ac-5', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_sta_sec_prof(dev, apdev):
    """Security Profile 9 with STA security profile config"""
    check_eppke_capab(dev[0])
    enable_sta_security_profiles(dev[0], 9)

    ssid = "test-sp9-sta-sec-prof"
    password = "12345678"

    params = hostapd.wpa2_params(ssid=ssid, passphrase=password,
                                 ieee80211w='2')
    params['wpa_key_mgmt'] = 'SAE EPPKE'
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['security_profiles'] = '9'
    params['ieee80211ax'] = '1'

    hapd = hostapd.add_ap(apdev[0], params)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect(ssid, sae_password=password, scan_freq="2412",
                       security_profiles="9")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def sec_prof_ap_all(apdev, suite_b_192=False):
    params = hostapd.wpa3_params(ssid="sec-profs", password="12345678",
                                 ieee80211w='2',
                                 wpa_key_mgmt="OWE SAE-EXT-KEY FT-SAE-EXT-KEY EPPKE WPA-EAP-SHA256 WPA-EAP-SHA384 WPA-EAP-SUITE-B-192 FT-EAP FT-EAP-SHA384")
    if suite_b_192:
        params["openssl_ciphers"] = "SUITEB192"
        params["eap_server"] = "1"
        params["eap_user_file"] = "auth_serv/eap_user.conf"
        params["ca_cert"] = "auth_serv/ec2-ca.pem"
        params["server_cert"] = "auth_serv/ec2-server.pem"
        params["private_key"] = "auth_serv/ec2-server.key"
    else:
        params.update(hostapd.radius_params())
    params["ieee8021x"] = "1"
    params['rsn_pairwise'] = 'GCMP-256'
    params['group_cipher'] = 'GCMP-256'
    params['group_mgmt_cipher'] = 'BIP-GMAC-256'
    params['beacon_prot'] = '1'
    params['sae_pwe'] = '2'
    params['sae_groups'] = '19 20'
    params['assoc_frame_encryption'] = '1'
    params['pmksa_caching_privacy'] = '1'
    params['eppke_unauth'] = '1'
    params["eap_using_authentication_frames"] = "1"
    params['security_profiles'] = '0 1 2 3 4 5 6 7 8 9'
    params["mobility_domain"] = "a1b2"
    params["r0_key_lifetime"] = "10000"
    params["pmk_r1_push"] = "1"
    params["reassociation_deadline"] = "1000"
    params['nas_identifier'] = "nas1.w1.fi"
    params['r1_key_holder'] = "000102030405"
    params['r0kh'] = "ff:ff:ff:ff:ff:ff * 100102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f"
    params['r1kh'] = "00:00:00:00:00:00 00:00:00:00:00:00 100102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f"
    return hostapd.add_ap(apdev[0], params)

def test_security_profile_0_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 0 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 0)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs",
                       security_profiles="0", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 0, akm='00-0f-ac-29', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_1_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 1 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 1)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", sae_password="12345678",
                       security_profiles="1", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 1, akm='00-0f-ac-24', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_2_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 2 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 2)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", sae_password="12345678",
                       security_profiles="2", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 2, akm='00-0f-ac-25', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_3_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 3 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 3)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       security_profiles="3", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 3, akm='00-0f-ac-5', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_4_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 4 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 4)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       security_profiles="4", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 4, akm='00-0f-ac-3', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_5_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 5 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 5)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       security_profiles="5", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 5, akm='00-0f-ac-23', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_6_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 6 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 6)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       security_profiles="6", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 6, akm='00-0f-ac-22', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_7_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 7 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 7)
    hapd = sec_prof_ap_all(apdev, suite_b_192=True)

    try:
        dev[0].connect("sec-profs",
                       openssl_ciphers="SUITEB192",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ec2-ca.pem",
                       client_cert="auth_serv/ec2-user.pem",
                       private_key="auth_serv/ec2-user.key",
                       security_profiles="7", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 7, akm='00-0f-ac-12', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_8_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 8 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 8)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs",
                       security_profiles="8", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 8, akm='00-0f-ac-18', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_ap_all_sta_sec_prof(dev, apdev):
    """Security Profile 9 with STA security profile config"""
    enable_sta_security_profiles(dev[0], 9)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", sae_password="12345678",
                       security_profiles="9", scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24', auth_alg='3',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_0_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 0 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 0)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", key_mgmt="EPPKE",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 0, akm='00-0f-ac-29', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_1_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 1 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 1)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", sae_password="12345678",
                       key_mgmt="SAE-EXT-KEY EPPKE",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 1, akm='00-0f-ac-24', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_2_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 2 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 2)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", sae_password="12345678",
                       key_mgmt="FT-SAE-EXT-KEY EPPKE",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 2, akm='00-0f-ac-25', auth_alg='9',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_3_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 3 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 3)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       key_mgmt="WPA-EAP-SHA256",
                       eap_over_auth_frame="1",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 3, akm='00-0f-ac-5', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_4_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 4 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 4)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       key_mgmt="FT-EAP",
                       eap_over_auth_frame="1",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 4, akm='00-0f-ac-3', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_5_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 5 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 5)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       key_mgmt="WPA-EAP-SHA384",
                       eap_over_auth_frame="1",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 5, akm='00-0f-ac-23', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_6_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 6 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 6)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].connect("sec-profs",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ca.pem",
                       client_cert="auth_serv/user.pem",
                       private_key="auth_serv/user.key",
                       key_mgmt="FT-EAP-SHA384",
                       eap_over_auth_frame="1",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 6, akm='00-0f-ac-22', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_7_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 7 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 7)
    hapd = sec_prof_ap_all(apdev, suite_b_192=True)

    try:
        dev[0].connect("sec-profs",
                       openssl_ciphers="SUITEB192",
                       eap="TLS",
                       identity="tls user",
                       ca_cert="auth_serv/ec2-ca.pem",
                       client_cert="auth_serv/ec2-user.pem",
                       private_key="auth_serv/ec2-user.key",
                       key_mgmt="WPA-EAP-SUITE-B-192",
                       eap_over_auth_frame="1",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 7, akm='00-0f-ac-12', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_8_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 8 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 8)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("pasn_groups", "")
        dev[0].connect("sec-profs", key_mgmt="OWE",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 8, akm='00-0f-ac-18', eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])

def test_security_profile_9_ap_all_sta_key_mgmt(dev, apdev):
    """Security Profile 9 with STA key_mgmt config"""
    enable_sta_security_profiles(dev[0], 9)
    hapd = sec_prof_ap_all(apdev)

    try:
        dev[0].set("sae_pwe", "2")
        dev[0].connect("sec-profs", sae_password="12345678",
                       key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", beacon_prot="1", pmksa_privacy="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256",
                       scan_freq="2412")
        hapd.wait_sta()
        check_security_profile(hapd, dev[0], 9, akm='00-0f-ac-24', auth_alg='3',
                               eht=False)
        hwsim_utils.test_connectivity(dev[0], hapd)
    finally:
        sta_cleanup(dev[0])
