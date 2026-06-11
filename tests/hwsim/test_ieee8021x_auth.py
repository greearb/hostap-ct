# Test cases for IEEE 802.1X authentication using Authentication frames
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
import time

import hostapd
import hwsim_utils
from utils import *
from wpasupplicant import WpaSupplicant
from hwsim import HWSimRadio
from test_eht import eht_mld_ap_wpa2_params, eht_mld_enable_ap, eht_verify_status

logger = logging.getLogger()

def check_hlr_auc_gw_support():
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        raise HwsimSkip("No hlr_auc_gw available")

def check_eap_capa(dev, method):
    res = dev.get_capability("eap")
    if method not in res:
        raise HwsimSkip("EAP method %s not supported in the build" % method)

def test_ieee8021x_auth_alg_eap_tls(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-TLS"""
    ssid = "test-ieee8021x-auth-tls"

    params = hostapd.wpa2_eap_params(ssid=ssid)

    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_ttls_mschapv2(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-TTLS/MSCHAPv2"""
    ssid = "test-ieee8021x-auth-ttls"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TTLS",
                   identity="user",
                   anonymous_identity="ttls",
                   password="password",
                   phase2="autheap=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_peap_mschapv2(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-PEAP/MSCHAPv2"""
    ssid = "test-ieee8021x-auth-peap"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PEAP",
                   identity="user",
                   anonymous_identity="peap",
                   password="password",
                   phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_multiple_clients(dev, apdev):
    """IEEE 802.1X authentication with multiple clients"""
    ssid = "test-ieee8021x-auth-multi"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    dev[1].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TTLS",
                   identity="user",
                   anonymous_identity="ttls",
                   password="password",
                   phase2="autheap=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    sta0 = hapd.get_sta(dev[0].own_addr())
    sta1 = hapd.get_sta(dev[1].own_addr())

    if sta0["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for client 0")

    if sta1["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for client 1")

    auth_alg0 = sta0.get("auth_alg")
    logger.info("Auth Algorithm client 0: " + str(auth_alg0))
    if str(auth_alg0) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) for client 0, got: " + str(auth_alg0))

    auth_alg1 = sta1.get("auth_alg")
    logger.info("Auth Algorithm client 1: " + str(auth_alg1))
    if str(auth_alg1) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) for client 1, got: " + str(auth_alg1))
    hwsim_utils.test_connectivity(dev[0], hapd)
    hwsim_utils.test_connectivity(dev[1], hapd)

def test_ieee8021x_auth_alg_eap_tls_wpa_eap(dev, apdev):
    """IEEE 802.1X authentication with WPA-EAP (non-SHA256) AKM"""
    ssid = "test-ieee8021x-auth-wpa-eap"

    # Setup AP with WPA2-EAP (standard AKM, not SHA256)
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-1':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "0":
        raise Exception("Expected OPEN_SYSTEM auth (0) for WPA-EAP, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_wpa_eap_sha384(dev, apdev):
    """IEEE 802.1X authentication with WPA-EAP-SHA384 AKM"""
    ssid = "test-ieee8021x-auth-sha384"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA384"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["ieee80211w"] = "2"  # Required for SHA384

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA384",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   ieee80211w="2",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-23':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_mixed_akm(dev, apdev):
    """IEEE 802.1X authentication with mixed AKM support"""
    ssid = "test-ieee8021x-auth-mixed"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta0 = hapd.get_sta(dev[0].own_addr())

    if sta0["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for SHA256 client")

    auth_alg0 = sta0.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg0))
    if str(auth_alg0) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg0))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_suite_b_192(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with Suite B 192-bit"""
    if "WPA-EAP-SUITE-B-192" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("WPA-EAP-SUITE-B-192 not supported")

    ssid = "test-ieee8021x-auth-suite-b-192"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SUITE-B-192"
    params["wpa_pairwise"] = "GCMP-256"
    params["rsn_pairwise"] = "GCMP-256"
    params["ieee80211w"] = "2"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   group="GCMP-256",
                   pairwise="GCMP-256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-12':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_sim(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-SIM"""
    check_hlr_auc_gw_support()
    ssid = "test-ieee8021x-auth-sim"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="SIM",
                   identity="1232010000000000",
                   password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_aka(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-AKA"""
    check_hlr_auc_gw_support()
    ssid = "test-ieee8021x-auth-aka"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="AKA",
                   identity="0232010000000000",
                   password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_aka_prime(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-AKA'"""
    check_hlr_auc_gw_support()
    ssid = "test-ieee8021x-auth-aka-prime"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="AKA'",
                   identity="6555444333222111",
                   password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_pwd(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-pwd"""
    check_eap_capa(dev[0], "PWD")
    ssid = "test-ieee8021x-auth-pwd"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PWD",
                   identity="pwd user",
                   password="secret password",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_pax(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-PAX"""
    ssid = "test-ieee8021x-auth-pax"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PAX",
                   identity="pax.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_psk(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-PSK"""
    ssid = "test-ieee8021x-auth-psk"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_sake(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-SAKE"""
    ssid = "test-ieee8021x-auth-sake"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="SAKE",
                   identity="sake user",
                   password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_gpsk(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-GPSK"""
    ssid = "test-ieee8021x-auth-gpsk"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="GPSK",
                   identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_eke(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-EKE"""
    ssid = "test-ieee8021x-auth-eke"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="EKE",
                   identity="eke user",
                   password="hello",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_ikev2(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-IKEv2"""
    check_eap_capa(dev[0], "IKEV2")
    ssid = "test-ieee8021x-auth-ikev2"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="IKEV2",
                   identity="ikev2 user",
                   password="ike password",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_fast(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-FAST"""
    check_eap_capa(dev[0], "FAST")
    ssid = "test-ieee8021x-auth-fast"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="FAST",
                   identity="user",
                   anonymous_identity="FAST",
                   password="password",
                   ca_cert="auth_serv/ca.pem",
                   phase2="auth=MSCHAPV2",
                   phase1="fast_provisioning=1",
                   pac_file="blob://fast_pac",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_mlo_single_link(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO single-link EAP-TLS"""
    ssid = "test-ieee8021x-auth-mlo-1l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: single link (link-0)
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        # Non-AP MLD supplicant
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

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
		     eap_over_auth_frame="1")

        hapd0.wait_sta()

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-5':
            raise Exception("Incorrect AKMSuiteSelector (single-link)")

        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

        # Verify MLD state: single link active
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_two_links(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO two-link EAP-TLS"""
    ssid = "test-ieee8021x-auth-mlo-2l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: two links (link-0 @ ch1, link-1 @ ch6)
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        # Non-AP MLD supplicant
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437",
		     eap_over_auth_frame="1")

        for hapd in (hapd0, hapd1):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-5':
            raise Exception("Incorrect AKMSuiteSelector (two-links)")

        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

        # Verify MLD state: two links => bitmap 0b11 == 3
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_three_links(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO three-link EAP-TLS"""
    ssid = "test-ieee8021x-auth-mlo-3l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)
        params['channel'] = '11'
        hapd2 = eht_mld_enable_ap(hapd_iface, 2, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437 2462",
		     eap_over_auth_frame="1")

        for hapd in (hapd0, hapd1, hapd2):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-5':
            raise Exception("Incorrect AKMSuiteSelector (three-links)")

        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=7, active_links=7)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_connect_disconnect_reconnect(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO two-link connect/disconnect/reconnect"""
    ssid = "test-ieee8021x-auth-mlo-cdr"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437",
		     eap_over_auth_frame="1")

        for hapd in (hapd0, hapd1):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)

        sta = hapd0.get_sta(wpas.own_addr())
        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
        hwsim_utils.test_connectivity(wpas, hapd0)

        for _ in range(2):
            wpas.request("DISCONNECT")
            wpas.wait_disconnected(timeout=5)
            wpas.request("RECONNECT")
            wpas.wait_connected(timeout=15)

            for hapd in (hapd0, hapd1):
                try:
                    hapd.wait_sta()
                except Exception:
                    pass
            hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_connect_disconnect_reconnect(dev, apdev):
    """IEEE 802.1X Authentication frames: non-MLO connect/disconnect/reconnect"""
    ssid = "test-ieee8021x-auth-cdr"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    sta = hapd.get_sta(dev[0].own_addr())
    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

    for _ in range(2):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=5)
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15, error="Reconnect timed out")
        hapd.wait_sta()
        hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_legacy_akm_wpa_eap(dev, apdev):
    """Legacy WPA-EAP authentication with AKM 1 (supplicant should not use IEEE 802.1X Authentication frames with AKM 1)"""
    ssid = "test-legacy-akm-wpa-eap"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-1':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "OPEN_SYSTEM" and str(auth_alg) != "0":
        raise Exception("Expected legacy OPEN_SYSTEM auth, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_pmksa_privacy(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and PMKSA caching privacy"""
    ssid = "test-ieee8021x-auth-tls-pmksa"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["pmksa_caching_privacy"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   pmksa_privacy="1",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

    pmksa1 = dev[0].get_pmksa(hapd.own_addr())
    if pmksa1 is None:
        raise Exception("No PMKSA entry after first connection")
    pmkid1 = pmksa1['pmkid']
    logger.info("PMKID after first connection: " + pmkid1)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].request("RECONNECT")
    dev[0].wait_connected(timeout=15, error="Reconnect timed out")

    hapd.wait_sta()

    pmksa2 = dev[0].get_pmksa(hapd.own_addr())
    if pmksa2 is None:
        raise Exception("No PMKSA entry after second connection")
    pmkid2 = pmksa2['pmkid']
    logger.info("PMKID after second connection: " + pmkid2)

    if pmkid1 == pmkid2:
        raise Exception("PMKID did not rotate: %s == %s" % (pmkid1, pmkid2))

    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value after PMKSA caching")

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm after PMKSA caching: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) after PMKSA caching, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_ptk_rekey(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and PTK rekey"""
    ssid = "test-ieee8021x-tls-ptk-rekey"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["wpa_ptk_rekey"] = "3"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

    ev = dev[0].wait_event(["WPA: Key negotiation completed"], timeout=11)
    if ev is None:
        raise Exception("PTK rekey timed out")

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_gtk_rekey(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and GTK rekey"""
    ssid = "test-ieee8021x-tls-gtk-rekey"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["wpa_group_rekey"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

    ev = dev[0].wait_event(["RSN: Group rekeying completed"], timeout=11)
    if ev is None:
        raise Exception("GTK rekey timed out")

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_protocol_eap_tls_pmksa_not_found_by_ap(dev, apdev):
    """IEEE 802.1X authentication with PMKSA caching fallback when AP does not recognize PMKID"""
    ssid = "test-ieee8021x-pmksa-fallback"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["ieee80211w"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)

    # First connection to establish PMKSA cache
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   ieee80211w="2",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    # Disconnect
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    # Flush AP's PMKSA cache to simulate AP not recognizing the PMKID
    hapd.request("PMKSA_FLUSH")

    hapd.dump_monitor()
    dev[0].dump_monitor()

    # Reconnect - wpa_supplicant will try PMKSA caching but AP won't recognize
    # it, triggering fallback to full EAP authentication
    dev[0].request("RECONNECT")
    dev[0].wait_connected(timeout=15,
                          error="Reconnect with PMKSA fallback timed out")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector after PMKSA fallback")

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) after PMKSA fallback, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_sta_eap_over_auth_frame_ap_no_support(dev, apdev):
    """STA requests EAP over auth frames but AP does not support it; connection succeeds with Open System auth"""
    ssid = "test-ieee8021x-auth-sta-only"

    # AP does not set eap_using_authentication_frames, so it will not
    # advertise or accept IEEE 802.1X Authentication frames. wpa_supplicant
    # sets eap_over_auth_frame=1 but must gracefully fall back to the
    # standard 802.11 Open System authentication + EAP-over-EAPOL path.
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "0":
        raise Exception("Expected OPEN_SYSTEM auth (0) when AP lacks auth frame support, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_sta_opts_out_of_auth_frames(dev, apdev):
    """AP supports auth frames but STA explicitly opts out (eap_over_auth_frame=0)"""
    ssid = "test-ieee8021x-sta-opts-out"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="0")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) not in ("0", "OPEN_SYSTEM"):
        raise Exception("Expected OPEN_SYSTEM auth (0) when STA opts out, got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_eap_failure_wrong_password(dev, apdev):
    """EAP authentication failure (wrong password) during auth frames exchange"""
    ssid = "test-ieee8021x-eap-fail-pw"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TTLS",
                   identity="user",
                   anonymous_identity="ttls",
                   password="WRONG_PASSWORD",
                   phase2="autheap=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1",
                   wait_connect=False)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=15)
    if ev is None:
        raise Exception("Expected EAP failure event, got nothing")
    logger.info("Got expected failure event: " + ev)

def test_ieee8021x_auth_eap_tls_cert_failure(dev, apdev):
    """EAP-TLS certificate failure during auth frames exchange"""
    ssid = "test-ieee8021x-tls-cert-fail"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    # Use wrong CA cert so TLS handshake fails
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca-sha384.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1",
                   wait_connect=False)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=15)
    if ev is None:
        raise Exception("Expected EAP-TLS certificate failure event, got nothing")
    logger.info("Got expected TLS cert failure event: " + ev)

def test_ieee8021x_auth_data_connectivity(dev, apdev):
    """Verify data plane works after EAP-over-auth-frames connection"""
    ssid = "test-ieee8021x-data-plane"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_repeated_reconnects_auth_alg_stable(dev, apdev):
    """Verify auth_alg=8 is stable across 5 connect/disconnect cycles"""
    ssid = "test-ieee8021x-repeat-reconnect"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    for cycle in range(5):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=5)
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=20,
                              error="Reconnect failed on cycle %d" % cycle)
        hapd.wait_sta()

        sta = hapd.get_sta(dev[0].own_addr())
        auth_alg = sta.get("auth_alg")
        logger.info("Cycle %d auth_alg: %s" % (cycle, str(auth_alg)))
        if str(auth_alg) != "8":
            raise Exception("auth_alg not 8 on cycle %d: %s" % (cycle, str(auth_alg)))

        hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_gcmp256_cipher(dev, apdev):
    """IEEE 802.1X auth frames with GCMP-256 pairwise cipher"""
    ssid = "test-ieee8021x-gcmp256"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["rsn_pairwise"] = "GCMP-256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["ieee80211w"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   pairwise="GCMP-256",
                   group="GCMP-256",
                   ieee80211w="2",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) with GCMP-256, got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_deauth_during_exchange(dev, apdev):
    """AP deauthenticates STA after connection; reconnect succeeds cleanly"""
    ssid = "test-ieee8021x-deauth"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if str(sta.get("auth_alg")) != "8":
        raise Exception("Expected auth_alg=8 before deauth")

    # Force AP to deauthenticate the STA
    hapd.request("DEAUTHENTICATE " + dev[0].own_addr())
    dev[0].wait_disconnected(timeout=5)

    # Reconnect must succeed cleanly (no leaked state)
    dev[0].wait_connected(timeout=20, error="Reconnect after deauth failed")
    hapd.wait_sta()

    sta = hapd.get_sta(dev[0].own_addr())
    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm after reconnect: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected auth_alg=8 after reconnect, got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_roam_to_non_auth_frame_ap(dev, apdev):
    """Roam from auth-frame AP to standard AP: STA falls back to Open System auth"""
    ssid = "test-ieee8021x-roam"

    params1 = hostapd.wpa2_eap_params(ssid=ssid)
    params1["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params1["eap_using_authentication_frames"] = "1"
    params1["assoc_frame_encryption"] = "1"
    hapd1 = hostapd.add_ap(apdev[0], params1)

    params2 = hostapd.wpa2_eap_params(ssid=ssid)
    params2["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    hapd2 = hostapd.add_ap(apdev[1], params2)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd1.wait_sta()

    sta1 = hapd1.get_sta(dev[0].own_addr())
    auth_alg1 = sta1.get("auth_alg")
    logger.info("Auth Algorithm on AP1: " + str(auth_alg1))
    if str(auth_alg1) != "8":
        raise Exception("Expected auth_alg=8 on AP1, got: " + str(auth_alg1))

    # Roam to AP2 (no auth frame support)
    dev[0].roam(apdev[1]['bssid'])
    hapd2.wait_sta()

    sta2 = hapd2.get_sta(dev[0].own_addr())
    auth_alg2 = sta2.get("auth_alg")
    logger.info("Auth Algorithm on AP2: " + str(auth_alg2))
    if str(auth_alg2) not in ("0", "OPEN_SYSTEM"):
        raise Exception("Expected OPEN_SYSTEM auth (0) on AP2, got: " + str(auth_alg2))

    hwsim_utils.test_connectivity(dev[0], hapd2)

def test_ieee8021x_auth_roam_between_auth_frame_aps(dev, apdev):
    """Roam between two auth-frame APs: second AP requires full EAP, first uses PMKSA fast path on return"""
    ssid = "test-ieee8021x-roam-both"

    params1 = hostapd.wpa2_eap_params(ssid=ssid)
    params1["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params1["eap_using_authentication_frames"] = "1"
    params1["assoc_frame_encryption"] = "1"
    hapd1 = hostapd.add_ap(apdev[0], params1)

    params2 = hostapd.wpa2_eap_params(ssid=ssid)
    params2["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params2["eap_using_authentication_frames"] = "1"
    params2["assoc_frame_encryption"] = "1"
    hapd2 = hostapd.add_ap(apdev[1], params2)

    # Initial connection to AP1
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd1.wait_sta()

    sta1 = hapd1.get_sta(dev[0].own_addr())
    if str(sta1.get("auth_alg")) != "8":
        raise Exception("Expected auth_alg=8 on AP1")

    # Roam to AP2 (no PMKSA cache entry for AP2 yet — full EAP)
    dev[0].roam(apdev[1]['bssid'])
    hapd2.wait_sta()

    sta2 = hapd2.get_sta(dev[0].own_addr())
    auth_alg2 = sta2.get("auth_alg")
    logger.info("Auth Algorithm on AP2: " + str(auth_alg2))
    if str(auth_alg2) != "8":
        raise Exception("Expected auth_alg=8 on AP2, got: " + str(auth_alg2))

    # Roam back to AP1 (PMKSA cache hit — fast path)
    dev[0].roam(apdev[0]['bssid'])
    hapd1.wait_sta()

    sta1b = hapd1.get_sta(dev[0].own_addr())
    auth_alg1b = sta1b.get("auth_alg")
    logger.info("Auth Algorithm back on AP1: " + str(auth_alg1b))
    if str(auth_alg1b) != "8":
        raise Exception("Expected auth_alg=8 on return to AP1, got: " + str(auth_alg1b))

    hwsim_utils.test_connectivity(dev[0], hapd1)

def test_ieee8021x_auth_mixed_concurrent(dev, apdev):
    """One STA uses EAP-over-auth-frames, another uses standard Open System + EAPOL simultaneously"""
    ssid = "test-ieee8021x-mixed-concurrent"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    # dev[0]: uses IEEE 802.1X Authentication frames
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()

    # dev[1]: uses standard Open System auth + EAP-over-EAPOL (no auth frames)
    dev[1].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412")
    hapd.wait_sta()

    sta0 = hapd.get_sta(dev[0].own_addr())
    sta1 = hapd.get_sta(dev[1].own_addr())

    if sta0["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for dev[0]")
    if sta1["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for dev[1]")

    auth_alg0 = sta0.get("auth_alg")
    logger.info("Auth Algorithm dev[0]: " + str(auth_alg0))
    if str(auth_alg0) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) for dev[0], got: " + str(auth_alg0))

    auth_alg1 = sta1.get("auth_alg")
    logger.info("Auth Algorithm dev[1]: " + str(auth_alg1))
    if str(auth_alg1) not in ("0", "OPEN_SYSTEM"):
        raise Exception("Expected OPEN_SYSTEM auth (0) for dev[1], got: " + str(auth_alg1))

    # Test STA-to-STA data delivery in both directions including broadcast.
    # Verifies the AP correctly forwards frames between an auth-frame STA
    # (auth_alg=8) and a standard EAPOL STA (auth_alg=0).
    # The GTK is delivered to dev[0] in the encrypted Association Response
    # (Key Delivery element), so broadcast should work immediately.
    hwsim_utils.test_connectivity(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[1], dev[0])
