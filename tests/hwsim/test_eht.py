# EHT tests
# Copyright (c) 2022, Qualcomm Innovation Center, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
from utils import *
from hwsim import HWSimRadio
import hwsim_utils
from wpasupplicant import WpaSupplicant
import re

def eht_verify_wifi_version(dev):
    status = dev.get_status()
    logger.info("station status: " + str(status))

    if 'wifi_generation' not in status:
        raise Exception("Missing wifi_generation information")
    if status['wifi_generation'] != "7":
        raise Exception("Unexpected wifi_generation value: " + status['wifi_generation'])

def _eht_get_links_bitmap(wpas, name):
    vfile = "/sys/kernel/debug/ieee80211/%s/netdev:%s/%s" % \
        (wpas.get_driver_status_field("phyname"), wpas.ifname, name)

    if wpas.cmd_execute(["ls", vfile])[0] != 0:
        logger_info("%s not supported in mac80211: %s" % (name, vfile))
        return 0

    res, out = wpas.cmd_execute(["cat", vfile], shell=True)
    if res != 0:
        raise Exception("Failed to read %s" % fname)

    logger.info("%s=%s" % (name, out))
    return int(out, 16)

def _eht_valid_links(wpas):
    return _eht_get_links_bitmap(wpas, "valid_links")

def _eht_active_links(wpas):
    return _eht_get_links_bitmap(wpas, "active_links")

def _eht_verify_links(wpas, valid_links=0, active_links=0):
    vlinks = _eht_valid_links(wpas)
    if vlinks != valid_links:
        raise Exception("Unexpected valid links (0x%04x != 0x%04x)" % (vlinks, valid_links))

    alinks = _eht_active_links(wpas)
    if alinks != active_links:
        raise Exception("Unexpected active links (0x%04x != 0x%04x)" % (alinks, active_links))

def eht_verify_status(wpas, hapd, freq, bw, is_ht=False, is_vht=False,
                      mld=False, valid_links=0, active_links=0):
    status = hapd.get_status()

    logger.info("hostapd STATUS: " + str(status))
    if is_ht and status["ieee80211n"] != "1":
        raise Exception("Unexpected STATUS ieee80211n value")
    if is_vht and status["ieee80211ac"] != "1":
        raise Exception("Unexpected STATUS ieee80211ac value")
    if status["ieee80211ax"] != "1":
        raise Exception("Unexpected STATUS ieee80211ax value")
    if status["ieee80211be"] != "1":
        raise Exception("Unexpected STATUS ieee80211be value")

    sta = hapd.get_sta(wpas.own_addr())
    logger.info("hostapd STA: " + str(sta))
    if is_ht and "[HT]" not in sta['flags']:
        raise Exception("Missing STA flag: HT")
    if is_vht and "[VHT]" not in sta['flags']:
        raise Exception("Missing STA flag: VHT")
    if "[HE]" not in sta['flags']:
        raise Exception("Missing STA flag: HE")
    if "[EHT]" not in sta['flags']:
        raise Exception("Missing STA flag: EHT")

    sig = wpas.request("SIGNAL_POLL").splitlines()

    # TODO: With MLD connection, signal poll logic is still not implemented.
    # While mac80211 maintains the station using the MLD address, the
    # information is maintained in the link stations, but it is not sent to
    # user space yet.
    if not mld:
        if "FREQUENCY=%s" % freq not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(1): " + str(sig))
        if "WIDTH=%s MHz" % bw not in sig:
            raise Exception("Unexpected SIGNAL_POLL value(2): " + str(sig))

    # Active links are updated in async work after the connection.
    # Sleep a bit to allow it to run.
    time.sleep(0.1)
    _eht_verify_links(wpas, valid_links, active_links)

def traffic_test(wpas, hapd, success=True):
    hwsim_utils.test_connectivity(wpas, hapd, success_expected=success)

def test_eht_open(dev, apdev):
    """EHT AP with open mode configuration"""
    params = {"ssid": "eht",
              "ieee80211ax": "1",
              "ieee80211be": "1"}
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise
    if hapd.get_status_field("ieee80211be") != "1":
        raise Exception("AP STATUS did not indicate ieee80211be=1")
    dev[0].connect("eht", key_mgmt="NONE", scan_freq="2412")
    sta = hapd.get_sta(dev[0].own_addr())
    if "[EHT]" not in sta['flags']:
        raise Exception("Missing STA flag: EHT")
    status = dev[0].request("STATUS")
    if "wifi_generation=7" not in status:
        raise Exception("STA STATUS did not indicate wifi_generation=7")

def test_prefer_eht_20(dev, apdev):
    params = {"ssid": "eht",
              "channel": "1",
              "ieee80211ax": "1",
              "ieee80211be" : "1",
              "ieee80211n": "1"}
    try:
        hapd0 = hostapd.add_ap(apdev[0], params)

        params["ieee80211be"] = "0"
        hapd1 = hostapd.add_ap(apdev[1], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

    dev[0].connect("eht", key_mgmt="NONE")
    if dev[0].get_status_field('bssid') != apdev[0]['bssid']:
        raise Exception("dev[0] connected to unexpected AP")

    est = dev[0].get_bss(apdev[0]['bssid'])['est_throughput']
    if est != "172103":
      raise Exception("Unexpected BSS1 est_throughput: " + est)

def start_eht_sae_ap(apdev, ml=False, transition_mode=False):
    params = hostapd.wpa2_params(ssid="eht", passphrase="12345678")
    params["ieee80211ax"] = "1"
    params["ieee80211be"] = "1"
    params['ieee80211w'] = '1' if transition_mode else '2'
    params['rsn_pairwise'] = "CCMP GCMP-256" if transition_mode else "GCMP-256"
    params['group_cipher'] = "CCMP" if transition_mode else "GCMP-256"
    params["group_mgmt_cipher"] = "AES-128-CMAC" if transition_mode else "BIP-GMAC-256"
    params['beacon_prot'] = '1'
    params['wpa_key_mgmt'] = "SAE SAE-EXT-KEY" if transition_mode else 'SAE-EXT-KEY'
    params['sae_groups'] = "19 20" if transition_mode else "20"
    params['sae_pwe'] = "2" if transition_mode else "1"
    if ml:
        ml_elem = "ff0d6b" + "3001" + "0a" + "021122334455" + "01" + "00" + "00"
        params['vendor_elements'] = ml_elem
    try:
        hapd = hostapd.add_ap(apdev, params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211be":
            raise HwsimSkip("EHT not supported")
        raise

def test_eht_sae(dev, apdev):
    """EHT AP with SAE"""
    check_sae_capab(dev[0])

    hapd = start_eht_sae_ap(apdev[0])
    try:
        dev[0].set("sae_groups", "20")
        dev[0].set("sae_pwe", "2")
        dev[0].connect("eht", key_mgmt="SAE-EXT-KEY", psk="12345678",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")
    finally:
        dev[0].set("sae_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eht_sae_mlo(dev, apdev):
    """EHT+MLO AP with SAE"""
    check_sae_capab(dev[0])

    hapd = start_eht_sae_ap(apdev[0], ml=True)
    try:
        dev[0].set("sae_groups", "20")
        dev[0].set("sae_pwe", "2")
        dev[0].connect("eht", key_mgmt="SAE-EXT-KEY", psk="12345678",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="GCMP-256",
                       group_mgmt="BIP-GMAC-256", scan_freq="2412")
    finally:
        dev[0].set("sae_groups", "")
        dev[0].set("sae_pwe", "0")

def test_eht_sae_mlo_tm(dev, apdev):
    """EHT+MLO AP with SAE and transition mode"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])

    hapd = start_eht_sae_ap(apdev[0], ml=True, transition_mode=True)
    try:
        dev[0].set("sae_groups", "20")
        dev[0].set("sae_pwe", "2")
        dev[0].connect("eht", key_mgmt="SAE-EXT-KEY", psk="12345678",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="GCMP-256", group="CCMP",
                       group_mgmt="AES-128-CMAC", scan_freq="2412")
        dev[1].set("sae_groups", "19")
        dev[1].connect("eht", key_mgmt="SAE-EXT-KEY", psk="12345678",
                       ieee80211w="2", beacon_prot="1",
                       pairwise="CCMP", group="CCMP",
                       group_mgmt="AES-128-CMAC", scan_freq="2412",
                       disable_eht="1")
    finally:
        dev[0].set("sae_groups", "")
        dev[0].set("sae_pwe", "0")
        dev[1].set("sae_groups", "")

def eht_mld_enable_ap(iface, params):
    hapd = hostapd.add_mld_link(iface, params)
    hapd.enable()

    ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=1)
    if ev is None:
        raise Exception("AP startup timed out")
    if "AP-ENABLED" not in ev:
        raise Exception("AP startup failed")

    return hapd

def eht_mld_ap_wpa2_params(ssid, passphrase=None, key_mgmt="WPA-PSK-SHA256",
                           mfp="2", pwe=None, beacon_prot="1"):
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 wpa_key_mgmt=key_mgmt, ieee80211w=mfp)
    params['ieee80211n'] = '1'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'
    params['channel'] = '1'
    params['hw_mode'] = 'g'
    params['group_mgmt_cipher'] = "AES-128-CMAC"
    params['beacon_prot'] = beacon_prot

    if pwe is not None:
        params['sae_pwe'] = pwe

    return params

def test_eht_mld_discovery(dev, apdev):
    """EHT MLD AP discovery"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        ssid = "mld_ap"
        link0_params = {"ssid": ssid,
                        "hw_mode": "g",
                        "channel": "1"}
        link1_params = {"ssid": ssid,
                        "hw_mode": "g",
                        "channel": "2"}

        hapd0 = eht_mld_enable_ap(hapd_iface, link0_params)
        hapd1 = eht_mld_enable_ap(hapd_iface, link1_params)

        res = wpas.request("SCAN freq=2412,2417")
        if "FAIL" in res:
            raise Exception("Failed to start scan")

        ev = wpas.wait_event(["CTRL-EVENT-SCAN-STARTED"])
        if ev is None:
            raise Exception("Scan did not start")

        ev = wpas.wait_event(["CTRL-EVENT-SCAN-RESULTS"])
        if ev is None:
            raise Exception("Scan did not complete")

        logger.info("Scan done")

        rnr_pattern = re.compile(".*ap_info.*, mld ID=0, link ID=",
                                 re.MULTILINE)
        ml_pattern = re.compile(".*multi-link:.*, MLD addr=.*", re.MULTILINE)

        bss = wpas.request("BSS " + hapd0.own_addr())
        logger.info("BSS 0: " + str(bss))

        if rnr_pattern.search(bss) is None:
            raise Exception("RNR element not found for first link")

        if ml_pattern.search(bss) is None:
            raise Exception("ML element not found for first link")

        bss = wpas.request("BSS " + hapd1.own_addr())
        logger.info("BSS 1: " + str(bss))

        if rnr_pattern.search(bss) is None:
            raise Exception("RNR element not found for second link")

        if ml_pattern.search(bss) is None:
            raise Exception("ML element not found for second link")

def test_eht_mld_owe_two_links(dev, apdev):
    """EHT MLD AP with MLD client OWE connection using two links"""
    with HWSimRadio(use_mlo=True) as (hapd0_radio, hapd0_iface), \
        HWSimRadio(use_mlo=True) as (hapd1_radio, hapd1_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        ssid = "mld_ap_owe_two_link"
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="OWE", mfp="2")

        hapd0 = eht_mld_enable_ap(hapd0_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd0_iface, params)
        # Check legacy client connection
        dev[0].connect(ssid, scan_freq="2437", key_mgmt="OWE", ieee80211w="2")
        wpas.connect(ssid, scan_freq="2412 2437", key_mgmt="OWE",
                     ieee80211w="2")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

def test_eht_mld_sae_single_link(dev, apdev):
    """EHT MLD AP with MLD client SAE H2E connection using single link"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
            HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_single_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase, key_mgmt="SAE",
                                        mfp="2", pwe='2')

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                     key_mgmt="SAE", ieee80211w="2")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)

def run_eht_mld_sae_two_links(dev, apdev, beacon_prot="1"):
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE", mfp="2", pwe='1',
                                        beacon_prot=beacon_prot)

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE", ieee80211w="2", beacon_prot="1")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

def test_eht_mld_sae_two_links(dev, apdev):
    """EHT MLD AP with MLD client SAE H2E connection using two links"""
    run_eht_mld_sae_two_links(dev, apdev)

def test_eht_mld_sae_two_links_no_beacon_prot(dev, apdev):
    """EHT MLD AP with MLD client SAE H2E connection using two links and no beacon protection"""
    run_eht_mld_sae_two_links(dev, apdev, beacon_prot="0")

def test_eht_mld_sae_ext_one_link(dev, apdev):
    """EHT MLD AP with MLD client SAE-EXT H2E connection using single link"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_ext_single_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase, key_mgmt="SAE-EXT-KEY")

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                     key_mgmt="SAE-EXT-KEY", ieee80211w="2")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)

def test_eht_mld_sae_ext_two_links(dev, apdev):
    """EHT MLD AP with MLD client SAE-EXT H2E connection using two links"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY")

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY", ieee80211w="2")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

def test_eht_mld_sae_legacy_client(dev, apdev):
    """EHT MLD AP with legacy client SAE H2E connection"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface):
        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE", mfp="2", pwe='1')

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        try:
            dev[0].set("sae_groups", "")
            dev[0].set("sae_pwe", "1")
            dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                           key_mgmt="SAE", ieee80211w="2", beacon_prot="1")

            eht_verify_status(dev[0], hapd0, 2412, 20, is_ht=True)
            traffic_test(dev[0], hapd0)
        finally:
            dev[0].set("sae_groups", "")
            dev[0].set("sae_pwe", "0")

def test_eht_mld_sae_transition(dev, apdev):
    """EHT MLD AP in SAE/PSK transition mode with MLD client connection using two links"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY SAE WPA-PSK WPA-PSK-SHA256",
                                        mfp="1")

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY", ieee80211w="2")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

        dev[0].set("sae_groups", "")
        dev[0].connect(ssid, sae_password=passphrase, scan_freq="2412",
                       key_mgmt="SAE", ieee80211w="2", beacon_prot="1")
        dev[1].connect(ssid, psk=passphrase, scan_freq="2412",
                       key_mgmt="WPA-PSK", ieee80211w="0")

def test_eht_mld_ptk_rekey(dev, apdev):
    """EHT MLD AP and PTK rekeying with MLD client connection using two links"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY SAE WPA-PSK WPA-PSK-SHA256",
                                        mfp="1")
        params['wpa_ptk_rekey'] = '5'

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY", ieee80211w="2")
        ev0 = hapd0.wait_event(["AP-STA-CONNECT"], timeout=1)
        if ev0 is None:
            ev1 = hapd1.wait_event(["AP-STA-CONNECT"], timeout=1)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

        ev = wpas.wait_event(["WPA: Key negotiation completed",
                              "CTRL-EVENT-DISCONNECTED"], timeout=10)
        if ev is None:
            raise Exception("PTK rekey timed out")
        if "CTRL-EVENT-DISCONNECTED" in ev:
            raise Exception("Disconnect instead of rekey")

        time.sleep(0.1)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

def test_eht_mld_gtk_rekey(dev, apdev):
    """AP MLD and GTK rekeying with MLD client connection using two links"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY SAE WPA-PSK WPA-PSK-SHA256",
                                        mfp="1")
        params['wpa_group_rekey'] = '5'

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412 2437",
                     key_mgmt="SAE-EXT-KEY", ieee80211w="2")
        ev0 = hapd0.wait_event(["AP-STA-CONNECT"], timeout=1)
        if ev0 is None:
            ev1 = hapd1.wait_event(["AP-STA-CONNECT"], timeout=1)
        traffic_test(wpas, hapd0)
        traffic_test(wpas, hapd1)

        for i in range(2):
            ev = wpas.wait_event(["MLO RSN: Group rekeying completed",
                                  "CTRL-EVENT-DISCONNECTED"], timeout=10)
            if ev is None:
                raise Exception("GTK rekey timed out")
            if "CTRL-EVENT-DISCONNECTED" in ev:
                raise Exception("Disconnect instead of rekey")

            #TODO: Uncomment these ones GTK rekeying works for MLO
            #time.sleep(0.1)
            #traffic_test(wpas, hapd0)
            #traffic_test(wpas, hapd1)

def test_eht_ml_probe_req(dev, apdev):
    """AP MLD with two links and non-AP MLD sending ML Probe Request"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_two_link"
        params = eht_mld_ap_wpa2_params(ssid, passphrase,
                                        key_mgmt="SAE-EXT-KEY")

        hapd0 = eht_mld_enable_ap(hapd_iface, params)

        params['channel'] = '6'

        hapd1 = eht_mld_enable_ap(hapd_iface, params)

        bssid = hapd0.own_addr()
        wpas.scan_for_bss(bssid, freq=2412)

        time.sleep(1)
        cmd = "ML_PROBE_REQ bssid=" + bssid + " mld_id=0"
        if "OK" not in wpas.request(cmd):
            raise Exception("Failed to run: " + cmd)
        ev = wpas.wait_event(["CTRL-EVENT-SCAN-RESULTS",
                              "CTRL-EVENT-SCAN-FAILED"], timeout=10)
        if ev is None:
            raise Exception("ML_PROBE_REQ did not result in scan results")

        time.sleep(1)
        cmd = "ML_PROBE_REQ bssid=" + bssid + " mld_id=0 link_id=2"
        if "OK" not in wpas.request(cmd):
            raise Exception("Failed to run: " + cmd)
        ev = wpas.wait_event(["CTRL-EVENT-SCAN-RESULTS",
                              "CTRL-EVENT-SCAN-FAILED"], timeout=10)
        if ev is None:
            raise Exception("ML_PROBE_REQ did not result in scan results")

def test_eht_mld_link_removal(dev, apdev):
    """EHT MLD with two links. Links removed during association"""

    with HWSimRadio(use_mlo=True) as (hapd0_radio, hapd0_iface), \
        HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        ssid = "mld_ap_owe_two_link"
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="OWE", mfp="2")
        hapd0 = eht_mld_enable_ap(hapd0_iface, params)

        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd0_iface, params)

        wpas.connect(ssid, scan_freq="2412 2437", key_mgmt="OWE",
                     ieee80211w="2")
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        eht_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)

        logger.info("Disable the 2nd link in 4 beacon intervals")
        hapd1.link_remove(4)
        time.sleep(0.6)

        logger.info("Test traffic after 2nd link disabled")
        traffic_test(wpas, hapd0)

        if "OK" not in hapd0.request("REKEY_GTK"):
            raise Exception("REKEY_GTK failed")

        ev = wpas.wait_event(["MLO RSN: Group rekeying completed"], timeout=2)
        if ev is None:
            raise Exception("GTK rekey timed out")

        traffic_test(wpas, hapd0)

        logger.info("Disable the 1st link in 20 beacon intervals")
        hapd0.link_remove(20)
        time.sleep(1)

        logger.info("Verify that traffic is valid before the link is removed")
        traffic_test(wpas, hapd0)
        time.sleep(2)

        logger.info("Test traffic after 1st link disabled")
        traffic_test(wpas, hapd0, success=False)
