# UHR tests
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# Copyright (C) 2025 Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import tempfile
import time
from functools import partial

import hostapd
from utils import *
from hwsim import HWSimRadio
import hwsim_utils
from wpasupplicant import WpaSupplicant
from test_eht import eht_verify_status, traffic_test, eht_verify_wifi_version
from test_eht import eht_mld_ap_wpa2_params, eht_mld_enable_ap

def uhr_verify_wifi_version(dev):
    status = dev.get_status()
    logger.info("station status: " + str(status))

    if 'wifi_generation' not in status:
        raise Exception("Missing wifi_generation information")
    if status['wifi_generation'] != "8":
        raise Exception("Unexpected wifi_generation value: " + status['wifi_generation'])

def uhr_verify_status(wpas, hapd, is_ht=False, is_vht=False,
                      sta_expect_uhr=True):
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
    if status["ieee80211bn"] != "1":
        raise Exception("Unexpected STATUS ieee80211bn value")

    sta = hapd.get_sta(wpas.own_addr())
    logger.info("hostapd STA: " + str(sta))
    if sta['addr'] == 'FAIL':
        raise Exception("hostapd " + hapd.ifname + " did not have a STA entry for the STA " + wpas.own_addr())
    if is_ht and "[HT]" not in sta['flags']:
        raise Exception("Missing STA flag: HT")
    if is_vht and "[VHT]" not in sta['flags']:
        raise Exception("Missing STA flag: VHT")
    if "[HE]" not in sta['flags']:
        raise Exception("Missing STA flag: HE")
    if "[EHT]" not in sta['flags']:
        raise Exception("Missing STA flag: EHT")
    if "[UHR]" not in sta['flags']:
        if sta_expect_uhr:
            raise Exception("Missing STA flag: UHR")
    elif not sta_expect_uhr:
        raise Exception("Erroneous STA flag: UHR")

def test_uhr_simple(dev, apdev):
    """UHR AP with simple SAE configuration"""
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        check_sae_capab(wpas)

        passphrase = 'qwertyuiop'
        params = eht_mld_ap_wpa2_params("uhr", key_mgmt="SAE",
                                        passphrase=passphrase,
                                        pwe='2', mfp='2')
        params['ieee80211bn'] = '1'
        params['require_uhr'] = '1'
        try:
            hapd = eht_mld_enable_ap(hapd_iface, 0, params)
        except Exception as e:
            if isinstance(e, Exception) and \
               str(e) == "Failed to set hostapd parameter ieee80211bn":
                raise HwsimSkip("UHR not supported")
            raise
        if hapd.get_status_field("ieee80211bn") != "1":
            raise Exception("AP STATUS did not indicate ieee80211bn=1")
        wpas.set("sae_pwe", "1")
        wpas.connect("uhr", key_mgmt="SAE", sae_password=passphrase,
                     ieee80211w="2", scan_freq="2412")
        hapd.wait_sta()
        sta = hapd.get_sta(wpas.own_addr())
        uhr_verify_status(wpas, hapd, is_ht=True)
        status = wpas.request("STATUS")
        if "wifi_generation=8" not in status:
            raise Exception("STA STATUS did not indicate wifi_generation=8")

def test_uhr_required_not_supported(dev, apdev):
    """no connection if UHR is required but not supported by client"""
    params = {
        "ssid": "uhr",
        "ieee80211ax": "1",
        "ieee80211be": "1",
        "ieee80211bn": "1",
        "require_uhr": "1",
    }
    try:
        hapd = hostapd.add_ap(apdev[0], params)
    except Exception as e:
        if isinstance(e, Exception) and \
           str(e) == "Failed to set hostapd parameter ieee80211bn":
            raise HwsimSkip("UHR not supported")
        raise
    if hapd.get_status_field("ieee80211bn") != "1":
        raise Exception("AP STATUS did not indicate ieee80211bn=1")
    dev[0].connect("uhr", key_mgmt="NONE", scan_freq="2412", disable_uhr="1",
                   wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    assert ev is None, "connected despite disable_uhr/require_uhr"

def uhr_mld_ap_wpa2_params(ssid, passphrase=None, key_mgmt="WPA-PSK-SHA256",
                           mfp="2", pwe=None, beacon_prot="1", bridge=False):
    params = hostapd.wpa2_params(ssid=ssid, passphrase=passphrase,
                                 wpa_key_mgmt=key_mgmt, ieee80211w=mfp)
    params['ieee80211n'] = '1'
    params['ieee80211ax'] = '1'
    params['ieee80211be'] = '1'
    params['ieee80211bn'] = '1'
    params['channel'] = '1'
    params['hw_mode'] = 'g'
    params['group_mgmt_cipher'] = "AES-128-CMAC"
    params['beacon_prot'] = beacon_prot
    if bridge:
        params['bridge'] = 'ap-br0'

    if pwe is not None:
        params['sae_pwe'] = pwe

    return params

def uhr_mld_enable_ap(iface, link_id, params):
    hapd = hostapd.add_mld_link(iface, link_id, params)
    hapd.enable()

    ev = hapd.wait_event(["AP-ENABLED", "AP-DISABLED"], timeout=1)
    if ev is None:
        raise Exception("AP startup timed out")
    if "AP-ENABLED" not in ev:
        raise Exception("AP startup failed")

    return hapd

def run_uhr_mld_sae_single_link(dev, apdev, anti_clogging_token=False):
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
            HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        check_sae_capab(wpas)

        passphrase = 'qwertyuiop'
        ssid = "mld_ap_sae_single_link"
        params = uhr_mld_ap_wpa2_params(ssid, passphrase, key_mgmt="SAE",
                                        mfp="2", pwe='2')
        if anti_clogging_token:
            params['sae_anti_clogging_threshold'] = '0'

        hapd0 = uhr_mld_enable_ap(hapd_iface, 0, params)

        wpas.set("sae_pwe", "1")
        wpas.connect(ssid, sae_password=passphrase, scan_freq="2412",
                     key_mgmt="SAE", ieee80211w="2")

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        uhr_verify_status(wpas, hapd0, is_ht=True)
        uhr_verify_wifi_version(wpas)
        traffic_test(wpas, hapd0)

def test_uhr_mld_sae_single_link(dev, apdev):
    """UHR MLD AP with MLD client SAE H2E connection using single link"""
    run_uhr_mld_sae_single_link(dev, apdev)

def uhr_5ghz_params(ssid, passphrase, channel, chanwidth, ccfs1, ccfs2=0,
                    he_ccfs1=None, he_oper_chanwidth=None):
    if he_ccfs1 is None:
        he_ccfs1 = ccfs1
    if he_oper_chanwidth is None:
        he_oper_chanwidth = chanwidth

    params = uhr_mld_ap_wpa2_params(ssid, passphrase, key_mgmt="SAE",
                                    mfp="2", pwe='2')
    params.update({
        "country_code": "US",
        "hw_mode": "a",
        "channel": str(channel),
        "ieee80211n": "1",
        "ieee80211ac": "1",
        "ieee80211ax": "1",
        "ieee80211be": "1",
        "ieee80211bn": "1",
        "vht_oper_chwidth": str(he_oper_chanwidth),
        "vht_oper_centr_freq_seg0_idx": str(he_ccfs1),
        "vht_oper_centr_freq_seg1_idx": str(ccfs2),
        "he_oper_chwidth": str(he_oper_chanwidth),
        "he_oper_centr_freq_seg0_idx": str(he_ccfs1),
        "he_oper_centr_freq_seg1_idx": str(ccfs2),
        "eht_oper_centr_freq_seg0_idx": str(ccfs1),
        "eht_oper_chwidth": str(chanwidth),
    })

    if he_oper_chanwidth == 0:
        if channel < he_ccfs1:
                params["ht_capab"] = "[HT40+]"
        elif channel > he_ccfs1:
                params["ht_capab"] = "[HT40-]"
    else:
        params["ht_capab"] = "[HT40+]"
        if he_oper_chanwidth == 2:
            params["vht_capab"] = "[VHT160]"
        elif he_oper_chanwidth == 3:
            params["vht_capab"] = "[VHT160-80PLUS80]"

    return params

def _test_uhr_5ghz(channel, chanwidth, ccfs1, ccfs2=0,
                   callback=None, uhr_connection=True, **kw):
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        check_sae_capab(wpas)

        passphrase = 'quertyiop'
        params = uhr_5ghz_params('uhr', passphrase, channel,
                                 chanwidth, ccfs1, ccfs2)
        params.update(kw)

        freq = 5000 + channel * 5

        hapd = uhr_mld_enable_ap(hapd_iface, 0, params)
        wpas.set('sae_pwe', '1')
        wpas.connect('uhr', sae_password=passphrase, scan_freq=str(freq),
                     key_mgmt="SAE", ieee80211w="2",
                     disable_uhr='1' if not uhr_connection else '0')
        hapd.wait_sta()

        uhr_verify_status(wpas, hapd, is_ht=True, is_vht=True,
                          sta_expect_uhr=uhr_connection)
        if uhr_connection:
            uhr_verify_wifi_version(wpas)
        else:
            eht_verify_wifi_version(wpas)
        hwsim_utils.test_connectivity(wpas, hapd)
        if callback: callback(wpas, hapd)

def _check_width(link, width, wpas, hapd):
    sig = wpas.request("MLO_SIGNAL_POLL").splitlines()
    logger.debug(sig)
    link_data = {}
    cur_link = None
    for line in sig:
        if line.startswith('LINK_ID='):
            cur_link = int(line[8:])
        if not cur_link in link_data:
            link_data[cur_link] = []
        link_data[cur_link].append(line)
    assert link in link_data, f'link {link} not found'
    assert f'WIDTH={width} MHz' in link_data[link], \
        f'client not connected with {width} MHz'

def test_uhr_5ghz_dbe_80(dev, apdev):
    """UHR with DBE enabled"""
    try:
        _test_uhr_5ghz(36, 0, 38, dbe_bandwidth="2",
                       callback=partial(_check_width, 0, 80))
    finally:
        set_world_reg(apdev[0], None, dev[0])

def test_uhr_5ghz_dbe_80_not_used(dev, apdev):
    """UHR with DBE enabled but client can't use it"""
    try:
        _test_uhr_5ghz(36, 0, 38, dbe_bandwidth="2",
                       callback=partial(_check_width, 0, 40),
                       uhr_connection=False)
    finally:
        set_world_reg(apdev[0], None, dev[0])
