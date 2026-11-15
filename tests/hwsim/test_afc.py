# AFC tests
# Copyright (c) 2025, MediaTek Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import os
import threading
from datetime import datetime, timedelta
import socket
import json

import hwsim_utils
import hostapd
from utils import *

class AFCDServer:
    def __init__(self):
        self.path = '/tmp/afcd.sock'
        if os.path.exists(self.path):
            os.remove(self.path)
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.bind(self.path)
        self.s.listen(1)

    def listen_reply(self, freq_info, chan_info):
        if freq_info is None:
            freq_info = []
        if chan_info is None:
            chan_info = []

        try:
            self.s.settimeout(1)
            self.conn, _ = self.s.accept()
        except Exception as e:
            logger.info("hostapd failed to connect to afcd")
            self.close()
            if os.path.exists(self.path):
                os.unlink(self.path)
            return

        try:
            req_raw = self.conn.recv(8192).decode()
        except socket.timeout:
            logger.info("AFCD failed to get request")
            req_raw = None
        if req_raw:
            logger.info(f"Received: {req_raw}")
            if 'availableSpectrumInquiryRequests' in req_raw:
                try:
                    req_json = json.loads(req_raw)
                    requestId = req_json["availableSpectrumInquiryRequests"][0]["requestId"]
                except Exception as e:
                    logger.info(f"Failed to parse requestId: {e}")
                    self.close()

                expire_time = (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

                resp = {
                    "availableSpectrumInquiryResponses": [
                        {
                            "response": {
                                "responseCode": 0,
                                "shortDescription": "SUCCESS"
                            },
                            "availableFrequencyInfo": freq_info,
                            "availableChannelInfo": chan_info,
                            "requestId": requestId,
                            "availabilityExpireTime": expire_time,
                            "rulesetId": "US_47_CFR_PART_15_SUBPART_E"
                        }
                    ],
                    "version": "1.4"
                }
                reply = json.dumps(resp)
                self.conn.sendall(reply.encode())
                logger.info(f"response Sent: {reply}")

    def __del__(self):
        self.close()

    def close(self):
        self.s.close()

def run_afcd_server(freq_info=None, chan_info=None):
    server = AFCDServer()
    server.listen_reply(freq_info, chan_info)
    server.close()

def init_afc_dut_params():
    params = {"country_code": "CA",
              "hw_mode": "a",
              "ssid": "AFC",
              "ieee80211ax": "1",
              "wpa": "2",
              "rsn_pairwise": "CCMP",
              "wpa_key_mgmt": "SAE",
              "sae_pwe": "1",
              "sae_password": "password",
              "ieee80211w": "2",
              "afcd_sock": "/tmp/afcd.sock",
              "afc_request_version": "1.4",
              "afc_serial_number": "SN000",
              "afc_cert_ids": "US_47_CFR_PART_15_SUBPART_E:CID000",
              "afc_location_type": "0",
              "afc_linear_polygon": "-121.98586998164663:37.38193354300452",
              "afc_radial_polygon": "118.8:92.76,76.44:87.456,98.56:123.33",
              "afc_major_axis": "150",
              "afc_minor_axis": "150",
              "afc_orientation": "0",
              "afc_height": "15",
              "afc_height_type": "AGL",
              "afc_vertical_tolerance": "2",
              "afc_freq_range": "5925-6425,6525-6875",
              "afc_op_class": "131,132,133,134,136,137"
              }
    return params

def test_afc_empty(dev, apdev):
    """AFC server with no usable channel"""

    dev[0].cmd_execute(['iw', 'reg', 'set', 'CA'])
    wait_regdom_changes(dev[0])
    try:
        t = threading.Thread(target=run_afcd_server)
        t.start()

        hapd = None
        params = init_afc_dut_params()
        params["he_6ghz_reg_pwr_type"] = "1"
        params["channel"] = "5"
        params["op_class"] = "131"

        if not he_6ghz_supported():
            raise HwsimSkip("6 GHz frequency is not supported")

        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        if hapd.get_status_field("state") != "COUNTRY_UPDATE":
            raise Exception("Unexpected interface state - expected COUNTRY_UPDATE")
    except Exception as e:
        if isinstance(e, Exception) and \
            str(e) == "Failed to set hostapd parameter afcd_sock":
            raise HwsimSkip("AFC is not supported")
        raise
    finally:
        t.join()
        clear_regdom(hapd, dev)

def _test_afc(dev, apdev, freq_info, chan_info, channel, op_class, ccfs1):
    check_sae_capab(dev[0])
    dev[0].cmd_execute(['iw', 'reg', 'set', 'CA'])
    wait_regdom_changes(dev[0])

    try:
        t = threading.Thread(target=run_afcd_server,
                             args=(freq_info, chan_info))
        t.start()

        hapd = None
        params = init_afc_dut_params()
        params["he_6ghz_reg_pwr_type"] = "1"
        params["channel"] = str(channel)
        params["op_class"] = str(op_class)

        if op_class == 137:
            if ccfs1 > channel:
                he_ccfs1 = ccfs1 - 16
            else:
                he_ccfs1 = ccfs1 + 16
            params["he_oper_centr_freq_seg0_idx"] = str(he_ccfs1)
            params["ieee80211be"] = "1"
            params["eht_oper_centr_freq_seg0_idx"] = str(ccfs1)
        else:
            params["he_oper_centr_freq_seg0_idx"] = str(ccfs1)

        if not he_6ghz_supported():
            raise HwsimSkip("6 GHz frequency is not supported")
        if op_class == 137 and not eht_320mhz_supported():
            raise HwsimSkip("320 MHz channels are not supported")

        hapd = hostapd.add_ap(apdev[0], params)

        status = hapd.get_status()
        logger.info("hostapd STATUS: " + str(status))
        if hapd.get_status_field("ieee80211ax") != "1":
            raise Exception("STATUS did not indicate ieee80211ax=1")

        freq = hapd.get_status_field("freq")
        if int(freq) < 5955:
            raise Exception("Unexpected frequency: " + freq)

        dev[0].set("sae_pwe", "1")

        dev[0].connect("AFC", key_mgmt="SAE", sae_password="password",
                       ieee80211w="2", scan_freq=freq)
        hwsim_utils.test_connectivity(dev[0], hapd)

        sta = hapd.get_sta(dev[0].own_addr())
        if 'supp_op_classes' not in sta:
            raise Exception("supp_op_classes not indicated")
        supp_op_classes = binascii.unhexlify(sta['supp_op_classes'])
        if op_class not in supp_op_classes:
            raise Exception("STA did not indicate support for opclass %d" % op_class)

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        hapd.wait_sta_disconnect()
        hapd.disable()

    except Exception as e:
        if isinstance(e, Exception) and \
            str(e) == "Failed to set hostapd parameter afcd_sock":
            raise HwsimSkip("AFC is not supported")
        raise

    finally:
        t.join()
        dev[0].set("sae_pwe", "0")
        clear_regdom(hapd, dev)

def afc_gen_freq_info(freq, max_psd):
    high = freq + 10
    low = freq - 10
    ranges = {
        "frequencyRange": {
            "highFrequency": high,
            "lowFrequency": low
        },
        "maxPsd": max_psd
    }
    return ranges

# Make current channel unusable to force using acs
def test_afc_freq_20mhz(dev, apdev):
    """AFC availableFrequencyInfo with 20 MHz channel width usable"""
    freq_info = [afc_gen_freq_info(5975, 10.0)]
    _test_afc(dev, apdev, freq_info, None, 5, 131, 5)

def test_afc_freq_40mhz(dev, apdev):
    """AFC availableFrequencyInfo with 40 MHz channel width usable"""
    freq_info = [afc_gen_freq_info(5955, 10.0), afc_gen_freq_info(5975, 10.0)]
    _test_afc(dev, apdev, freq_info, None, 5, 132, 3)

def test_afc_freq_80mhz(dev, apdev):
    """AFC availableFrequencyInfo with 80 MHz channel width usable"""
    freq_info = [afc_gen_freq_info(5955, 10.0), afc_gen_freq_info(5975, 10.0),
                 afc_gen_freq_info(5995, 10.0), afc_gen_freq_info(6015, 10.0)]
    _test_afc(dev, apdev, freq_info, None, 5, 133, 7)

def test_afc_freq_160mhz(dev, apdev):
    """AFC availableFrequencyInfo with 160 MHz channel width usable"""
    freq_info = [afc_gen_freq_info(5955, 10.0), afc_gen_freq_info(5975, 10.0),
                 afc_gen_freq_info(5995, 10.0), afc_gen_freq_info(6015, 10.0),
                 afc_gen_freq_info(6035, 10.0), afc_gen_freq_info(6055, 10.0),
                 afc_gen_freq_info(6075, 10.0), afc_gen_freq_info(6095, 10.0)]
    _test_afc(dev, apdev, freq_info, None, 5, 134, 15)

def test_afc_freq_320mhz_1(dev, apdev):
    """AFC availableFrequencyInfo with 320 MHz-1 channel width usable"""
    freq_info = [afc_gen_freq_info(5955, 10.0), afc_gen_freq_info(5975, 10.0),
                 afc_gen_freq_info(5995, 10.0), afc_gen_freq_info(6015, 10.0),
                 afc_gen_freq_info(6035, 10.0), afc_gen_freq_info(6055, 10.0),
                 afc_gen_freq_info(6075, 10.0), afc_gen_freq_info(6095, 10.0),
                 afc_gen_freq_info(6115, 10.0), afc_gen_freq_info(6135, 10.0),
                 afc_gen_freq_info(6155, 10.0), afc_gen_freq_info(6175, 10.0),
                 afc_gen_freq_info(6195, 10.0), afc_gen_freq_info(6215, 10.0),
                 afc_gen_freq_info(6235, 10.0), afc_gen_freq_info(6255, 10.0)]
    _test_afc(dev, apdev, freq_info, None, 5, 137, 31)

def test_afc_freq_320mhz_2(dev, apdev):
    """AFC availableFrequencyInfo with 320 MHz-2 channel width usable"""
    freq_info = [afc_gen_freq_info(6115, 10.0), afc_gen_freq_info(6135, 10.0),
                 afc_gen_freq_info(6155, 10.0), afc_gen_freq_info(6175, 10.0),
                 afc_gen_freq_info(6195, 10.0), afc_gen_freq_info(6215, 10.0),
                 afc_gen_freq_info(6235, 10.0), afc_gen_freq_info(6255, 10.0),
                 afc_gen_freq_info(6275, 10.0), afc_gen_freq_info(6295, 10.0),
                 afc_gen_freq_info(6315, 10.0), afc_gen_freq_info(6335, 10.0),
                 afc_gen_freq_info(6355, 10.0), afc_gen_freq_info(6375, 10.0),
                 afc_gen_freq_info(6395, 10.0), afc_gen_freq_info(6415, 10.0)]
    _test_afc(dev, apdev, freq_info, None, 37, 137, 63)


def afc_gen_chan_info(chan, op_class, eirp):
    chan_info = {
        "channelCfi": chan,
        "globalOperatingClass": op_class,
        "maxEirp": [eirp] * len(chan)
    }
    return chan_info

def test_afc_chan_20mhz(dev, apdev):
    """AFC availableChannelInfo with 20 MHz channel width usable"""
    chan_info = [afc_gen_chan_info([5], 131, 23.0)]
    _test_afc(dev, apdev, None, chan_info, 5, 131, 5)

def test_afc_chan_40mhz(dev, apdev):
    """AFC availableChannelInfo with 40 MHz channel width usable"""
    chan_info = [afc_gen_chan_info([1, 5], 131, 23.0),
                 afc_gen_chan_info([3], 132, 26.0)]
    _test_afc(dev, apdev, None, chan_info, 5, 132, 3)

def test_afc_chan_80mhz(dev, apdev):
    """AFC availableChannelInfo with 80 MHz channel width usable"""
    chan_info = [afc_gen_chan_info([1, 5, 9, 13], 131, 23.0),
                 afc_gen_chan_info([3, 11], 132, 26.0),
                 afc_gen_chan_info([7], 133, 29.0)]
    _test_afc(dev, apdev, None, chan_info, 5, 133, 7)

def test_afc_chan_160mhz(dev, apdev):
    """AFC availableChannelInfo with 160 MHz channel width usable"""
    chan_info = [afc_gen_chan_info([1, 5, 9, 13, 17, 21, 25, 29], 131, 23.0),
                 afc_gen_chan_info([3, 11, 19, 27], 132, 26.0),
                 afc_gen_chan_info([7, 23], 133, 29.0),
                 afc_gen_chan_info([15], 134, 32.0)]
    _test_afc(dev, apdev, None, chan_info, 5, 134, 15)

def test_afc_chan_320mhz_1(dev, apdev):
    """AFC availableChannelInfo with 320 MHz-1 channel width usable"""
    chan_info = [afc_gen_chan_info([1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45,
                                    49, 53, 57, 61], 131, 23.0),
                 afc_gen_chan_info([3, 11, 19, 27, 35, 43, 51, 59], 132, 26.0),
                 afc_gen_chan_info([7, 23, 39, 55], 133, 29.0),
                 afc_gen_chan_info([15, 47], 134, 32.0),
                 afc_gen_chan_info([31], 137, 35.0)]
    _test_afc(dev, apdev, None, chan_info, 5, 137, 31)

def test_afc_chan_320mhz_2(dev, apdev):
    """AFC availableChannelInfo with 320 MHz-2 channel width usable"""
    chan_info = [afc_gen_chan_info([33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73,
                                    77, 81, 85, 89, 93], 131, 23.0),
                 afc_gen_chan_info([35, 43, 51, 59, 67, 75, 83, 91], 132, 26.0),
                 afc_gen_chan_info([39, 55, 71, 87], 133, 29.0),
                 afc_gen_chan_info([47, 79], 134, 32.0),
                 afc_gen_chan_info([63], 137, 35.0)]
    _test_afc(dev, apdev, None, chan_info, 37, 137, 63)
