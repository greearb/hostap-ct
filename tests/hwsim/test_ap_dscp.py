# AP DSCP Policy hwsim tests
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd
from utils import *


def ap_client_connect(dev, apdev, params=None, enable_dscp=False):
    if params is None:
        params = {}

    p = hostapd.wpa2_params(ssid="dscp-ap", passphrase="12345678")
    p["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    p["ieee80211w"] = "2"
    p.update(params)
    if enable_dscp:
        p["enable_dscp_policy_capa"] = "1"

    try:
        hapd = hostapd.add_ap(apdev[0], p)
    except:
        raise HwsimSkip("AP DSCP policy not supported")

    # Enable DSCP capability in STA.
    if "OK" not in dev[0].request("SET enable_dscp_policy_capa 1"):
        raise Exception("Failed to enable STA DSCP capability")
    dev[0].connect(p.get("ssid", "dscp-ap"), psk="12345678", ieee80211w="2",
                   key_mgmt="WPA-PSK-SHA256", scan_freq="2412")
    hapd.wait_sta()
    return hapd

def set_ap_dscp_policy(hapd, sta, policy):
    cmd = "DSCP_POLICY " + sta + " " + policy
    res = hapd.request(cmd)
    if "UNKNOWN COMMAND" in res:
        raise HwsimSkip("AP DSCP policy ctrl_iface not supported")
    if "OK" in res:
        return

    raise Exception("Failed to configure AP DSCP policy: " + cmd +
                    " (initial response: " + res.strip() + ")")

def set_ap_dscp_policy_fail(hapd, sta, policy):
    cmd = "DSCP_POLICY " + sta + " " + policy
    res = hapd.request(cmd)
    if "UNKNOWN COMMAND" in res:
        raise HwsimSkip("AP DSCP policy ctrl_iface not supported")
    if "FAIL" not in res:
        raise Exception("Invalid AP DSCP policy accepted: " + cmd)

def send_unsolicited_dscp_req(hapd, sta, reset, policy_ids):
    policy_list = "_".join([str(x) for x in policy_ids])
    cmd = ("SEND_UNSOLICITED_DSCP_REQ " + sta + " reset=" + str(reset) +
           " policy_id_list=" + policy_list)
    res = hapd.request(cmd)
    if "UNKNOWN COMMAND" in res:
        raise HwsimSkip("AP DSCP policy ctrl_iface not supported")
    if "OK" in res:
        return

    policy_list = ",".join([str(x) for x in policy_ids])
    cmd = ("SEND_UNSOLICITED_DSCP_REQ " + sta + " reset=" + str(reset) +
           " policy_id_list=" + policy_list)
    res = hapd.request(cmd)
    if "UNKNOWN COMMAND" in res:
        raise HwsimSkip("AP DSCP policy ctrl_iface not supported")
    if "OK" not in res:
        raise Exception("Failed to send unsolicited DSCP policy request")

def expect_dscp_event(dev, expected):
    ev = dev.wait_event(["CTRL-EVENT-DSCP-POLICY"], timeout=5)
    if ev is None:
        raise Exception("No DSCP event reported")
    if ev != expected:
        raise Exception("Unexpected DSCP event (%s; expected: %s)" % (ev, expected))

def expect_dscp_event_contains(dev, expected):
    ev = dev.wait_event(["CTRL-EVENT-DSCP-POLICY"], timeout=5)
    if ev is None:
        raise Exception("No DSCP event reported")
    if expected not in ev:
        raise Exception("Unexpected DSCP event (%s; expected to contain: %s)"
                        % (ev, expected))

def test_ap_dscp_unsolicited_request(dev, apdev):
    """AP DSCP: unsolicited request with multiple policies"""

    hapd = ap_client_connect(dev, apdev, enable_dscp=True)
    sta = dev[0].own_addr()

    set_ap_dscp_policy(hapd, sta,
                       "policy_id=1 request_type=Add dscp=46 "
                       "classifier_mask=0x55 ip_version=4 "
                       "dst_ip=192.168.1.148 dst_port=5002 protocol=17")
    set_ap_dscp_policy(hapd, sta,
                       "policy_id=2 request_type=Add dscp=34 "
                       "classifier_mask=0x5F ip_version=4 "
                       "src_ip=192.168.1.155 dst_ip=192.168.1.148 "
                       "src_port=7003 dst_port=5003 protocol=17")
    set_ap_dscp_policy(hapd, sta,
                       "policy_id=3 request_type=Add dscp=24 "
                       "domain_name=video.wifitest.org")
    send_unsolicited_dscp_req(hapd, sta, 0, [1, 2, 3])

    expect_dscp_event_contains(dev[0], "request_start")
    expect_dscp_event_contains(dev[0], "add policy_id=1 dscp=46")
    expect_dscp_event_contains(dev[0], "add policy_id=2 dscp=34")
    expect_dscp_event_contains(dev[0], "add policy_id=3 dscp=24")
    expect_dscp_event_contains(dev[0], "request_end")

def test_ap_dscp_unsolicited_request_reset(dev, apdev):
    """AP DSCP: unsolicited request with reset flag"""

    hapd = ap_client_connect(dev, apdev, enable_dscp=True)
    sta = dev[0].own_addr()

    set_ap_dscp_policy(hapd, sta,
                       "policy_id=7 dscp=36 "
                       "start_port=12345 end_port=23456")
    send_unsolicited_dscp_req(hapd, sta, 1, [7])

    expect_dscp_event(dev[0],
                      "<3>CTRL-EVENT-DSCP-POLICY request_start clear_all")
    expect_dscp_event(
        dev[0],
        "<3>CTRL-EVENT-DSCP-POLICY add policy_id=7 dscp=36 ip_version=0 start_port=12345 end_port=23456",
    )
    expect_dscp_event(dev[0], "<3>CTRL-EVENT-DSCP-POLICY request_end")

def test_ap_dscp_query_triggers_request(dev, apdev):
    """AP DSCP: STA query triggers policy request"""

    hapd = ap_client_connect(dev, apdev, enable_dscp=True)
    sta = dev[0].own_addr()

    set_ap_dscp_policy(hapd, sta,
                       "policy_id=2 dscp=10 "
                       "start_port=1000 end_port=2000")
    set_ap_dscp_policy(hapd, sta,
                       "policy_id=3 dscp=20 "
                       "domain_name=example.com")

    if "OK" not in dev[0].request("DSCP_QUERY wildcard"):
        ev = dev[0].wait_event(["CTRL-EVENT-DSCP-POLICY request_wait end"],
                               timeout=6)
        if ev is None:
            raise Exception("STA failed to send DSCP Query")
        if "OK" not in dev[0].request("DSCP_QUERY wildcard"):
            raise Exception("STA failed to send DSCP Query")

    expect_dscp_event(dev[0], "<3>CTRL-EVENT-DSCP-POLICY request_start")
    expect_dscp_event(
        dev[0],
        "<3>CTRL-EVENT-DSCP-POLICY add policy_id=2 dscp=10 ip_version=0 start_port=1000 end_port=2000",
    )
    expect_dscp_event(
        dev[0],
        "<3>CTRL-EVENT-DSCP-POLICY add policy_id=3 dscp=20 ip_version=0 domain_name=example.com",
    )
    expect_dscp_event(dev[0], "<3>CTRL-EVENT-DSCP-POLICY request_end")

def test_ap_dscp_invalid_policy(dev, apdev):
    """AP DSCP: invalid policy combinations rejected"""

    hapd = ap_client_connect(dev, apdev, enable_dscp=True)
    sta = dev[0].own_addr()

    set_ap_dscp_policy_fail(hapd, sta,
                            "policy_id=10 dscp=36 "
                            "classifier_mask=4 ip_version=4 "
                            "dst_ip=192.168.0.2 domain_name=example.com")
    set_ap_dscp_policy_fail(hapd, sta,
                            "policy_id=11 dscp=36 "
                            "classifier_mask=16 ip_version=4 dst_port=2345 "
                            "start_port=100 end_port=200")

def test_ap_dscp_remove_policy(dev, apdev):
    """AP DSCP: remove policy request"""

    hapd = ap_client_connect(dev, apdev, enable_dscp=True)
    sta = dev[0].own_addr()

    set_ap_dscp_policy(hapd, sta,
                       "policy_id=12 request_type=remove")
    send_unsolicited_dscp_req(hapd, sta, 0, [12])

    expect_dscp_event(dev[0], "<3>CTRL-EVENT-DSCP-POLICY request_start")
    expect_dscp_event(dev[0], "<3>CTRL-EVENT-DSCP-POLICY remove policy_id=12")
    expect_dscp_event(dev[0], "<3>CTRL-EVENT-DSCP-POLICY request_end")

def test_ap_dscp_add_send_remove_send(dev, apdev):
    """AP DSCP: add policies, send request, remove and send request"""

    hapd = ap_client_connect(dev, apdev, enable_dscp=True)
    sta = dev[0].own_addr()

    # Add policies on AP for this STA.
    set_ap_dscp_policy(
        hapd,
        sta,
        "policy_id=1 request_type=Add dscp=46 "
        "classifier_mask=0x55 ip_version=4 "
        "dst_ip=192.168.1.148 dst_port=5002 protocol=17",
    )
    set_ap_dscp_policy(
        hapd,
        sta,
        "policy_id=2 request_type=Add dscp=34 "
        "classifier_mask=0x5F ip_version=4 "
        "src_ip=192.168.1.155 dst_ip=192.168.1.148 "
        "src_port=7003 dst_port=5003 protocol=17",
    )
    set_ap_dscp_policy(
        hapd,
        sta,
        "policy_id=4 request_type=Add dscp=50 "
        "classifier_mask=0x5F ip_version=6 "
        "src_ip=::0 dst_ip=::0 src_port=7001 dst_port=5001 protocol=17",
    )

    # Send unsolicited request for the added policies.
    send_unsolicited_dscp_req(hapd, sta, 0, [1, 2, 4])
    expect_dscp_event_contains(dev[0], "request_start")
    expect_dscp_event_contains(dev[0], "add policy_id=1 dscp=46")
    expect_dscp_event_contains(dev[0], "add policy_id=2 dscp=34")
    expect_dscp_event_contains(dev[0], "add policy_id=4 dscp=50")
    expect_dscp_event_contains(dev[0], "request_end")

    # Update policy 1 as remove and send again.
    set_ap_dscp_policy(hapd, sta, "policy_id=1 request_type=Remove")
    send_unsolicited_dscp_req(hapd, sta, 0, [1, 2, 4])
    expect_dscp_event_contains(dev[0], "request_start")
    expect_dscp_event_contains(dev[0], "remove policy_id=1")
    expect_dscp_event_contains(dev[0], "add policy_id=2 dscp=34")
    expect_dscp_event_contains(dev[0], "add policy_id=4 dscp=50")
    expect_dscp_event_contains(dev[0], "request_end")
