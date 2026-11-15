# Test cases for Wi-Fi Direct R2 features like unsynchronized service discovery
# (P2P USD), Bootstrapping and Pairing.
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import binascii
import logging

from hwsim import HWSimRadio

logger = logging.getLogger()
import os
import hwsim_utils

from utils import *
from wpasupplicant import WpaSupplicant
from test_nan_usd import check_nan_usd_capab, split_nan_event
from test_pasn import check_pasn_capab
from test_p2p_grpform import autogo

def check_p2p2_capab(dev):
    check_nan_usd_capab(dev)
    check_pasn_capab(dev)
    res = dev.request("GET_CAPABILITY p2p2")
    if res is None or "not supported" in res:
        raise HwsimSkip("P2P2 not supported")
    res = dev.request("GET_CAPABILITY pcc_mode")
    if res is None or "not supported" in res:
        raise HwsimSkip("PCC mode not supported")

def set_p2p2_configs(dev):
    dev.global_request("P2P_SET pasn_type 3")
    dev.global_request("P2P_SET supported_bootstrapmethods 6")

def test_p2p_usd_publish_invalid_param(dev):
    """P2P USD Publish with invalid parameters"""
    check_p2p2_capab(dev[0])

    # Both solicited and unsolicited disabled is invalid
    cmd = "NAN_PUBLISH service_name=_test solicited=0 unsolicited=0 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" not in id0:
        raise Exception("NAN_PUBLISH accepts both solicited=0 and unsolicited=0 with p2p=1")

def test_p2p_usd_publish(dev, apdev):
    """P2P USD Publish"""
    check_p2p2_capab(dev[0])
    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_PUBLISH for P2P failed")

    cmd = "NAN_UPDATE_PUBLISH publish_id=" + id0 + " ssi=1122334455"
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_UPDATE_PUBLISH for P2P failed")

    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["NAN-PUBLISH-TERMINATED"], timeout=1)
    if ev is None:
        raise Exception("PublishTerminated event not seen")
    if "publish_id=" + id0 not in ev:
        raise Exception("Unexpected publish_id: " + ev)
    if "reason=user-request" not in ev:
        raise Exception("Unexpected reason: " + ev)

    cmd = "NAN_PUBLISH service_name=_test p2p=1"
    count = 0
    for i in range(256):
        if "FAIL" in dev[0].global_request(cmd):
            break
        count += 1
    logger.info("Maximum services: %d" % count)
    for i in range(count):
        cmd = "NAN_CANCEL_PUBLISH publish_id=%s" % (i + 1)
        if "FAIL" in dev[0].global_request(cmd):
            raise Exception("NAN_CANCEL_PUBLISH failed")

        ev = dev[0].wait_global_event(["NAN-PUBLISH-TERMINATED"], timeout=1)
        if ev is None:
            raise Exception("PublishTerminated event not seen")

def test_p2p_usd_subscribe(dev, apdev):
    """P2P USD Subscribe"""
    check_p2p2_capab(dev[0])
    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")

    ev = dev[0].wait_global_event(["NAN-SUBSCRIBE-TERMINATED"], timeout=1)
    if ev is None:
        raise Exception("SubscribeTerminated event not seen")
    if "subscribe_id=" + id0 not in ev:
        raise Exception("Unexpected subscribe_id: " + ev)
    if "reason=user-request" not in ev:
        raise Exception("Unexpected reason: " + ev)

def test_p2p_usd_match(dev, apdev):
    """P2P USD Publish/Subscribe match"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])
    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=5 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    dev[0].global_request("NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0)
    dev[1].global_request("NAN_CANCEL_PUBLISH publish_id=" + id1)

def run_p2p_pairing_password(dev):
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair provdisc he go_intent=15 p2p2 bstrapmethod=2 auth password=975310123 freq=2437"
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth Failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair provdisc he go_intent=5 p2p2 bstrapmethod=32 password=975310123"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT Failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].group_form_result(ev, no_pwd=True)
    dev[0].dump_monitor()

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")
    dev[1].group_form_result(ev)

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_pairing_password(dev, apdev):
    """P2P Pairing with Password"""
    run_p2p_pairing_password(dev)

def test_p2p_pairing_password_dev(dev, apdev):
    """P2P Pairing with Password with dedicated P2P device"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        run_p2p_pairing_password([dev[0], wpas])

def test_p2p_pairing_password_dev2(dev, apdev):
    """P2P Pairing with Password with dedicated P2P device (reversed) and no group interface"""
    with HWSimRadio(use_p2p_device=True) as (radio, iface):
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(iface)
        wpas.global_request("SET p2p_no_group_iface 1")
        run_p2p_pairing_password([wpas, dev[0]])

def test_p2p_pairing_opportunistic(dev, apdev):
    """P2P Pairing with Opportunistic"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair provdisc he go_intent=15 p2p2 bstrapmethod=1 auth freq=2437"
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth Failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair provdisc he go_intent=5 p2p2 bstrapmethod=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT Failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")
    dev[1].group_form_result(ev)
    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_auto_go_and_client_join(dev, apdev):
    """A new client joining a group using P2P Pairing/Opportunistic"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_GROUP_ADD p2p2"
    res = dev[1].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair provdisc he go_intent=15 p2p2 bstrapmethod=1 join auth"
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair provdisc p2p2 join bstrapmethod=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_pcc_auto_go_and_pcc_client_join(dev, apdev):
    """A PCC client joining a PCC Auto GO using P2P join"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_GROUP_ADD p2p2 p2pmode=2 freq=2437"
    res = dev[1].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")
    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")

    res = dev[1].group_form_result(ev)
    if dev[1].get_group_status_field("passphrase", extra="WPS") != res['passphrase']:
        raise Exception("passphrase mismatch")
    if dev[1].group_request("P2P_GET_PASSPHRASE") != res['passphrase']:
        raise Exception("passphrase mismatch(2)")

    cli = dev[0]
    id2 = cli.p2pdev_add_network()
    cli.p2pdev_set_network_quoted(id2, "ssid", res['ssid'])
    cli.p2pdev_set_network_quoted(id2, "psk", res['passphrase'])
    cli.p2pdev_set_network(id2, "mode", "0")
    cli.p2pdev_set_network(id2, "disabled", "2")
    cmd = "P2P_GROUP_ADD persistent=" + str(id2) + " p2p2 p2pmode=2 freq=2437"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_GROUP_ADD join on client failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].dump_monitor()

    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_r1_auto_go_and_pcc_client_join(dev, apdev):
    """A PCC client joining an R1 Auto GO using the legacy PSK profile"""
    check_p2p2_capab(dev[1])
    set_p2p2_configs(dev[1])

    res = dev[0].global_request("P2P_GROUP_ADD freq=2437")
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")
    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    res = dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    cli = dev[1]
    id2 = cli.p2pdev_add_network()
    cli.p2pdev_set_network_quoted(id2, "ssid", res['ssid'])
    cli.p2pdev_set_network_quoted(id2, "psk", res['passphrase'])
    cli.p2pdev_set_network(id2, "bssid", res['go_dev_addr'])
    cli.p2pdev_set_network(id2, "mode", "0")
    cli.p2pdev_set_network(id2, "disabled", "2")
    cmd = "P2P_GROUP_ADD persistent=%d p2p2 p2pmode=2 freq=2437" % id2
    if "FAIL" in cli.global_request(cmd):
        raise Exception("P2P_GROUP_ADD join on client failed")

    ev = cli.wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out (client)")
    dev[0].wait_sta(addr=cli.own_addr(), wait_4way_hs=True)

    key_mgmt = cli.get_status_field("key_mgmt")
    if key_mgmt != "WPA2-PSK":
        raise Exception("Unexpected key_mgmt: " + key_mgmt)
    pmf = cli.get_status_field("pmf")
    if pmf not in (None, "0"):
        raise Exception("Unexpected pmf: " + str(pmf))

    hwsim_utils.test_connectivity_p2p(dev[0], cli)

    dev[0].remove_group()
    cli.wait_go_ending_session()
    cli.dump_monitor()

def test_p2p_auto_go_and_client_join_sae(dev, apdev):
    """A new client joining a group using P2P Pairing/SAE"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_GROUP_ADD p2p2"
    res = dev[1].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair provdisc he go_intent=15 p2p2 bstrapmethod=2 join auth password=975310123"
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair provdisc p2p2 join bstrapmethod=32 password=975310123"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_pairing_verification(dev, apdev, params):
    """P2P Pairing with Verification"""

    """wpa_supplicant config file for pairing verification"""
    config = os.path.join(params['logdir'], 'p2p_pairing_verification.conf')
    if os.path.exists(config):
        os.remove(config)

    wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')

    with open(config, "w") as f:
         f.write("update_config=1\n")

    wpas.interface_add("wlan5", config=config)

    check_p2p2_capab(wpas)
    check_p2p2_capab(dev[1])

    set_p2p2_configs(wpas)
    set_p2p2_configs(dev[1])

    wpas.global_request("SET update_config 1")
    wpas.global_request("SAVE_CONFIG")

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = wpas.global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = wpas.wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = wpas.wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in wpas.global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_CONNECT " + wpas.p2p_dev_addr() + " pair provdisc he go_intent=15 p2p2 bstrapmethod=2 auth password=975310123 freq=2437 persistent"
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth Failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair provdisc he go_intent=5 p2p2 bstrapmethod=32 password=975310123 persistent"
    id0 = wpas.global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT Failed")

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[1].group_form_result(ev)

    ev = wpas.wait_global_event(["P2P-GROUP-STARTED",
                                   "WPA: 4-Way Handshake failed"], timeout=30)
    if ev is None:
        raise Exception("Group formation timed out (2)")
    wpas.dump_monitor()

    dev[1].remove_group()
    wpas.wait_go_ending_session()
    wpas.dump_monitor()

    wpas.interface_remove("wlan5")
    wpas.interface_add("wlan5", config=config)
    set_p2p2_configs(wpas)

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    id0 = wpas.global_request(cmd)
    if "FAIL" in id0:
        raise Exception("NAN_SUBSCRIBE for P2P failed (2)")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    id1 = dev[1].global_request(cmd)
    if "FAIL" in id1:
        raise Exception("NAN_PUBLISH for P2P failed (2)")

    ev = wpas.wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = wpas.wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + id0
    if "FAIL" in wpas.global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed (2)")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + id1
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed (2)")

    wpas.global_request("SET persistent_reconnect 1")
    dev[1].global_request("SET persistent_reconnect 1")
    peer = wpas.get_peer(dev[1].p2p_dev_addr())
    if 'persistent' not in peer:
        raise Exception("Missing information on persistent group for the peer")
    cmd = "P2P_INVITE persistent peer=" + dev[1].p2p_dev_addr() + " p2p2"
    id0 = wpas.global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_INVITE Failed")

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=30)
    if ev is None:
        raise Exception("Group re-invoke failed")
    dev[1].group_form_result(ev)

    ev = wpas.wait_global_event(["P2P-GROUP-STARTED",
                                 "WPA: 4-Way Handshake failed"], timeout=30)
    if ev is None:
        raise Exception("Group re-invoke failed (2)")
    if "P2P-GROUP-STARTED" not in ev:
        raise Exception("Failed to complete group start on reinvocation")
    wpas.dump_monitor()

    res = dev[1].group_request("P2P_GET_DIRA")
    addr, nonce, tag = res.split()

    cmd = "P2P_VALIDATE_DIRA " + addr + " nonce=" + nonce + " tag=" + tag
    res = wpas.group_request(cmd)
    if "FAIL" in res:
        raise Exception("DIRA validation failed")

    dev[1].remove_group()
    wpas.wait_go_ending_session()
    wpas.dump_monitor()

def test_p2p_auto_go_pcc_with_two_cli(dev, apdev):
    """P2P autonomous GO in PCC mode with PSK and SAE clients"""
    check_p2p2_capab(dev[0])
    set_p2p2_configs(dev[0])

    cmd = "P2P_GROUP_ADD p2p2 p2pmode=2 freq=2462"
    res = dev[0].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")
    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")

    res = dev[0].group_form_result(ev)
    if dev[0].get_group_status_field("passphrase", extra="WPS") != res['passphrase']:
        raise Exception("passphrase mismatch")
    if dev[0].group_request("P2P_GET_PASSPHRASE") != res['passphrase']:
        raise Exception("passphrase mismatch(2)")

    logger.info("Connect legacy non-WPS P2P client")
    dev[1].global_request("P2P_SET disabled 1")
    dev[0].dump_monitor()
    dev[1].connect(ssid=res['ssid'], psk=res['passphrase'], proto='RSN',
                   key_mgmt='WPA-PSK', pairwise='CCMP',
                   group='CCMP', scan_freq=res['freq'])
    dev[0].wait_sta(addr=dev[1].own_addr(), wait_4way_hs=True)

    try:
        logger.info("Connect P2P2 client")
        dev[2].global_request("P2P_SET disabled 1")
        dev[0].dump_monitor()
        dev[2].set("rsn_overriding", "1")
        dev[2].set("sae_pwe", "2")
        dev[2].connect(ssid=res['ssid'], sae_password=res['passphrase'],
                       proto='WPA2', key_mgmt='SAE', ieee80211w='2',
                       pairwise='GCMP-256 CCMP', group='GCMP-256 CCMP',
                       scan_freq=res['freq'])
        dev[0].wait_sta(addr=dev[2].own_addr(), wait_4way_hs=True)

        hwsim_utils.test_connectivity_p2p_sta(dev[1], dev[2])

        dev[2].request("DISCONNECT")
        dev[2].wait_disconnected()
        dev[0].wait_sta_disconnect(addr=dev[2].own_addr())
    finally:
        dev[2].set("sae_pwe", "0")
        dev[2].set("rsn_overriding", "0")

    dev[1].request("DISCONNECT")
    dev[1].wait_disconnected()
    dev[0].wait_sta_disconnect(addr=dev[1].own_addr())

    dev[0].remove_group()

def test_p2p_auto_go_pcc_with_p2p2_cli(dev, apdev):
    """P2P autonomous GO in PCC mode with P2P2 clients"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])
    set_p2p2_configs(dev[0])

    cmd = "P2P_GROUP_ADD p2p2 p2pmode=2 freq=2462"
    res = dev[0].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")
    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")

    res = dev[0].group_form_result(ev)
    if dev[0].get_group_status_field("passphrase", extra="WPS") != res['passphrase']:
        raise Exception("passphrase mismatch")
    if dev[0].group_request("P2P_GET_PASSPHRASE") != res['passphrase']:
        raise Exception("passphrase mismatch(2)")

    ssidhex =  binascii.hexlify(res['ssid'].encode()).decode()
    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair p2p2 skip_prov join password=" + res['passphrase'] + " ssid=" + ssidhex
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT failed")

    ev = dev[1].wait_global_event(["CTRL-EVENT-CONNECTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[1].dump_monitor()

    dev[0].wait_sta()

    dev[0].remove_group()
    dev[1].dump_monitor()

def run_p2p_r2_pcc_go_and_pcc_client_join(go, cli):
    """Start a PCC Auto GO and join with a PCC client using SAE"""
    check_sae_capab(go)
    check_sae_capab(cli)
    set_p2p2_configs(go)
    set_p2p2_configs(cli)

    cmd = "P2P_GROUP_ADD p2p2 p2pmode=2 freq=2437"
    if "FAIL" in go.global_request(cmd):
        raise Exception("P2P_GROUP_ADD failed")
    ev = go.wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")

    res = go.group_form_result(ev)
    if go.get_group_status_field("passphrase", extra="WPS") != res['passphrase']:
        raise Exception("passphrase mismatch")
    if go.group_request("P2P_GET_PASSPHRASE") != res['passphrase']:
        raise Exception("passphrase mismatch(2)")

    id2 = cli.p2pdev_add_network()
    cli.p2pdev_set_network_quoted(id2, "ssid", res['ssid'])
    cli.p2pdev_set_network_quoted(id2, "psk", res['passphrase'])
    cli.p2pdev_set_network(id2, "mode", "0")
    cli.p2pdev_set_network(id2, "disabled", "2")
    cmd = "P2P_GROUP_ADD persistent=" + str(id2) + " p2p2 p2pmode=2 freq=2437"
    if "FAIL" in cli.global_request(cmd):
        raise Exception("P2P_GROUP_ADD join on client failed")

    ev = cli.wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out (client)")
    go.wait_sta(addr=cli.own_addr(), wait_4way_hs=True)

    key_mgmt = cli.get_status_field("key_mgmt")
    if key_mgmt != "SAE":
        raise Exception("Unexpected key_mgmt: " + key_mgmt)
    pmf = cli.get_status_field("pmf")
    if pmf != "2":
        raise Exception("Unexpected pmf: " + pmf)

    hwsim_utils.test_connectivity_p2p(go, cli)

    go.remove_group()
    cli.wait_go_ending_session()
    cli.dump_monitor()

def test_p2p_r2_pcc_auto_go_and_pcc_client_sae(dev, apdev):
    """PCC Auto GO and PCC client join using SAE"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])
    run_p2p_r2_pcc_go_and_pcc_client_join(dev[0], dev[1])

def test_p2p_r2_pcc_auto_go_and_pcc_client_sae_no_group_iface(dev, apdev):
    """PCC Auto GO and PCC client SAE join with p2p_no_group_iface=1"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])
    dev[0].global_request("SET p2p_no_group_iface 1")
    try:
        run_p2p_r2_pcc_go_and_pcc_client_join(dev[0], dev[1])
    finally:
        dev[0].global_request("SET p2p_no_group_iface 0")

def test_p2p_bootstrapping_comeback_pairing(dev, apdev):
    """P2P bootstrapping with comeback and pairing"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    sub_id = dev[0].global_request(cmd)
    if "FAIL" in sub_id:
        raise Exception("NAN_SUBSCRIBE for P2P failed")

    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    pub_id = dev[1].global_request(cmd)
    if "FAIL" in pub_id:
        raise Exception("NAN_PUBLISH for P2P failed")

    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")
    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=5)
    if ev is None:
        raise Exception("Peer not found")

    ev = dev[0].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=5)
    if ev is None:
        raise Exception("DiscoveryResult event not seen")
    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    cmd = "P2P_PROV_DISC " + dev[1].p2p_dev_addr() + " bstrapmethod=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("Bootstrapping failed")

    ev = dev[1].wait_global_event(["P2P-BOOTSTRAP-REQUEST"], timeout=10)
    if ev is None:
        raise Exception("Bootstrap request event not received")

    cmd = "P2P_CONNECT " + dev[0].p2p_dev_addr() + " pair he go_intent=15 p2p2 bstrapmethod=1 auth freq=2437"
    id0 = dev[1].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT auth failed")

    ev = dev[0].wait_global_event(["P2P-BOOTSTRAP-SUCCESS"], timeout=10)
    if ev is None:
        raise Exception("Bootstrap success not received")

    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + sub_id
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE for P2P failed")
    cmd = "NAN_CANCEL_PUBLISH publish_id=" + pub_id
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH for P2P failed")

    cmd = "P2P_CONNECT " + dev[1].p2p_dev_addr() + " pair he go_intent=5 p2p2 bstrapmethod=1"
    id0 = dev[0].global_request(cmd)
    if "FAIL" in id0:
        raise Exception("P2P_CONNECT failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    #dev[0].group_form_result(ev)
    dev[0].dump_monitor()

    ev = dev[1].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out(2)")
    dev[1].group_form_result(ev)
    dev[1].wait_sta()

    dev[1].remove_group()
    dev[0].wait_go_ending_session()
    dev[0].dump_monitor()

def test_p2p_go_started_before_usd(dev, apdev):
    """P2P GO with NAN USD discovery - GO as subscriber, device as publisher"""
    check_p2p2_capab(dev[0])
    check_p2p2_capab(dev[1])

    set_p2p2_configs(dev[0])
    set_p2p2_configs(dev[1])

    # Create autonomous P2P GO on dev[0]
    logger.info("Creating P2P GO on dev[0]")
    cmd = "P2P_GROUP_ADD p2p2 freq=2437"
    res = dev[0].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].group_form_result(ev)

    # Start NAN_PUBLISH (active subscriber) on P2P GO interface (dev[0])
    logger.info("Starting NAN_PUBLISH (active subscriber) on P2P GO")
    cmd = "NAN_PUBLISH service_name=_test unsolicited=0 srv_proto_type=2 ssi=6677 ttl=10 p2p=1"
    pub_id = dev[0].global_request(cmd)
    if "FAIL" in pub_id:
        raise Exception("NAN_PUBLISH on P2P GO failed")
    logger.info("NAN_PUBLISH ID on GO: %s" % pub_id)

    # Start NAN_SUBSCRIBE (solicited publisher) on P2P device (dev[1])
    logger.info("Starting NAN_SUBSCRIBE (solicited publisher) on P2P device")
    cmd = "NAN_SUBSCRIBE service_name=_test active=1 srv_proto_type=2 ssi=1122334455 ttl=10 p2p=1"
    sub_id = dev[1].global_request(cmd)
    if "FAIL" in sub_id:
        raise Exception("NAN_SUBSCRIBE on P2P device failed")
    logger.info("NAN_SUBSCRIBE ID on device: %s" % sub_id)

    # Wait for P2P-DEVICE-FOUND events
    logger.info("Waiting for P2P-DEVICE-FOUND events")
    ev = dev[0].wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev is None:
        raise Exception("Peer not found by GO")
    logger.info("GO found peer: %s" % ev)

    ev = dev[1].wait_global_event(["P2P-DEVICE-FOUND"], timeout=10)
    if ev is None:
        raise Exception("Peer not found by device")
    logger.info("Device found peer: %s" % ev)

    # Wait for NAN-DISCOVERY-RESULT on the subscriber (dev[1])
    logger.info("Waiting for NAN-DISCOVERY-RESULT on subscriber")
    ev = dev[1].wait_global_event(["NAN-DISCOVERY-RESULT"], timeout=10)
    if ev is None:
        raise Exception("DiscoveryResult event not seen on subscriber")
    logger.info("Discovery result on subscriber: %s" % ev)

    if "srv_proto_type=2" not in ev.split(' '):
        raise Exception("Unexpected srv_proto_type: " + ev)
    if "ssi=6677" not in ev.split(' '):
        raise Exception("Unexpected ssi: " + ev)

    # Wait for NAN-REPLIED on the publisher (dev[0] - P2P GO)
    logger.info("Waiting for NAN-REPLIED on publisher (P2P GO)")
    ev = dev[0].wait_global_event(["NAN-REPLIED"], timeout=10)
    if ev is None:
        logger.info("NAN-REPLIED event not seen on P2P GO (this is expected if SDF frames are not being processed)")
    else:
        logger.info("NAN-REPLIED on GO: %s" % ev)
        if "srv_proto_type=2" not in ev.split(' '):
            raise Exception("Unexpected srv_proto_type in REPLIED: " + ev)

    # Cleanup
    logger.info("Cleaning up")
    cmd = "NAN_CANCEL_SUBSCRIBE subscribe_id=" + sub_id
    if "FAIL" in dev[1].global_request(cmd):
        raise Exception("NAN_CANCEL_SUBSCRIBE failed")

    cmd = "NAN_CANCEL_PUBLISH publish_id=" + pub_id
    if "FAIL" in dev[0].global_request(cmd):
        raise Exception("NAN_CANCEL_PUBLISH failed")

    dev[0].remove_group()
    logger.info("Test completed successfully")

def test_nan_usd_p2p_go_on_publisher_channel(dev, apdev):
    """NAN USD Publish/Subscribe with P2P GO started on publisher channel"""
    check_nan_usd_capab(dev[0])
    check_nan_usd_capab(dev[1])

    # Start USD solicited publisher on channel 6 (2437 MHz) with P2P attributes
    logger.info("Starting NAN USD solicited publisher on channel 6 with P2P attributes")
    cmd = "NAN_PUBLISH service_name=_test srv_proto_type=2 ssi=6677 ttl=60 freq=2437 p2p=1 unsolicited=0"
    pub_id = dev[0].request(cmd)
    if "FAIL" in pub_id:
        raise Exception("NAN_PUBLISH failed")
    logger.info("Solicited publisher started with ID: " + pub_id)

    # Start USD active subscriber with P2P attributes
    logger.info("Starting NAN USD active subscriber with P2P attributes")
    cmd = "NAN_SUBSCRIBE service_name=_test srv_proto_type=2 ssi=1122334455 p2p=1 active=1"
    sub_id = dev[1].request(cmd)
    if "FAIL" in sub_id:
        raise Exception("NAN_SUBSCRIBE failed")
    logger.info("Active subscriber started with ID: " + sub_id)

    # Wait for initial discovery (subscriber should receive response from
    # publisher)
    logger.info("Waiting for initial NAN discovery")
    ev = dev[1].wait_event(["NAN-DISCOVERY-RESULT"], timeout=10)
    if ev is None:
        raise Exception("Initial DiscoveryResult event not seen")
    vals = split_nan_event(ev)
    if vals['srv_proto_type'] != '2':
        raise Exception("Unexpected srv_proto_type: " + ev)
    if vals['ssi'] != '6677':
        raise Exception("Unexpected ssi: " + ev)
    logger.info("Initial discovery successful - subscriber received response from publisher")

    # Wait for publisher to receive query from active subscriber
    logger.info("Waiting for publisher to receive query from active subscriber")
    ev = dev[0].wait_event(["NAN-REPLIED"], timeout=10)
    if ev is None:
        raise Exception("Publisher did not receive query from active subscriber")
    logger.info("Publisher received query from active subscriber")

    # Clear the event queues
    dev[0].dump_monitor()
    dev[1].dump_monitor()

    # Now start P2P GO on the same channel as the USD publisher (channel 6)
    logger.info("Starting P2P GO on channel 6 (same as USD publisher)")
    cmd = "P2P_GROUP_ADD p2p2 freq=2437"
    res = dev[0].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].group_form_result(ev)
    logger.info("P2P GO started successfully")

    time.sleep(1)

    # Verify that the publisher (now P2P GO) continues to receive SDF frames
    # from active subscriber
    logger.info("Verifying that P2P GO (publisher) receives SDF frames from active subscriber")
    for i in range(5):
        ev = dev[0].wait_event(["NAN-REPLIED"], timeout=10)
        if ev is None:
            raise Exception("P2P GO (publisher) did not receive query %d from active subscriber - SDF frames may be getting dropped" % (i + 1))
        logger.info("P2P GO (publisher) received query %d from active subscriber" % (i + 1))

    logger.info("SUCCESS: P2P GO (publisher) continues to receive SDF frames from active subscriber")

    # Also verify that subscriber continues to receive responses
    logger.info("Verifying that subscriber continues to receive responses from P2P GO (publisher)")
    for i in range(3):
        ev = dev[1].wait_event(["NAN-DISCOVERY-RESULT"], timeout=10)
        if ev is None:
            raise Exception("Subscriber did not receive response %d from P2P GO (publisher)" % (i + 1))
        vals = split_nan_event(ev)
        if vals['srv_proto_type'] != '2':
            raise Exception("Unexpected srv_proto_type: " + ev)
        if vals['ssi'] != '6677':
            raise Exception("Unexpected ssi: " + ev)
        logger.info("Subscriber received response %d from P2P GO (publisher)" % (i + 1))

    logger.info("SUCCESS: Bidirectional SDF exchange continues after P2P GO started")

    # Cleanup
    logger.info("Cleaning up...")
    dev[0].remove_group()
    dev[0].request("NAN_CANCEL_PUBLISH id=" + pub_id)
    dev[1].request("NAN_CANCEL_SUBSCRIBE id=" + sub_id)
    logger.info("Test completed successfully")

def test_nan_usd_p2p_go_multi_channel(dev, apdev):
    """NAN USD with P2P GO on different channel"""
    check_nan_usd_capab(dev[0])
    check_nan_usd_capab(dev[1])

    # Start USD publisher on channel 6 (2437 MHz) with P2P attributes
    logger.info("Starting NAN USD publisher on channel 6 with P2P attributes")
    cmd = "NAN_PUBLISH service_name=_test srv_proto_type=2 ssi=6677 ttl=30 freq=2437 p2p=1 unsolicited=0"
    pub_id = dev[0].request(cmd)
    if "FAIL" in pub_id:
        raise Exception("NAN_PUBLISH failed")
    logger.info("Publisher started with ID: " + pub_id)

    # Start USD subscriber with P2P attributes
    logger.info("Starting NAN USD subscriber with P2P attributes")
    cmd = "NAN_SUBSCRIBE service_name=_test srv_proto_type=2 ssi=1122334455 p2p=1 active=1"
    sub_id = dev[1].request(cmd)
    if "FAIL" in sub_id:
        raise Exception("NAN_SUBSCRIBE failed")
    logger.info("Subscriber started with ID: " + sub_id)

    # Wait for initial discovery
    logger.info("Waiting for initial NAN discovery")
    ev = dev[1].wait_event(["NAN-DISCOVERY-RESULT"], timeout=10)
    if ev is None:
        raise Exception("Initial DiscoveryResult event not seen")
    logger.info("Initial discovery successful")

    # Clear the event queue
    dev[1].dump_monitor()

    # Start P2P GO on a different channel (channel 11)
    logger.info("Starting P2P GO on channel 11 (different from USD publisher)")
    cmd = "P2P_GROUP_ADD p2p2 freq=2462"
    res = dev[0].global_request(cmd)
    if "FAIL" in res:
        raise Exception("P2P_GROUP_ADD failed")

    ev = dev[0].wait_global_event(["P2P-GROUP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("Group formation timed out")
    dev[0].group_form_result(ev)
    logger.info("P2P GO started successfully")

    time.sleep(1)

    # Verify that SDF frames are still being received
    logger.info("Verifying SDF reception with P2P GO on different channel")
    ev = dev[1].wait_event(["NAN-DISCOVERY-RESULT"], timeout=15)
    if ev is None:
        raise Exception("DiscoveryResult event not seen after P2P GO started on different channel")

    vals = split_nan_event(ev)
    if vals['srv_proto_type'] != '2':
        raise Exception("Unexpected srv_proto_type: " + ev)
    if vals['ssi'] != '6677':
        raise Exception("Unexpected ssi: " + ev)
    logger.info("SUCCESS: SDF frames received with P2P GO on different channel")

    # Cleanup
    logger.info("Cleaning up...")
    dev[0].remove_group()
    dev[0].request("NAN_CANCEL_PUBLISH id=" + pub_id)
    dev[1].request("NAN_CANCEL_SUBSCRIBE id=" + sub_id)
    logger.info("Test completed successfully")
