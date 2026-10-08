# Test cases for Wi-Fi Aware (NAN)
# Copyright (c) 2025 Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from wpasupplicant import WpaSupplicant
import logging
logger = logging.getLogger()
from utils import *
import string
import hwsim_utils
from hwsim import HWSimRadio, HWSimController
from contextlib import contextmanager, ExitStack
from test_p2p_channel import set_country
import time

@contextmanager
def hwsim_nan_radios(count=2, n_channels=3):
    """
    Context manager to create NAN-capable HWSimRadios with
    WpaSupplicant instances.
    """
    global_ifaces = ("/tmp/wpas-wlan5", "/tmp/wpas-wlan6", "/tmp/wpas-wlan7")
    if not 1 <= count <= len(global_ifaces):
        raise ValueError(f"count must be in [1, {len(global_ifaces)}]")

    with ExitStack() as stack:
        wpas_list = []
        for global_iface in global_ifaces[:count]:
            _, ifname = stack.enter_context(HWSimRadio(n_channels=n_channels,
                                                       use_nan=True))
            wpas = WpaSupplicant(global_iface=global_iface)
            wpas.interface_add(ifname)
            wpas_list.append(wpas)

        yield wpas_list

def check_nan_capab(dev):
    capa = dev.request("GET_CAPABILITY nan")
    logger.info(f"NAN capabilities: {capa}")

    if "NAN" not in capa:
        raise HwsimSkip(f"NAN not supported: {capa}")

class NanDevice:
    def __init__(self, dev, ifname, ndi_name=None, nmi_addr=None,
                 mgmt_group_cipher=None):
        self.dev = dev
        self.ifname = ifname
        self.wpas = None
        self.ndi_name = ndi_name
        self.nmi_addr = nmi_addr
        self.mgmt_group_cipher = mgmt_group_cipher
        self.cluster_id = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def start(self):
        check_nan_capab(self.dev)

        logger.info(f"NAN device starting on {self.ifname}")
        self.dev.interface_add(self.ifname, if_type="nan", create=True,
                               addr=self.nmi_addr)
        self.wpas = WpaSupplicant(ifname=self.ifname)
        self.set("master_pref", "10")
        self.set("dual_band", "0")
        if self.mgmt_group_cipher is not None:
            self.set("mgmt_group_cipher", self.mgmt_group_cipher)

        if "OK" not in self.wpas.request("NAN_START"):
            raise Exception(f"Failed to start NAN functionality on {self.ifname}")

        ev = self.wpas.wait_event(["NAN-CLUSTER-JOIN"], timeout=5)
        if ev is None:
            raise Exception(f"NAN-CLUSTER-JOIN event not received on {self.ifname}")

        self.cluster_id = split_nan_event(ev)['cluster_id']
        logger.info(f"NAN device started on {self.ifname} cluster_id={self.cluster_id}")

        # Add NDI
        if self.ndi_name is not None:
            self.dev.interface_add(self.ndi_name, if_type="nan_data",
                                   create=True)

    def update_cluster_id(self):
        """Pick up the Cluster ID of a cluster joined after the initial one."""
        ev = self.wpas.wait_event(["NAN-CLUSTER-JOIN"], timeout=0)
        if ev:
            self.cluster_id = split_nan_event(ev)['cluster_id']
        return self.cluster_id

    def stop(self):
        logger.info(f"NAN device stopping on {self.ifname}")

        if "OK" not in self.wpas.request("NAN_STOP"):
            raise Exception(f"Failed to stop NAN functionality on {self.ifname}")

        if self.ndi_name is not None:
            self.dev.interface_remove(self.ndi_name)

        self.dev.global_request(f"INTERFACE_REMOVE {self.ifname}")
        self.wpas.remove_ifname()

        logger.info(f"NAN device stopped on {self.ifname}")

    def publish(self, service_name, ssi=None, unsolicited=1, solicited=1,
                sync=1, match_filter_rx=None, match_filter_tx=None,
                close_proximity=0, pbm=0, nd_pmk=None, cipher_suites=None,
                ttl=None, data_path=False, pairing_setup_info=None,
                randomized_service_id=0, orig_nmi=None, instance_id=None,
                dp_type=None, security_required=0, extended_pbm=0):

        cmd = f"NAN_PUBLISH service_name={service_name} sync={sync} srv_proto_type=2 fsd=0"

        if solicited == 0:
            cmd += " solicited=0"

        if unsolicited == 0:
            cmd += " unsolicited=0"

        if ssi is not None:
            cmd += f" ssi={ssi}"

        if match_filter_rx:
            cmd += f" match_filter_rx={match_filter_rx}"

        if match_filter_tx:
            cmd += f" match_filter_tx={match_filter_tx}"

        if pbm:
            cmd += f" pbm={pbm}"

        if cipher_suites is not None:
            cmd += f" cipher_suites={cipher_suites}"

        if nd_pmk is not None:
            cmd += f" nd_pmk={nd_pmk}"

        if ttl is not None:
            cmd += f" ttl={ttl}"

        if data_path:
            cmd += " data_path=1"

        if pairing_setup_info is not None:
            cmd += f" pairing_setup_info={pairing_setup_info}"

        if randomized_service_id:
            cmd += " randomized_service_id=1"

        if orig_nmi is not None:
            cmd += f" orig_nmi={orig_nmi}"

        if instance_id is not None:
            cmd += f" instance_id={instance_id}"

        if dp_type is not None:
            cmd += f" dp_type={dp_type}"

        if security_required:
            cmd += " security_required=1"

        if extended_pbm:
            cmd += f" extended_pbm={extended_pbm}"

        return self.wpas.request(cmd)

    def schedule_config(self, *chans, map_id=1):
        cmd = f"NAN_SCHED_CONFIG_MAP map_id={map_id} "
        cmd += " ".join([f"{freq}:{bitmap}" for freq, bitmap in chans])
        return self.wpas.request(cmd)

    def remove_schedule(self, map_id=1):
        cmd = f"NAN_SCHED_CONFIG_MAP map_id={map_id}"
        return self.wpas.request(cmd)

    def ndp_request(self, ndi, handle, peer_nmi, peer_id, ssi=None,
                    qos_slots=0, qos_latency=0xffff, csid=None, password=None,
                    pwd_hex=None, pmk=None, interface_id=None, gtk_csid=None):
        cmd = f"NAN_NDP_REQUEST handle={handle} ndi={ndi} peer_nmi={peer_nmi} peer_id={peer_id}"

        params = [
            ("ssi", ssi),
            ("csid", csid),
            ("password", password),
            ("pwd_hex", pwd_hex),
            ("pmk", pmk),
            ("interface_id", interface_id),
            ("gtk_csid", gtk_csid),
        ]

        cmd += "".join(f" {name}={value}" for name, value in params if value is not None)

        if qos_slots > 0 or qos_latency != 0xffff:
            cmd += f" qos={qos_slots}:{qos_latency}"

        return self.wpas.request(cmd)

    def ndp_response(self, action, peer_nmi, ndi=None, peer_ndi=None,
                     ndp_id=None, init_ndi=None, reason_code=None, ssi=None,
                     qos_slots=0, qos_latency=0xffff, handle=None, csid=None,
                     password=None, pwd_hex=None, pmk=None, interface_id=None,
                     gtk_csid=None):
        if action not in ["accept", "reject"]:
            raise Exception(f"Invalid action: {action}. Must be 'accept' or 'reject'")

        cmd = f"NAN_NDP_RESPONSE {action} peer_nmi={peer_nmi}"

        params = [
            ("reason_code", reason_code),
            ("ndi", ndi),
            ("peer_ndi", peer_ndi),
            ("ndp_id", ndp_id),
            ("init_ndi", init_ndi),
            ("handle", handle),
            ("ssi", ssi),
            ("csid", csid),
            ("password", password),
            ("pwd_hex", pwd_hex),
            ("pmk", pmk),
            ("interface_id", interface_id),
            ("gtk_csid", gtk_csid),
        ]

        cmd += "".join(f" {name}={value}" for name, value in params if value is not None)

        if qos_slots > 0 or qos_latency != 0xffff:
            cmd += f" qos={qos_slots}:{qos_latency}"

        return self.wpas.request(cmd)

    def ndp_terminate(self, peer_nmi, init_ndi, ndp_id):
        cmd = f"NAN_NDP_TERMINATE peer_nmi={peer_nmi} init_ndi={init_ndi} ndp_id={ndp_id}"
        return self.wpas.request(cmd)

    def subscribe(self, service_name, ssi=None, active=1,
                  sync=1, match_filter_rx=None, match_filter_tx=None,
                  srf_include=0, srf_mac_list=None, srf_bf_len=0,
                  srf_bf_idx=0, close_proximity=0, pbm=0,
                  pairing_setup_info=None, randomized_service_id=0,
                  dp_required=0, dp_type=None, security_required=0,
                  cipher_suites=None, extended_pbm=0):

        cmd = f"NAN_SUBSCRIBE service_name={service_name} sync={sync} srv_proto_type=2"

        if active == 1:
            cmd += " active=1"

        if ssi is not None:
            cmd += f" ssi={ssi}"

        if match_filter_rx:
            cmd += f" match_filter_rx={match_filter_rx}"

        if match_filter_tx:
            cmd += f" match_filter_tx={match_filter_tx}"

        if srf_include:
            cmd += f" srf_include={srf_include}"

        if srf_mac_list:
            cmd += f" srf_mac_list={srf_mac_list}"

        if srf_bf_len > 0:
            cmd += f" srf_bf_len={srf_bf_len} srf_bf_idx={srf_bf_idx}"

        if close_proximity:
            cmd += " close_proximity=1"

        if pbm:
            cmd += f" pbm={pbm}"

        if pairing_setup_info is not None:
            cmd += f" pairing_setup_info={pairing_setup_info}"

        if randomized_service_id:
            cmd += " randomized_service_id=1"

        if dp_required:
            cmd += " dp_required=1"

        if dp_type is not None:
            cmd += f" dp_type={dp_type}"

        if security_required:
            cmd += " security_required=1"

        if cipher_suites is not None:
            cmd += f" cipher_suites={cipher_suites}"

        if extended_pbm:
            cmd += f" extended_pbm={extended_pbm}"

        return self.wpas.request(cmd)

    def bootstrap(self, peer, handle, peer_instance_id, pbm, auth=False):
        logger.info(f"Bootstrapping NAN with peer {peer} pbm={pbm} auth={auth} on {self.ifname}")
        auth_param = " auth" if auth else ""

        if "OK" not in self.wpas.request(f"NAN_BOOTSTRAP {peer} handle={handle} "
                         f"req_instance_id={peer_instance_id} method={pbm}" + auth_param):
            raise Exception(f"{self.ifname}: failed to bootstrap with {peer}")

    def bootstrap_reset(self, peer):
        logger.info(f"Reset Bootstrapping NAN with peer {peer}")

        if "OK" not in self.wpas.request(f"NAN_BOOTSTRAP_RESET {peer}"):
            raise Exception(f"{self.ifname}: failed to reset bootstrap with {peer}")

    def cancel_publish(self, publish_id):
        logger.info(f"Cancelling publish with ID {publish_id} on {self.ifname}")
        if "OK" not in self.wpas.request(f"NAN_CANCEL_PUBLISH publish_id={publish_id}"):
            raise Exception(f"{self.ifname}: failed to cancel publish id={publish_id}")

    def cancel_subscribe(self, subscribe_id):
        logger.info(f"Cancelling subscribe with ID {subscribe_id} on {self.ifname}")
        if "OK" not in self.wpas.request(f"NAN_CANCEL_SUBSCRIBE subscribe_id={subscribe_id}"):
            raise Exception(f"{self.ifname}: failed to cancel subscribe id={subscribe_id}")

    def set(self, param, value, ok=True):
        logger.info(f"Setting {param} to {value} on {self.ifname}")

        ret = self.wpas.request(f"NAN_SET {param} {value}")

        if ok and "OK" not in ret:
            raise Exception(f"{self.ifname}: failed to set {param}={value}")

        if not ok and "OK" in ret:
            raise Exception(f"{self.ifname}: expected failure for {param}={value}, got OK")

    def update_config(self):
        logger.info(f"Updating NAN configuration on {self.ifname}")
        if "OK" not in self.wpas.request("NAN_UPDATE_CONFIG"):
            raise Exception(f"{self.ifname}: failed to update NAN configuration")

    def transmit(self, handle, req_instance_id, address, ssi=None, cookie=None):
        logger.info(f"Transmitting followup on {self.ifname}")
        cmd = f"NAN_TRANSMIT handle={handle} req_instance_id={req_instance_id} address={address}"
        if ssi is not None:
            cmd += f" ssi={ssi}"

        if cookie is not None:
            cmd += f" cookie={cookie}"

        if "OK" not in self.wpas.request(cmd):
            raise Exception(f"{self.ifname}: failed to transmit NAN followup")

    def pairing_request(self, peer, handle, peer_instance_id, mode, responder=False, password=None):
        if mode == "SAE":
            mode = 1
        elif mode == "PASN":
            mode = 0
        elif mode == "PMK":
            mode = 2

        peer_nmi = peer.wpas.own_addr()
        cmd = f"NAN_PAIR {peer_nmi} auth={mode} cipher=GCMP-256 handle={handle} peer_instance_id={peer_instance_id}"
        if password is not None:
            cmd += f" password={password}"
        if responder:
            cmd += " responder"

        if "OK" not in self.wpas.request(cmd):
            raise Exception("NAN_PAIR Failed on requesting device")

    def pair_abort(self, peer_nmi):
        cmd = f"NAN_PAIR_ABORT {peer_nmi}"
        return self.wpas.request(cmd)

def split_nan_event(ev):
    vals = dict()
    for p in ev.split(' ')[1:]:
        if '=' in p:
            name, val = p.split('=', 1)
            vals[name] = val
    return vals

def _check_discovery_result_field(ev, field, expected):
    """Assert that a key=value pair is present in a NAN-DISCOVERY-RESULT event."""
    data = split_nan_event(ev)
    if field not in data:
        raise Exception(f"Field '{field}' missing in NAN-DISCOVERY-RESULT: {ev}")
    if data[field] != expected:
        raise Exception(f"Field '{field}': expected '{expected}', got '{data[field]}' in: {ev}")

def nan_sync_verify_event(ev, addr, pid, sid, ssi, data_path=None):
    data = split_nan_event(ev)

    if data['srv_proto_type'] != '2':
        raise Exception("Unexpected srv_proto_type: " + ev)

    if data['ssi'] != ssi:
        raise Exception("Unexpected ssi: " + ev)

    if data['subscribe_id'] != sid:
        raise Exception("Unexpected subscribe_id: " + ev)

    if data['publish_id'] != pid:
        raise Exception("Unexpected publish_id: " + ev)

    if data['address'] != addr:
        raise Exception("Unexpected peer_addr: " + ev)

    if data_path is not None and int(data.get('data_path', 0)) != int(data_path):
        raise Exception(f"Unexpected data_path: got {data.get('data_path')}, expected {int(data_path)} in event: " + ev)

def nan_ndp_verify_event(ev, peer_nmi, publish_inst_id=None, init_ndi=None,
                         ssi=None, csid=None):
    """Verify NAN-NDP-REQUEST event format and content"""
    data = split_nan_event(ev)

    if 'peer_nmi' not in data:
        raise Exception(f"Missing peer_nmi in NDP event: {ev}")

    if 'init_ndi' not in data:
        raise Exception(f"Missing init_ndi in NDP event: {ev}")

    if 'ndp_id' not in data:
        raise Exception(f"Missing ndp_id in NDP event: {ev}")

    if publish_inst_id is not None and 'publish_inst_id' not in data:
        raise Exception(f"Missing publish_inst_id in NDP event: {ev}")

    if data['peer_nmi'] != peer_nmi:
        raise Exception(f"Unexpected peer_nmi: got {data['peer_nmi']}, expected {peer_nmi} in event: {ev}")

    if init_ndi is not None and data['init_ndi'] != init_ndi:
        raise Exception(f"Unexpected init_ndi: got {data['init_ndi']}, expected {init_ndi} in event: {ev}")

    if (publish_inst_id is not None and data['publish_inst_id'] != publish_inst_id):
        raise Exception(f"Unexpected publish_inst_id: got {data['publish_inst_id']}, expected {publish_inst_id} in event: {ev}")

    if ssi is not None and 'ssi' in data:
        if data['ssi'] != ssi:
            raise Exception(f"Unexpected ssi: got {data['ssi']}, expected {ssi} in event: {ev}")

    if csid is not None and 'csid' in data:
        if data['csid'] != str(csid):
            raise Exception(f"Unexpected csid: got {data['csid']}, expected {str(csid)} in event: {ev}")

def nan_check_same_cluster(*nan_devs, timeout=1):
    """Verify that the NAN devices converged into a single cluster"""
    start = time.time()
    while True:
        cluster_ids = {nan_dev.update_cluster_id() for nan_dev in nan_devs}
        if len(cluster_ids) == 1:
            logger.info(f"NAN devices are in cluster {cluster_ids.pop()}")
            return

        if time.time() - start >= timeout:
            raise Exception("NAN devices did not join the same cluster: " +
                            str([nan_dev.cluster_id for nan_dev in nan_devs]))

        time.sleep(0.1)

def nan_sync_discovery(pub, sub, service_name, pssi, sssi,
                       unsolicited=1, solicited=1, active=1,
                       expect_discovery=True,
                       timeout=2, cipher_suites=None):
    nan_check_same_cluster(pub, sub)

    paddr = pub.wpas.own_addr()
    saddr = sub.wpas.own_addr()

    pid = pub.publish(service_name, ssi=pssi, unsolicited=unsolicited,
                      solicited=solicited, cipher_suites=cipher_suites)
    sid = sub.subscribe(service_name, ssi=sssi, active=active)

    logger.info(f"Publish ID: {pid}, Subscribe ID: {sid}")

    ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=timeout)
    if expect_discovery:
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")
        nan_sync_verify_event(ev, paddr, pid, sid, pssi)
    else:
        if ev is not None:
            raise Exception("Unexpected NAN-DISCOVERY-RESULT event")

    ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=timeout)
    if active and solicited:
        if ev is None:
            raise Exception("NAN-REPLIED event not seen")
        nan_sync_verify_event(ev, saddr, pid, sid, sssi)
    else:
        if ev is not None:
            raise Exception("Unexpected NAN-REPLIED event")

    return pid, sid, paddr, saddr

def test_nan_sync_active_subscribe(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_sync_discovery(pub, sub, "test_service",
                           pssi="aabbccdd", sssi="ddbbccaa",
                           unsolicited=0)

def test_nan_sync_cluster_id_mismatch(dev, apdev, params):
    """NAN synchronized discovery ignored on Cluster ID mismatch"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_check_same_cluster(pub, sub)

        cluster_id = sub.cluster_id.replace(":", "")[-4:]
        other_cluster_id = f"{int(cluster_id, 16) ^ 0xffff:04x}"

        # Override the subscriber Cluster ID, so that the unsolicited Publish
        # SDFs are still received but carry a non-matching Cluster ID in A3.
        sub.set("test_cluster_id", other_cluster_id)

        pid = pub.publish("test_service", ssi="aabbccdd", solicited=0, ttl=60)
        sid = sub.subscribe("test_service", ssi="ddbbccaa", active=0)
        logger.info(f"Publish ID: {pid}, Subscribe ID: {sid}")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is not None:
            raise Exception("Unexpected NAN-DISCOVERY-RESULT on Cluster ID mismatch: " + ev)

        # Restore the real Cluster ID and verify successful discovery
        sub.set("test_cluster_id", cluster_id)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen after restoring the Cluster ID")
        nan_sync_verify_event(ev, pub.wpas.own_addr(), pid, sid, "aabbccdd")

def test_nan_sync_with_nmi_addresses(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with NMI addresses"""
    pnmi_addr = "40:00:00:00:17:00"
    snmi_addr = "40:00:00:00:18:00"

    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
            NanDevice(wpas1, "nan0", nmi_addr=pnmi_addr) as pub, \
            NanDevice(wpas2, "nan1", nmi_addr=snmi_addr) as sub:

        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        if paddr != pnmi_addr:
            raise Exception(f"Publisher NMI address mismatch: got {paddr}, expected {pnmi_addr}")

        if saddr != snmi_addr:
            raise Exception(f"Subscriber NMI address mismatch: got {saddr}, expected {snmi_addr}")

        nan_sync_discovery(pub, sub, "test_service",
                           pssi="aabbccdd", sssi="ddbbccaa",
                           unsolicited=0)

def test_nan_sync_followup(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, _ = nan_sync_discovery(pub, sub, "test_service",
                                                pssi="aabbccdd",
                                                sssi="ddbbccaa",
                                                unsolicited=0, timeout=2)
        sub.transmit(handle=sid, req_instance_id=pid, address=paddr,
                     ssi="11223344")
        ev = pub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
        if ev is None or f"id={pid}" not in ev or f"peer_instance_id={sid}" not in ev or "ssi=11223344" not in ev:
            raise Exception("NAN-RECEIVE followup event not seen or invalid format")

def test_nan_sync_followup_tracking(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with followup tracking"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, _ = nan_sync_discovery(pub, sub, "test_service",
                                                pssi="aabbccdd",
                                                sssi="ddbbccaa",
                                                unsolicited=0, timeout=2)

        # Check followup to the publisher. Acknowledgment is expected.
        cookie = 127
        sub.transmit(handle=sid, req_instance_id=pid, address=paddr,
                     ssi="11223344", cookie=cookie)
        ev = pub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
        if ev is None or f"id={pid}" not in ev or f"peer_instance_id={sid}" not in ev or "ssi=11223344" not in ev:
            raise Exception("NAN-RECEIVE followup event not seen or invalid format")

        ev = sub.wpas.wait_event(["NAN-TRANSMIT-STATUS"], timeout=2)
        if ev is None or f"cookie={cookie}" not in ev or "acked=1" not in ev:
            raise Exception("NAN-TX-STATUS event not seen or invalid data")

        # Check followup to an invalid address. Acknowledgment is not expected.
        cookie = 243
        suffix = int(paddr[-2:], 16) ^ 0xFF
        addr = paddr[:-2] + f"{suffix:02x}"

        sub.transmit(handle=sid, req_instance_id=pid, address=addr,
                     cookie=cookie)
        ev = sub.wpas.wait_event(["NAN-TRANSMIT-STATUS"], timeout=2)
        if ev is None or f"cookie={cookie}" not in ev or "acked=0" not in ev:
            raise Exception("NAN-TX-STATUS event not seen or invalid data")

def test_nan_sync_active_subscribe_two_publishers(dev, apdev, params):
    """NAN synchronized active subscribe and 2 publishers"""
    with hwsim_nan_radios(count=3) as [wpas1, wpas2, wpas3], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub, \
        NanDevice(wpas3, "nan2") as ext:
        eaddr = ext.wpas.own_addr()

        essi = "ddbbccaa1212121212121212"

        # Start with the first publisher which is solicited only
        pid, sid, _, _ = nan_sync_discovery(pub, sub, "test_service",
                                            pssi="aabbccdd", sssi="ddbbccaa",
                                            unsolicited=0)

        pub.cancel_publish(pid)

        # And second publisher which is unsolicited only
        sub.wpas.dump_monitor()
        eid = ext.publish("test_service", ssi=essi, solicited=0)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")

        nan_sync_verify_event(ev, eaddr, eid, sid, essi)

        ev = ext.wpas.wait_event(["NAN-REPLIED"], timeout=1)
        if ev is not None:
            raise Exception("NAN-REPLIED event not expected for unsolicited publish")

def test_nan_sync_passive_subscribe(dev, apdev, params):
    """NAN synchronized passive Subscribe and unsolicited publish"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_sync_discovery(pub, sub, "test_service",
                           pssi="aabbccdd001122334455667788",
                           sssi="ddbbccaa001122334455667788",
                           active=0)

def test_nan_sync_active_subscribe_no_match(dev, apdev, params):
    """NAN synchronized active subscribe and with 2 Publishes: no match"""
    with hwsim_nan_radios(count=3) as [wpas1, wpas2, wpas3], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub, \
        NanDevice(wpas3, "nan2") as ext:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()
        eaddr = ext.wpas.own_addr()

        pssi = "aabbccdd"
        sssi = "ddbbccaa"
        essi = "ddbbccaa1212121212121212"

        pid = pub.publish("test_dummy", ssi=pssi, unsolicited=0)
        eid = ext.publish("test_dummy", ssi=essi, solicited=0)
        sid = sub.subscribe("test_service", ssi=sssi)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is not None:
            raise Exception("Got unexpected NAN-DISCOVERY-RESULT event")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is not None:
            raise Exception("Unexpected NAN-REPLIED event on solicited publish")

        ev = ext.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is not None:
            raise Exception("Unexpected NAN-REPLIED event on unsolicited publish")

def _nan_sync_publisher_match_filter(sub_tx_filter=None, pub_rx_filter=None,
                                     match=True):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_check_same_cluster(pub, sub)

        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid = pub.publish("test_pub_match_filter", ssi=pssi, unsolicited=0,
                          match_filter_rx=pub_rx_filter)
        sid = sub.subscribe("test_pub_match_filter", ssi=sssi,
                            match_filter_tx=sub_tx_filter)

        sub_ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        pub_ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        if match:
            if sub_ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            nan_sync_verify_event(sub_ev, paddr, pid, sid, pssi)

            if pub_ev is None:
                raise Exception("NAN-REPLIED event not seen")
            nan_sync_verify_event(pub_ev, saddr, pid, sid, sssi)
        else:
            if sub_ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT event")
            if pub_ev is not None:
                raise Exception("Unexpected NAN-REPLIED event")

def test_nan_sync_publisher_match_filter_1(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter()

def test_nan_sync_publisher_match_filter_2(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0000000000")

def test_nan_sync_publisher_match_filter_3(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(sub_tx_filter="0000000000")

def test_nan_sync_publisher_match_filter_4(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_5(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(sub_tx_filter="01010102010301040105", match=False)

def test_nan_sync_publisher_match_filter_6(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0000000000",
                                     sub_tx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_7(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="0000000000")

def test_nan_sync_publisher_match_filter_8(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_9(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010101040105",
                                     sub_tx_filter="01010102010301040105",
                                     match=False)

def test_nan_sync_publisher_match_filter_10(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="0101000103000105")

def test_nan_sync_publisher_match_filter_11(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0001020103000105",
                                     sub_tx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_12(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="000102000104")

def test_nan_sync_publisher_match_filter_13(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="010100010300",
                                     sub_tx_filter="01010102010301040105",
                                     match=False)

def test_nan_sync_publisher_match_filter_14(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="051122334455",
                                     sub_tx_filter="051122334455")

def test_nan_sync_publisher_match_filter_15(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0411223344",
                                     sub_tx_filter="051122334455", match=False)

def test_nan_sync_publisher_match_filter_16(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="051122334455",
                                     sub_tx_filter="03112233", match=False)

def _nan_sync_subscriber_match_filter(pub_tx_filter=None, sub_rx_filter=None,
                                      match=True):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_check_same_cluster(pub, sub)

        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid = pub.publish("test_sub_match_filter", ssi=pssi, solicited=0,
                          match_filter_tx=pub_tx_filter)
        sid = sub.subscribe("test_sub_match_filter", active=0, ssi=sssi,
                            match_filter_rx=sub_rx_filter)

        sub_ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        if match:
            if sub_ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            nan_sync_verify_event(sub_ev, paddr, pid, sid, pssi)
        else:
            if sub_ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT event")

def test_nan_sync_subscriber_match_filter_1(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter()

def test_nan_sync_subscriber_match_filter_2(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(sub_rx_filter="0000000000")

def test_nan_sync_subscriber_match_filter_3(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0000000000")

def test_nan_sync_subscriber_match_filter_4(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(sub_rx_filter="01010102010301040105", match=False)

def test_nan_sync_subscriber_match_filter_5(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_6(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0000000000",
                                      sub_rx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_7(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="0000000000")

def test_nan_sync_subscriber_match_filter_8(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_9(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="01010102010101040105", match=False)

def test_nan_sync_subscriber_match_filter_10(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0101000103000105",
                                      sub_rx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_11(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="0001020103000105")

def test_nan_sync_subscriber_match_filter_12(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0001020104",
                                      sub_rx_filter="01010102010301040105",
                                      match=False)

def test_nan_sync_subscriber_match_filter_13(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="010100010300")

def test_nan_sync_subscriber_match_filter_14(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="051122334455",
                                      sub_rx_filter="051122334455")

def test_nan_sync_subscriber_match_filter_15(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="021122",
                                      sub_rx_filter="051122334455", match=False)

def test_nan_sync_subscriber_match_filter_16(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="051122334455",
                                      sub_rx_filter="03112233", match=False)

def _nan_sync_srf(wpas, pub, srf_mac_list=None, srf_include=1,
                  srf_bf_len=0, srf_bf_idx=0, match=True):
    with NanDevice(wpas, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid = pub.publish("test_srf", ssi=pssi, unsolicited=0)
        sid = sub.subscribe("test_srf", ssi=sssi, srf_include=srf_include,
                            srf_mac_list=srf_mac_list)

        sub_ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        pub_ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        if match:
            if sub_ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            nan_sync_verify_event(sub_ev, paddr, pid, sid, pssi)

            if pub_ev is None:
                raise Exception("NAN-REPLIED event not seen")
            nan_sync_verify_event(pub_ev, saddr, pid, sid, sssi)
        else:
            if sub_ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT event")
            if pub_ev is not None:
                raise Exception("Unexpected NAN-REPLIED event")

def test_nan_sync_srf_mac_addr_1(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        _nan_sync_srf(wpas2, pub)

def test_nan_sync_srf_mac_addr_2(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = paddr.replace(':', '')

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=1, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_3(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = paddr.replace(':', '')

        _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf, match=False)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf,
                          srf_bf_len=1, srf_bf_idx=i, match=False)

def test_nan_sync_srf_mac_addr_4(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = "030303030303" + paddr.replace(':', '')

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)

        # test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=2, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_5(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = "030303030303" + paddr.replace(':', '') + "040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)

        # test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=5, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_6(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = paddr.replace(':', '') + "040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=3, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_7(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        srf = "030303030303040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf, match=False)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=3, srf_bf_idx=i, match=False)

def test_nan_sync_srf_mac_addr_8(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        srf = "030303030303040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf,
                          srf_bf_len=3, srf_bf_idx=i)

def _nan_sync_multi_services(params, n_services=10):
    services = []
    for i in range(n_services):
        service_name = f"srv_test_{i}"
        sssi = (i + 1) * "00"
        pssi = (i + 1) * "11"
        services.append({"service_name": service_name, "sssi": sssi,
                         "pssi": pssi})

    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pids = []
        sids = []
        for entry in params:
            service = services[entry["service_id"]]
            if "pub" in entry:
                unsolicited = entry["pub"].get("unsolicited", 1)
                solicited = entry["pub"].get("solicited", 1)
                pub_tx_filter = entry["pub"].get("pub_tx_filter", None)
                pub_rx_filter = entry["pub"].get("pub_rx_filter", None)
                pid = pub.publish(service["service_name"],
                                  ssi=service["pssi"],
                                  unsolicited=unsolicited,
                                  match_filter_rx=pub_rx_filter,
                                  match_filter_tx=pub_tx_filter)

                if entry["pub"].get("replied", False):
                    pids.append({"pid": pid, "replied": False})

            if "sub" in entry:
                active = entry["sub"].get("active", 1)
                sub_tx_filter = entry["sub"].get("sub_tx_filter", None)
                sub_rx_filter = entry["sub"].get("sub_rx_filter", None)
                sid = sub.subscribe(service["service_name"],
                                    ssi=service["sssi"],
                                    active=active,
                                    match_filter_rx=sub_rx_filter,
                                    match_filter_tx=sub_tx_filter)

                if entry["sub"].get("discovered", False):
                    sids.append({"sid": sid, "discovered": False})

        # Now wait for the events. Limit the loop to avoid infinite waiting
        max_loops = 2 * (len(sids) + len(pids))
        loop_count = 0
        while (any(not sid["discovered"] for sid in sids) or
               any(not pid["replied"] for pid in pids)) and loop_count < max_loops:
            loop_count += 1

            if any(not sid["discovered"] for sid in sids):
                ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
                if ev:
                    data = split_nan_event(ev)
                    for sid in sids:
                        if sid["sid"] == data["subscribe_id"]:
                            sid["discovered"] = True
                            break
            if any(not pid["replied"] for pid in pids):
                ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)
                if ev:
                    data = split_nan_event(ev)
                    for pid in pids:
                        if pid["pid"] == data["publish_id"]:
                            pid["replied"] = True
                            break

        if any(not sid["discovered"] for sid in sids):
            raise Exception("Not all services where discovered")

        if any(not pid["replied"] for pid in pids):
            raise Exception("Not all services where replied to")

def test_nan_sync_multi_services_1(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: active subscribe"""
    test_params = []
    for i in range(10):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 0, "replied": True},
            "sub": { "active": 1, "discovered": True},
        })

    _nan_sync_multi_services(test_params)

def test_nan_sync_multi_services_2(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: passive subscribe"""
    test_params = []
    for i in range(10):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 1, "replied": False},
            "sub": { "active": 0, "discovered": True},
        })

    _nan_sync_multi_services(test_params)

def test_nan_sync_multi_services_3(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: active subscribe (subset)"""
    test_params = []
    for i in range(0, 10, 2):
        test_params.append({
            "service_id": i,
            "sub": { "active": 1, "discovered": False},
        })

    for i in range(1, 10, 2):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 0, "replied": True,
                     "pub_rx_filter": "01010102010301040105"},
            "sub": { "active": 1, "discovered": True,
                     "sub_tx_filter": "01010102010301040105"},
        })

    _nan_sync_multi_services(test_params)

def test_nan_sync_multi_services_4(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: passive subscribe (subset)"""
    test_params = []
    for i in range(0, 10, 2):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 1, "replied": False,
                     "pub_tx_filter": "01010102010301040105"},
            "sub": { "active": 0, "discovered": True,
                     "sub_rx_filter": "01010102010301040105"},
        })

    for i in range(1, 10, 2):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 1, "replied": False},
        })

    _nan_sync_multi_services(test_params)

def test_nan_merged_sdf_multiple_services(dev, apdev, params):
    """NAN: Multiple active services merged into a single SDF per DW"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        n_services = 5
        pids = []
        sids = []

        for i in range(n_services):
            sname = f"test_merged_{i}"
            pid = pub.publish(sname, ssi=f"aabb{i:02x}{i:02x}", unsolicited=0)
            sid = sub.subscribe(sname, ssi=f"ddcc{i:02x}{i:02x}")
            pids.append(pid)
            sids.append(sid)

        discovered = set()
        replied = set()

        for _ in range(n_services * 3):
            ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
            if ev:
                data = split_nan_event(ev)
                discovered.add(data.get("subscribe_id"))
            ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)
            if ev:
                data = split_nan_event(ev)
                replied.add(data.get("publish_id"))
            if len(discovered) >= n_services and len(replied) >= n_services:
                break

        if len(discovered) < n_services:
            raise Exception(f"Only {len(discovered)}/{n_services} services discovered (merged SDF test)")
        if len(replied) < n_services:
            raise Exception(f"Only {len(replied)}/{n_services} services replied (merged SDF test)")

def _nan_service_id_randomization(pub_randomized=False, sub_randomized=False,
                                   pub_nik=None, sub_nik=None,
                                   group_nik=None, assoc_self_nik=None,
                                   expect_discovery=True):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()

        if pub_nik:
            pub.set("self_nik", f"{pub_nik} 1")
        if sub_nik:
            sub.set("self_nik", f"{sub_nik} 1")
        if pub_nik and pub_randomized:
            sub.set("peer_nik", f"{pub_nik} 1")
        if sub_nik and sub_randomized:
            pub.set("peer_nik", f"{sub_nik} 1")
        if group_nik and assoc_self_nik:
            pub.set("self_nik", f"{assoc_self_nik} 1")
            pub.set("group_nik", f"{group_nik} associated_nik {assoc_self_nik} 1")
            sub.set("group_nik", f"{group_nik} associated_nik {assoc_self_nik} 1")

        pssi = "aabbccdd"
        sssi = "ddbbccaa"

        pid = pub.publish("test_rand_svc", ssi=pssi, unsolicited=0,
                          randomized_service_id=1 if pub_randomized else 0)
        sid = sub.subscribe("test_rand_svc", ssi=sssi,
                            randomized_service_id=1 if sub_randomized else 0)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if expect_discovery:
            if ev is None:
                raise Exception("NAN-DISCOVERY-RESULT not seen with randomized service ID")
            data = split_nan_event(ev)
            if data.get("address") != paddr:
                raise Exception(f"Unexpected peer address in discovery result: {ev}")
            ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
            if ev is None:
                raise Exception("NAN-REPLIED not seen on publisher")
        else:
            if ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT without NIK for randomized service ID")

def test_nan_service_id_randomization_publish(dev, apdev, params):
    """NAN: Service ID randomization on publish side"""
    pub_nik = "0102030405060708090a0b0c0d0e0f10"
    _nan_service_id_randomization(pub_randomized=True, pub_nik=pub_nik,
                                  sub_nik=None)

def test_nan_service_id_randomization_subscribe(dev, apdev, params):
    """NAN: Service ID randomization on subscribe side"""
    sub_nik = "1112131415161718191a1b1c1d1e1f20"
    _nan_service_id_randomization(pub_randomized=False, sub_randomized=True,
                                  sub_nik=sub_nik)

def test_nan_service_id_randomization_no_nik(dev, apdev, params):
    """NAN: Service ID randomization without NIK - no discovery expected"""
    _nan_service_id_randomization(pub_randomized=True, expect_discovery=False)

def test_nan_service_id_randomization_group_nik(dev, apdev, params):
    """NAN: Service ID randomization using group NIK"""
    group_nik = "deadbeefcafe0102030405060708090a"
    assoc_self_nik = "0102030405060708090a0b0c0d0e0f10"
    _nan_service_id_randomization(pub_randomized=True,
                                  group_nik=group_nik,
                                  assoc_self_nik=assoc_self_nik)

def test_nan_service_id_randomization_irsa_unicast(dev, apdev, params):
    """NAN: IRSA unicast response uses matched NIK context"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()

        pub_nik = "aabbccddeeff00112233445566778899"
        pub.set("self_nik", f"{pub_nik} 1")

        sub_self_nik = "99887766554433221100ffeeddccbbaa"
        sub.set("self_nik", f"{sub_self_nik} 1")
        sub.set("peer_nik", f"{pub_nik} associated_nik {sub_self_nik} 1")
        pub.set("peer_nik", f"{sub_self_nik} 1")

        pid = pub.publish("test_irsa_uni", ssi="aabbccdd", unsolicited=0,
                          randomized_service_id=1)
        sid = sub.subscribe("test_irsa_uni", ssi="ddbbccaa")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (IRSA unicast response)")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED not seen (IRSA unicast response)")

def test_nan_config(dev, apdev, params):
    """NAN configuration testing"""
    with hwsim_nan_radios(count=1) as [wpas1], \
        NanDevice(wpas1, "nan0") as nan:
        # Start with some invalid values
        nan.set("master_pre", "20", ok=False)
        nan.set("cluser_id", "12", ok=False)
        nan.set("scan_peod", "30", ok=False)
        nan.set("can_dwell_time", "150", ok=False)
        nan.set("discovery_beaconl", "1", ok=False)
        nan.set("low_band_cfg", "-70,-85,", ok=False)
        nan.set("high_band_cfg", "75,,2", ok=False)

        # And then set the valid values
        nan.set("master_pref", "20")
        nan.set("cluster_id", "50:6f:9a:01:01:01")
        nan.set("scan_period", "30")
        nan.set("scan_dwell_time", "150")
        nan.set("discovery_beacon_interval", "100")

        nan.set("low_band_cfg", "-59,-65,1,0")
        nan.set("high_band_cfg", "-59,-65,2,0")

        # and finally update the configuration
        logger.info("Updating NAN configuration")
        nan.update_config()

        nan.set("master_pref", "255")
        nan.update_config()

def test_nan_nik_config(dev, apdev, params):
    """NAN NIK list management configuration"""
    with hwsim_nan_radios(count=1) as [wpas1], \
        NanDevice(wpas1, "nan0") as nan:
        nik1 = "0102030405060708090a0b0c0d0e0f10"
        nan.set("self_nik", f"{nik1} 1")

        nik2 = "1112131415161718191a1b1c1d1e1f20"
        nan.set("self_nik", f"{nik2} 0")

        nik3 = "2122232425262728292a2b2c2d2e2f30"
        nik4 = "3132333435363738393a3b3c3d3e3f40"
        nan.set("self_nik", f"{nik3},{nik4} 1")

        peer_nik = "aabbccddeeff00112233445566778899"
        nan.set("peer_nik", f"{peer_nik} 1")

        assoc_nik = "0102030405060708090a0b0c0d0e0f10"
        nan.set("peer_nik", f"{peer_nik} associated_nik {assoc_nik} 1")

        group_nik = "deadbeefcafe0102030405060708090a"
        nan.set("group_nik", f"{group_nik} associated_nik {assoc_nik} 1")

        nan.set("self_nik", "0102030405060708090a0b0c0d0e0f", ok=False)
        nan.set("self_nik", "0102030405060708090a0b0c0d0e0fgg", ok=False)

        valid_nik = "0102030405060708090a0b0c0d0e0f10"
        nan.set("peer_nik",
                f"{valid_nik} associated_nik 0102030405060708090a0b0c0d0e0f",
                ok=False)

def test_nan_sched(dev, apdev, params):
    """NAN configure schedule"""
    set_country("US")
    try:
        with hwsim_nan_radios() as (wpas1, wpas2), \
             NanDevice(wpas1, "nan0") as pub:
            if "OK" not in pub.schedule_config((2437, "03000000"),
                                               (5180, "0000ff00"),
                                               (5825, "000000ff")):
                raise Exception("Failed to configure schedule")
            # Remove
            if "OK" not in pub.remove_schedule():
                raise Exception("Failed to remove schedule")
            # Overlapping maps
            if "FAIL" not in pub.schedule_config((2437, "03000000"),
                                                 (5180, "0000ff00"),
                                                 (5825, "050000ff")):
                raise Exception("A schedule with overlapping time bitmaps was unexpectedly accepted")
            # Same channel
            if "FAIL" not in pub.schedule_config((2437, "03000000"),
                                                 (2437, "0000ff00")):
                raise Exception("A schedule with duplicate channel entries was unexpectedly accepted")
            # Bad length
            if "FAIL" not in pub.schedule_config((2437, "0300")):
                raise Exception("Too short schedule bitmap accepted")
    finally:
        set_country("00")

def _nan_discover_service(pub, sub, service_name, pssi, sssi, ttl=None,
                          csid=None, gtk_csid=None, data_path=False):
    nan_check_same_cluster(pub, sub)

    paddr = pub.wpas.own_addr()
    saddr = sub.wpas.own_addr()

    cipher_suites = None
    if csid is not None:
        cipher_suites = f"{csid}"
        if gtk_csid is not None:
            cipher_suites += f",{gtk_csid}"

    pid = pub.publish(service_name, ssi=pssi, ttl=ttl,
                      cipher_suites=cipher_suites,
                      data_path=data_path)
    sid = sub.subscribe(service_name, ssi=sssi, active=0)

    logger.info(f"Publish ID: {pid}, Subscribe ID: {sid}")

    ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
    if ev is None:
        raise Exception(f"NAN-DISCOVERY-RESULT event not seen for {service_name}")

    nan_sync_verify_event(ev, paddr, pid, sid, pssi, data_path=data_path)

    return pid, sid, paddr, saddr

def _nan_ndp_request_and_accept(pub, sub, pid, sid, paddr, saddr, req_ssi,
                                resp_ssi, csid=None,
                                password=None, pwd_hex=None, pmk=None,
                                counter=False, force_conditional=False,
                                wrong_pwd=False, configure_schedule=True,
                                pub_interface_id=None, sub_interface_id=None,
                                gtk_csid=None):
    """
    Request NDP from subscriber and accept on publisher.

    Returns: (ndp_id, init_ndi) or None if wrong_pwd test completed
    """
    # Configure schedule on subscriber if needed
    if configure_schedule:
        if "OK" not in sub.schedule_config((2437, "0e000000"),
                                           (5180, "f0ffffff")):
            raise Exception("Failed to configure schedule (sub)")

    # NDP request
    if "OK" not in sub.ndp_request(sub.ndi_name, sid, paddr, pid, req_ssi,
                                   csid=csid, password=password,
                                   pwd_hex=pwd_hex, pmk=pmk,
                                   interface_id=sub_interface_id,
                                   gtk_csid=gtk_csid):
        raise Exception("NDP request failed")

    ev = pub.wpas.wait_event(["NAN-NDP-REQUEST"], timeout=5)
    if ev is None:
        raise Exception("NAN-NDP-REQUEST event not seen")

    ndi_sub = sub.dev.get_iface_addr(sub.ndi_name)
    nan_ndp_verify_event(ev, saddr, pid, ndi_sub, req_ssi)

    data = split_nan_event(ev)
    ndp_id = data['ndp_id']
    init_ndi = data['init_ndi']

    # Configure schedule on publisher
    if force_conditional:
        pub.set("force_conditional_sched", "1")
        sub.set("force_conditional_sched", "1")

    if configure_schedule:
        if counter:
            if "OK" not in pub.schedule_config((5745, "feffffff")):
                raise Exception("Failed to configure schedule (pub)")
        else:
            if "OK" not in pub.schedule_config((2437, "0e000000"),
                                               (5180, "f0ffffff")):
                raise Exception("Failed to configure schedule (pub)")

    # Accept NDP request
    accept_pwd = "WRONG_PWD" if wrong_pwd else password
    accept_pwd_hex = None if password or wrong_pwd else pwd_hex
    if "OK" not in pub.ndp_response("accept", saddr, ndi=pub.ndi_name,
                                    ndp_id=ndp_id, init_ndi=init_ndi,
                                    handle=pid, ssi=resp_ssi, csid=csid,
                                    password=accept_pwd,
                                    pwd_hex=accept_pwd_hex, pmk=pmk,
                                    interface_id=pub_interface_id,
                                    gtk_csid=gtk_csid):
        raise Exception("NDP response (accept) failed")

    # Verify disconnection on wrong password
    if wrong_pwd:
        ev = sub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
        if ev is None or "reason=3" not in ev or "failure=1" not in ev:
            raise Exception("NAN-NDP-DISCONNECTED(failure) event not seen on subscriber")
        ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
        if ev is None or "reason=3" not in ev or "failure=1" not in ev:
            raise Exception("NAN-NDP-DISCONNECTED(failure) event not seen on publisher")
        return None

    # Handle counter proposal
    if counter:
        ev = sub.wpas.wait_event(["NAN-NDP-COUNTER-REQUEST"], timeout=5)
        if ev is None:
            raise Exception("NAN-NDP-COUNTER-REQUEST event not seen")

        nan_ndp_verify_event(ev, paddr, init_ndi=ndi_sub, ssi=resp_ssi)

        data = split_nan_event(ev)
        ndp_id = data['ndp_id']
        init_ndi = data['init_ndi']

        if "OK" not in sub.schedule_config((5745, "feffffff")):
            raise Exception("Failed to configure schedule (sub)")

        if "OK" not in sub.ndp_response("accept", paddr, ndi=sub.ndi_name,
                                        ndp_id=ndp_id, handle=sid,
                                        init_ndi=init_ndi, ssi="11223344",
                                        csid=csid, password=password,
                                        pwd_hex=pwd_hex, pmk=pmk):
            raise Exception("NDP response (confirm) failed")

    # Wait for NDP connected events
    ev = pub.wpas.wait_event(["NAN-NDP-CONNECTED"], timeout=5)
    if ev is None:
        raise Exception("NAN-NDP-CONNECTED event not seen on publisher")

    data_pub = split_nan_event(ev)

    ev = sub.wpas.wait_event(["NAN-NDP-CONNECTED"], timeout=5)
    if ev is None:
        raise Exception("NAN-NDP-CONNECTED event not seen on subscriber")

    logger.info("NDP connection established successfully")

    data_sub = split_nan_event(ev)

    if (sub_interface_id):
        interface_id = data_pub.get("interface_id")
        if interface_id != sub_interface_id:
            raise Exception("No or invalid subscriber interface ID")

    if (pub_interface_id):
        interface_id = data_sub.get("interface_id")
        if interface_id != pub_interface_id:
            raise Exception("No or invalid publisher interface ID")

    return ndp_id, init_ndi

def _nan_ndp_terminate(pub, sub, paddr, init_ndi, ndp_id):
    """Terminate an NDP and wait for disconnect events on both sides."""

    sub.ndp_terminate(paddr, init_ndi, ndp_id)

    ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception(f"NAN-NDP-DISCONNECTED event not seen on publisher")

    ev = sub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
    if ev is None:
        raise Exception(f"NAN-NDP-DISCONNECTED event not seen on subscriber")

def _nan_test_connectivity(pub, sub):
    """Test IP connectivity between publisher and subscriber NDI interfaces."""
    wpas_ndi_pub = WpaSupplicant(ifname=pub.ndi_name)
    wpas_ndi_sub = WpaSupplicant(ifname=sub.ndi_name)
    hwsim_utils.test_connectivity(wpas_ndi_pub, wpas_ndi_sub, tos=0,
                                  ifname1=pub.ndi_name, ifname2=sub.ndi_name,
                                  max_tries=3, timeout=5, broadcast=True)

def _run_nan_dp(counter=False, csid=None, wrong_pwd=False, use_pmk=False,
                use_pwd_hex=False,
                use_interface_id=False, verify_max_idle_period=False,
                gtk_csid=None, mgmt_group_cipher=None,
                force_conditional=False):
    if use_pmk:
        pmk = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        pwd = None
        pwd_hex = None
    else:
        pwd = "NAN" if csid is not None else None
        pwd_hex = pwd.encode().hex() if use_pwd_hex and pwd is not None else None
        if use_pwd_hex:
            pwd = None
        pmk = None

    pub_interface_id, sub_interface_id = (
            ("0011223344556677", "8899aabbccddeeff") if use_interface_id else (None, None)
    )

    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0", "ndi0", mgmt_group_cipher=mgmt_group_cipher) as pub, \
        NanDevice(wpas2, "nan1", "ndi1", mgmt_group_cipher=mgmt_group_cipher) as sub:

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid, sid, paddr, saddr= _nan_discover_service(pub, sub, "test_service",
                                                      pssi, sssi,
                                                      csid=csid,
                                                      gtk_csid=gtk_csid,
                                                      data_path=True)

        # Log peer info (specific to this test)
        peer_schedule = pub.wpas.request("NAN_PEER_INFO " + saddr + " schedule")
        logger.info("\n" + peer_schedule)
        potential = pub.wpas.request("NAN_PEER_INFO " + saddr + " potential")
        logger.info("\n" + potential)
        capa = pub.wpas.request("NAN_PEER_INFO " + saddr + " capa")
        logger.info("\n" + capa)

        if verify_max_idle_period:
            pub.set("max_ndl_idle_period", "10")
            sub.set("max_ndl_idle_period", "10")

        result = _nan_ndp_request_and_accept(pub, sub, pid, sid, paddr, saddr,
                                             req_ssi="aabbcc",
                                             resp_ssi="ddeeff", csid=csid,
                                             password=pwd, pwd_hex=pwd_hex,
                                             pmk=pmk, counter=counter,
                                             force_conditional=force_conditional,
                                             wrong_pwd=wrong_pwd,
                                             pub_interface_id=pub_interface_id,
                                             sub_interface_id=sub_interface_id,
                                             gtk_csid=gtk_csid)
        if result is None:
            # wrong_pwd test completed
            return

        ndp_id, init_ndi = result

        _nan_test_connectivity(pub, sub)

        if not verify_max_idle_period:
            _nan_ndp_terminate(pub, sub, paddr, init_ndi, ndp_id)
            return

        sub_sched = pub.wpas.request("NAN_PEER_INFO " + saddr + " schedule")
        m = re.search(r'\bmax_idle_period\s*=\s*(\d+)', sub_sched)
        if not m:
            raise Exception("max_idle_period not found in peer schedule")

        if int(m.group(1)) != 10:
            raise Exception(f"Unexpected max_idle_period value in peer schedule: {m.group(1)}")

        pub_sched = sub.wpas.request("NAN_PEER_INFO " + paddr + " schedule")
        m = re.search(r'\bmax_idle_period\s*=\s*(\d+)', pub_sched)
        if not m:
            raise Exception("max_idle_period not found in peer schedule")

        if int(m.group(1)) != 10:
            raise Exception(f"Unexpected max_idle_period value in peer schedule: {m.group(1)}")

        # Verify that the NDP is terminated due to max idle period (no traffic).
        # While the max idle period is set to 10 seconds, wait longer as there
        # is traffic generated internally by the kernel, e.g., IPv6 router
        # solicitation messages.
        ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=30)
        if ev is None or "locally_generated=1" not in ev or "reason=1" not in ev:
            raise Exception(f"NAN-NDP-DISCONNECTED event not seen on publisher or invalid data")

        ev = sub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=30)
        if ev is None or "locally_generated=1" not in ev or "reason=1" not in ev:
            raise Exception(f"NAN-NDP-DISCONNECTED event not seen on subscriber or invalid data")

def run_nan_dp(country="US", counter=False, csid=None, wrong_pwd=False,
               use_pmk=False, use_pwd_hex=False, use_interface_id=False,
               verify_max_idle_period=False, gtk_csid=None,
               mgmt_group_cipher=None, force_conditional=False):
    set_country(country)
    try:
        _run_nan_dp(counter=counter, csid=csid, wrong_pwd=wrong_pwd,
                    use_pmk=use_pmk, use_pwd_hex=use_pwd_hex,
                    use_interface_id=use_interface_id,
                    verify_max_idle_period=verify_max_idle_period,
                    gtk_csid=gtk_csid,
                    mgmt_group_cipher=mgmt_group_cipher,
                    force_conditional=force_conditional)
    finally:
        set_country("00")

def test_nan_dp_open(dev, apdev, params):
    """NAN DP open"""
    run_nan_dp(use_interface_id=True)

def test_nan_dp_open_2_ndps(dev, apdev, params):
    """NAN DP open - 2 NDPs with same peer"""
    set_country("US")
    try:
        _run_nan_dp_2_ndps(secure_ndp2=False)
    finally:
        set_country("00")

def test_nan_dp_open_2_ndps_security_upgrade(dev, apdev, params):
    """NAN DP - 2 NDPs with same peer, second with security upgrade"""
    set_country("US")
    try:
        _run_nan_dp_2_ndps(secure_ndp2=True)
    finally:
        set_country("00")

def _run_nan_dp_2_ndps(secure_ndp2=False):
    """
    Test 2 NDPs with the same peer.

    @secure_ndp2: If True, NDP2 uses SK CCMP-128 security (security upgrade).
                  If False, both NDPs are open.
    """
    pwd2 = "NAN" if secure_ndp2 else None
    csid2 = 1 if secure_ndp2 else None  # SK CCMP-128

    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0", "ndi0") as pub, \
        NanDevice(wpas2, "nan1", "ndi1") as sub:

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        # First NDP (always open)
        pid1, sid1, paddr, saddr = _nan_discover_service(pub, sub,
                                                         "test_service1", pssi,
                                                         sssi, data_path=True)

        ndp_id1, init_ndi1 = _nan_ndp_request_and_accept(pub, sub, pid1, sid1,
                                                         paddr, saddr,
                                                         req_ssi="aabbcc",
                                                         resp_ssi="ddeeff",
                                                         configure_schedule=True)

        logger.info("NDP1 (open) connection established successfully")

        # Second NDP (open or secure based on secure_ndp2)
        pid2, sid2, _, _ = _nan_discover_service(pub, sub, "test_service2",
                                                 pssi, sssi, data_path=True)

        # Schedule already configured
        ndp_id2, init_ndi2 = _nan_ndp_request_and_accept(pub, sub, pid2, sid2,
                                                         paddr, saddr,
                                                         req_ssi="112233",
                                                         resp_ssi="445566",
                                                         csid=csid2,
                                                         password=pwd2,
                                                         configure_schedule=False)

        if secure_ndp2:
            logger.info("NDP2 (secure) connection established successfully")
            logger.info("Security upgrade test: open NDP1 + secure NDP2 with same peer")
        else:
            logger.info("NDP2 (open) connection established successfully")
            logger.info("Both open NDPs with same peer established successfully")

        _nan_test_connectivity(pub, sub)
        _nan_ndp_terminate(pub, sub, paddr, init_ndi1, ndp_id1)

        # Test connectivity again to ensure NDP2 is still functional
        _nan_test_connectivity(pub, sub)
        _nan_ndp_terminate(pub, sub, paddr, init_ndi2, ndp_id2)

def test_nan_dp_open_counter(dev, apdev, params):
    """NAN DP open with counter proposal"""
    run_nan_dp(counter=True, use_interface_id=True)

def test_nan_dp_open_conditional(dev, apdev, params):
    """NAN DP open with conditional availability"""
    run_nan_dp(force_conditional=True)

def test_nan_dp_open_counter_conditional(dev, apdev, params):
    """NAN DP open with counter proposal using conditional availability"""
    run_nan_dp(counter=True, force_conditional=True)

def test_nan_dp_sk_ccmp128(dev, apdev, params):
    """NAN DP - 2way NDL + SK CCMP security"""
    run_nan_dp(csid=1)

def test_nan_dp_sk_gcmp256(dev, apdev, params):
    """NAN DP - 3way NDL + SK GCMP-256 security"""
    run_nan_dp(counter=True, csid=2)

def test_nan_dp_wrong_pwd(dev, apdev, params):
    """NAN DP - Wrong password"""
    run_nan_dp(csid=1, wrong_pwd=True)

def test_nan_dp_pmk(dev, apdev, params):
    """NAN DP - 3way NDL + SK CCMP security with PMK"""
    run_nan_dp(counter=True, csid=1, use_pmk=True, use_interface_id=True)

def test_nan_sdf_dp_params(dev, apdev, params):
    """NAN SDF: Data path parameters in publish and subscribe SDF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid = pub.publish("test_dp_params", ssi="aabbccdd", unsolicited=0,
                          dp_type=1, security_required=1)
        sid = sub.subscribe("test_dp_params", ssi="ddbbccaa",
                            dp_required=1, dp_type=1, security_required=1)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (SDF dp params)")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED not seen (SDF dp params)")

def test_nan_subscribe_sdea_cipher_suites(dev, apdev, params):
    """NAN: cipher suite list in subscribe SDF (SDEA attribute)"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid = pub.publish("test_sub_sdea", ssi="aabbccdd", unsolicited=0,
                          cipher_suites=1)
        sid = sub.subscribe("test_sub_sdea", ssi="ddbbccaa", cipher_suites=1)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (subscribe SDEA cipher suites)")

        data = split_nan_event(ev)
        if "cipher_suites" not in data:
            raise Exception(f"cipher_suites missing in discovery result: {ev}")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED not seen (subscribe SDEA)")

def nan_pre_bootstrap(pub, sub, pmb=0x1):
    paddr = pub.wpas.own_addr()
    saddr = sub.wpas.own_addr()

    pssi = "aabbccdd"
    sssi = "ddbbccaa"

    pid = pub.publish("test_service", ssi=pssi, unsolicited=0, pbm=pmb)
    sid = sub.subscribe("test_service", ssi=sssi)

    logger.info(f"Publish ID: {pid}, Subscribe ID: {sid}")

    ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
    if ev is None:
        raise Exception("NAN-DISCOVERY-RESULT event not seen")

    nan_sync_verify_event(ev, paddr, pid, sid, pssi)

    ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
    if ev is None:
        raise Exception("NAN-REPLIED event not seen")

    nan_sync_verify_event(ev, saddr, pid, sid, sssi)

    return pid, sid, paddr, saddr

def test_nan_bootstrap_opportunistic(dev, apdev, params):
    """NAN opportunistic bootstrap with auto accept"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, saddr = nan_pre_bootstrap(pub, sub)

        sub.bootstrap(paddr, sid, pid, 0x1)

        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen")

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen")

def test_nan_bootstrap_password(dev, apdev, params):
    """NAN bootstrap with password"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, saddr = nan_pre_bootstrap(pub, sub, pmb=0x4)

        # request bootstrap with passphrase using passpharse keypad method (BIT 6)
        sub.bootstrap(paddr, sid, pid, 0x40)

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-REQUEST"], timeout=2)
        if ev is None or "peer_nmi=" + saddr not in ev or "pbm=0x0004" not in ev:
            raise Exception("NAN-BOOTSTRAP-REQUEST event not seen")

        pub.bootstrap(saddr, pid, sid, 0x4, auth=True)
        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None or "pbm=0x0040" not in ev:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen (subscriber)")

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None or "pbm=0x0004" not in ev:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen (publisher)")

def test_nan_bootstrap_password_with_delays(dev, apdev, params):
    """NAN bootstrap with password with delay and wrong method"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, saddr = nan_pre_bootstrap(pub, sub, pmb=0x4)

        # request bootstrap with passphrase using passpharse keypad method (BIT 6)
        sub.bootstrap(paddr, sid, pid, 0x40)

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-REQUEST"], timeout=2)
        if ev is None or "peer_nmi=" + saddr not in ev or "pbm=0x0004" not in ev:
            raise Exception("NAN-BOOTSTRAP-REQUEST event not seen")

        # To not authenticate the peer for 10 seconds and verify that no success event is sent
        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=10)
        if ev is not None:
            raise Exception("Got unexpected NAN-BOOTSTRAP-SUCCESS event seen (subscriber)")

        # now try with wrong method (QR code display, BIT 3)
        pub.bootstrap(saddr, pid, sid, 0x8, auth=True)
        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=5)
        if ev is not None:
            raise Exception("Got unexpected NAN-BOOTSTRAP-SUCCESS event seen (subscriber)")

        # now authenticate properly
        pub.bootstrap(saddr, pid, sid, 0x4, auth=True)
        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None or "pbm=0x0040" not in ev:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen (subscriber)")

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None or "pbm=0x0004" not in ev:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen (publisher)")

        pub.bootstrap_reset(saddr)
        sub.bootstrap_reset(paddr)

def test_nan_bootstrap_password_no_response(dev, apdev, params):
    """NAN bootstrap with password with no response from publisher"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, saddr = nan_pre_bootstrap(pub, sub, pmb=0x4)

        # cancel the publish to simulate no response
        pub.cancel_publish(pid)

        # request bootstrap with passphrase using passpharse keypad method (BIT 6)
        sub.bootstrap(paddr, sid, pid, 0x40)

        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=10)
        if ev is not None:
            raise Exception("Got unexpected NAN-BOOTSTRAP-SUCCESS event seen (subscriber)")

        sub.bootstrap_reset(paddr)
        sub.cancel_subscribe(sid)

def test_nan_pair_abort(dev, apdev, params):
    """NAN pair abort"""
    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, saddr = nan_pre_bootstrap(pub, sub, pmb=0x4)

        # Complete bootstrap
        sub.bootstrap(paddr, sid, pid, 0x40)
        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-REQUEST"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-REQUEST event not seen")
        pub.bootstrap(saddr, pid, sid, 0x4, auth=True)
        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen (subscriber)")
        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen (publisher)")

        # Start PASN pairing without responder ready
        sub.pairing_request(pub, sid, pid, "SAE", responder=False,
                            password="password123")

        ev_sub = sub.wpas.wait_event(["NAN-PAIRING-STATUS"], timeout=2)
        if ev_sub is not None:
            raise Exception("Unexpected PASN result seen on subscriber")

        ev_pub = pub.wpas.wait_event(["NAN-PAIRING-REQUEST"], timeout=2)
        if ev_pub is None:
            raise Exception("PASN pairing request not seen on publisher")

        if "OK" not in pub.pair_abort(saddr):
            raise Exception("NAN_PAIR_ABORT failed on publisher")

        # The subscriber should get a failure result
        ev_sub = sub.wpas.wait_event(["NAN-PAIRING-STATUS"], timeout=5)
        if ev_sub is None:
            raise Exception("PASN result not seen on subscriber")
        if "status=failure" not in ev_sub:
            raise Exception("NAN pairing failed status not seen on subscriber after abort")

        # After abort, we should be able to restart pairing successfully
        sub.pairing_request(pub, sid, pid, "SAE", responder=False,
                            password="password123")
        ev_pub = pub.wpas.wait_event(["NAN-PAIRING-REQUEST"], timeout=2)
        if ev_pub is None:
            raise Exception("PASN pairing request not seen on publisher after abort")

        pub.pairing_request(sub, sid, pid, "SAE", responder=True,
                            password="password123")
        ev_sub = sub.wpas.wait_event(["NAN-PAIRING-STATUS"], timeout=5)
        if ev_sub is None:
            raise Exception("PASN result not seen on subscriber")
        if "status=success" not in ev_sub:
            raise Exception("NAN PASN pairing failed on subscriber after abort")
        ev_pub = pub.wpas.wait_event(["NAN-PAIRING-STATUS"], timeout=5)
        if ev_pub is None:
            raise Exception("PASN result not seen on publisher")
        if "status=success" not in ev_pub:
            raise Exception("NAN PASN pairing failed on publisher after abort")

        # Test abort with invalid peer address
        if "FAIL" not in sub.pair_abort("02:00:00:00:00:00"):
            raise Exception("NAN_PAIR_ABORT with invalid peer address succeeded unexpectedly")

def test_nan_dp_pwd_hex(dev, apdev, params):
    """NAN DP - SK CCMP security with password specified as hex"""
    run_nan_dp(csid=1, use_pwd_hex=True)

def run_nan_pairing(sub, pub, pid, sid, pairing_type, password=None):
    if pairing_type == "SAE":
        if password is not None:
            pass
        else:
            raise Exception("Password must be provided for SAE pairing")

    pub.pairing_request(sub, sid, pid, pairing_type, responder=True,
                        password=password)
    sub.pairing_request(pub, sid, pid, pairing_type, responder=False,
                        password=password)

    ev_sub = sub.wpas.wait_event(["NAN-PAIRING-STATUS"], timeout=5)
    if ev_sub is None:
        raise Exception("PASN result not seen on requesting device")
    if "status=success" not in ev_sub:
        raise Exception("NAN PASN pairing failed on requesting device")

    ev_pub = pub.wpas.wait_event(["NAN-PAIRING-STATUS"], timeout=5)
    if ev_pub is None:
        raise Exception("PASN result not seen on publisher")
    if "status=success" not in ev_pub:
        raise Exception("NAN PASN pairing failed on publisher")

    # Extract nd_pmk from both events
    data_sub = split_nan_event(ev_sub)
    data_pub = split_nan_event(ev_pub)

    nd_pmk_sub = data_sub.get('nd_pmk')
    nd_pmk_pub = data_pub.get('nd_pmk')

    if nd_pmk_sub is None:
        raise Exception("nd_pmk not found in subscriber pairing status event")
    if nd_pmk_pub is None:
        raise Exception("nd_pmk not found in publisher pairing status event")

    if nd_pmk_sub != nd_pmk_pub:
        raise Exception(f"nd_pmk mismatch: sub={nd_pmk_sub}, pub={nd_pmk_pub}")

    logger.info(f"NAN pairing successful, nd_pmk={nd_pmk_sub}")

    ev = pub.wpas.wait_event(["NAN-NIK-RECEIVED"], timeout=1)
    ev = sub.wpas.wait_event(["NAN-NIK-RECEIVED"], timeout=1)

    return nd_pmk_sub

def run_nan_pairing_bootstrap(pairing_type, password=None):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        if "OK" not in sub.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule (sub)")

        if "OK" not in pub.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule (pub)")

        pid, sid, paddr, saddr = nan_pre_bootstrap(pub, sub)
        sub.bootstrap(paddr, sid, pid, 0x1)

        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen")

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen")

        run_nan_pairing(sub, pub, pid, sid, pairing_type, password)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

def test_nan_sae_pairing_bootstrap(dev, apdev, params):
    """NAN Pairing setup using opportunistic bootstrapping"""
    run_nan_pairing_bootstrap("SAE", password="password123")

def test_nan_pbea_pairing_setup_info_discovery(dev, apdev, params):
    """NAN PBEA: Pairing Setup Info fields and extended PBM"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid = pub.publish("test_pbea_disc", ssi="aabbccdd", unsolicited=0,
                          pbm=1, extended_pbm=1,
                          pairing_setup_info="locale=en-US,vendorName=Qualcomm,modelName=TestDevice,pairingName=MyPairing")
        sid = sub.subscribe("test_pbea_disc", ssi="ddbbccaa")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (PBEA PSI)")

        _check_discovery_result_field(ev, "locale", "en-US")
        _check_discovery_result_field(ev, "vendorName", "Qualcomm")
        _check_discovery_result_field(ev, "modelName", "TestDevice")
        _check_discovery_result_field(ev, "pairingName", "MyPairing")

def test_nan_pbea_pairing_setup_info_bootstrap_request(dev, apdev, params):
    """NAN PBEA: Pairing Setup Info in NAN-BOOTSTRAP-REQUEST event"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()

        pid = pub.publish("test_pbea_bsr", ssi="aabbccdd", unsolicited=0,
                          pbm=4)
        sid = sub.subscribe("test_pbea_bsr", ssi="ddbbccaa", pbm=4,
                            pairing_setup_info="locale=fr-FR,vendorName=Acme,modelName=Widget,pairingName=AcmePair")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (PBEA BSR)")

        data = split_nan_event(ev)
        pub_id = data["publish_id"]
        sub_id = data["subscribe_id"]

        sub.bootstrap(paddr, sub_id, pub_id, 0x40)

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-REQUEST"], timeout=5)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-REQUEST not seen on publisher")

        if "locale=fr-FR" not in ev:
            raise Exception(f"locale not found in NAN-BOOTSTRAP-REQUEST: {ev}")
        if "vendorName=Acme" not in ev:
            raise Exception(f"vendorName not found in NAN-BOOTSTRAP-REQUEST: {ev}")
        if "modelName=Widget" not in ev:
            raise Exception(f"modelName not found in NAN-BOOTSTRAP-REQUEST: {ev}")
        if "pairingName=AcmePair" not in ev:
            raise Exception(f"pairingName not found in NAN-BOOTSTRAP-REQUEST: {ev}")

def test_nan_pbea_pairing_setup_info_subscribe(dev, apdev, params):
    """NAN PBEA: Pairing Setup Info set on subscriber side"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid = pub.publish("test_pbea_sub", ssi="aabbccdd", unsolicited=0, pbm=1)
        sid = sub.subscribe("test_pbea_sub", ssi="ddbbccaa", pbm=1,
                            pairing_setup_info="locale=ja-JP,vendorName=SubCo,modelName=SubModel,pairingName=SubPair")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (PBEA sub side)")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED not seen on publisher (PBEA sub side)")

def test_nan_pbea_randomized_sid(dev, apdev, params):
    """NAN PBEA: Service ID randomization combined with Pairing Setup Info"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        self_nik = "0102030405060708090a0b0c0d0e0f10"
        pub.set("self_nik", f"{self_nik} 1")
        sub.set("peer_nik", f"{self_nik} 1")

        pid = pub.publish("test_rand_pbea", ssi="aabbccdd", unsolicited=0,
                          pbm=1, randomized_service_id=1,
                          pairing_setup_info="locale=en-GB,vendorName=ComboCo,modelName=ComboModel,pairingName=ComboPair")
        sid = sub.subscribe("test_rand_pbea", ssi="ddbbccaa")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen (randomized SID + PBEA PSI)")

        _check_discovery_result_field(ev, "locale", "en-GB")
        _check_discovery_result_field(ev, "vendorName", "ComboCo")
        _check_discovery_result_field(ev, "modelName", "ComboModel")
        _check_discovery_result_field(ev, "pairingName", "ComboPair")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED not seen (randomized SID + PBEA PSI)")

def test_nan_proxied_service_publish(dev, apdev, params):
    """NAN: Publish a proxied service with PBEA and verify discovery"""
    with hwsim_nan_radios(count=3) as [wpas1, wpas2, wpas3], \
        NanDevice(wpas1, "nan0") as proxy, \
        NanDevice(wpas2, "nan1") as sub, \
        NanDevice(wpas3, "nan2") as orig:
        orig_nmi = orig.wpas.own_addr()

        pid = proxy.publish("test_proxy", ssi="aabbccdd",
                            orig_nmi=orig_nmi, instance_id=1, pbm=1,
                            pairing_setup_info="locale=zh-CN,vendorName=ProxyCo,modelName=ProxyModel,pairingName=ProxyPair")
        sid = sub.subscribe("test_proxy", ssi="ddbbccaa", active=0)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT not seen for proxied service")

        data = split_nan_event(ev)
        if "orig_nmi" not in data:
            raise Exception(f"orig_nmi missing in proxied discovery result: {ev}")

        if data["orig_nmi"].lower() != orig_nmi.lower():
            raise Exception(f"orig_nmi mismatch: got {data['orig_nmi']}, expected {orig_nmi} in: {ev}")

        _check_discovery_result_field(ev, "locale", "zh-CN")
        _check_discovery_result_field(ev, "vendorName", "ProxyCo")
        _check_discovery_result_field(ev, "modelName", "ProxyModel")
        _check_discovery_result_field(ev, "pairingName", "ProxyPair")

def run_nan_pairing_verification(pairing_type, password=None,
                                  send_followup=False):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        if "OK" not in sub.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule (sub)")

        if "OK" not in pub.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule (pub)")

        pid, sid, paddr, saddr = nan_sync_discovery(pub, sub, "test_service",
                                                    pssi="aabbccdd",
                                                    sssi="ddbbccaa",
                                                    unsolicited=0)

        if pairing_type == "SAE":
            if password is not None:
                pass
            else:
                raise Exception("Password must be provided for SAE pairing")

        run_nan_pairing(sub, pub, pid, sid, pairing_type, password)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        import time
        time.sleep(1)
        pub.wpas.dump_monitor()
        sub.wpas.dump_monitor()

        pid, sid, paddr, saddr = nan_sync_discovery(pub, sub, "test_service",
                                                    pssi="aabbccee",
                                                    sssi="ddbbccee",
                                                    unsolicited=0,
                                                    timeout=5)

        run_nan_pairing(sub, pub, pid, sid, "PMK")

        if send_followup:
            # Send unicast follow-up to peer's NMI - should be PMF protected
            # with NM-TK after verification pairing
            sub.transmit(handle=sid, req_instance_id=pid,
                         address=paddr, ssi="aabbccddeeff")

            ev = pub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
            if ev is None or f"address={saddr}" not in ev or \
               "ssi=aabbccddeeff" not in ev:
                raise Exception("NAN-RECEIVE followup event not seen")

            pub.transmit(handle=pid, req_instance_id=sid,
                         address=saddr, ssi="ffeeddccbbaa")

            ev = sub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
            if ev is None or f"address={paddr}" not in ev or \
               "ssi=ffeeddccbbaa" not in ev:
                raise Exception("NAN-RECEIVE followup event not seen")

def test_nan_opportunistic_pairing(dev, apdev, params):
    """NAN Pairing setup using opportunistic bootstrapping"""
    run_nan_pairing_verification("PASN")

def test_nan_sae_pairing(dev, apdev, params):
    """NAN Pairing setup using a password (SAE)"""
    run_nan_pairing_verification("SAE", "nanpassword")

def test_nan_sae_pairing_with_cipher_list(dev, apdev, params):
    """NAN SAE pairing with a two-entry PASN-capable cipher list"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, _, _ = nan_sync_discovery(
            pub, sub, "test_service_two_cipher",
            pssi="aabbccdd", sssi="ddbbccaa", unsolicited=0,
            cipher_suites="1,8")

        run_nan_pairing(sub, pub, pid, sid, "SAE", "nanpassword")

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

def test_nan_prot_ucast_followup_after_verification(dev, apdev, params):
    """NAN protected unicast follow-up after pairing verification"""
    run_nan_pairing_verification("SAE", password="nanpassword",
                                 send_followup=True)

def test_nan_publish_with_pmk(dev, apdev, params):
    """NAN publish with PMK and cipher suites"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()

        # Test PMK - 32 bytes (64 hex characters)
        nd_pmk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        cipher_suites = "1,2"  # NAN_CS_SK_CCM_128, NAN_CS_SK_GCM_256

        # Publish with PMK and cipher suites
        pid = pub.publish("secure_test", nd_pmk=nd_pmk, cipher_suites=cipher_suites)
        if "FAIL" in pid:
            raise Exception(f"Failed to publish with PMK: {pid}")

        logger.info(f"Published with PMK, ID: {pid}")

        # Subscribe to the service
        sid = sub.subscribe("secure_test", ssi=None)

        # Wait for discovery with PMKIDs advertised
        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")

        if f"address={paddr}" not in ev:
            raise Exception(f"Unexpected publisher address in discovery: {ev}")

        if f"publish_id={pid}" not in ev:
            raise Exception(f"Unexpected publish ID in discovery: {ev}")

        logger.info(f"Discovery event: {ev}")

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

def _run_nan_pairing_bootstrap_ndp(pairing_type, password=None, csid=1):
    """Run NAN pairing bootstrap followed by NDP setup with security"""
    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0", "ndi0") as pub, \
        NanDevice(wpas2, "nan1", "ndi1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        # Configure schedules for both devices
        if "OK" not in sub.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule (sub)")

        if "OK" not in pub.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule (pub)")

        # Step 1: Pre-bootstrap discovery
        pssi = "aabbccdd"
        sssi = "ddbbccaa"

        pid = pub.publish("test_service", ssi=pssi, unsolicited=0, pbm=0x1,
                          data_path=True)
        sid = sub.subscribe("test_service", ssi=sssi)

        logger.info(f"Publish ID: {pid}, Subscribe ID: {sid}")

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")

        nan_sync_verify_event(ev, paddr, pid, sid, pssi, data_path=True)

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED event not seen")

        nan_sync_verify_event(ev, saddr, pid, sid, sssi)

        # Step 2: Bootstrapping
        sub.bootstrap(paddr, sid, pid, 0x1)

        ev = sub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen on subscriber")

        ev = pub.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen on publisher")

        # Step 3: Pairing
        nd_pmk = run_nan_pairing(sub, pub, pid, sid, pairing_type, password)

        logger.info(f"Pairing completed successfully: nd_pmk={nd_pmk}, now setting up NDP")

        # Step 4: NDP setup with security using the derived nd_pmk
        ndp_id, init_ndi = _nan_ndp_request_and_accept(pub, sub, pid, sid, paddr, saddr,
                                                       req_ssi="aabbcc", resp_ssi="ddeeff", csid=csid,
                                                       pmk=nd_pmk, configure_schedule=True)

        logger.info("NDP connection established successfully after pairing")

        _nan_test_connectivity(pub, sub)
        _nan_ndp_terminate(pub, sub, paddr, init_ndi, ndp_id)

        # Once the NDP is removed, verify that service discovery still works
        pub.wpas.dump_monitor()
        sub.wpas.dump_monitor()
        time.sleep(1)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")

        nan_sync_verify_event(ev, paddr, pid, sid, pssi, data_path=True)

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED event not seen")

        nan_sync_verify_event(ev, saddr, pid, sid, sssi)

def test_nan_pairing_bootstrap_ndp_sk_ccmp128(dev, apdev, params):
    """NAN Pairing bootstrap followed by NDP with SK CCMP-128 security"""
    set_country("US")
    try:
        _run_nan_pairing_bootstrap_ndp("SAE", password="password123", csid=1)
    finally:
        set_country("00")

def _run_nan_ndp_reconnect_after_terminate():
    pwd = "NAN"
    csid1 = 1  # SK CCMP-128
    csid2 = 2  # SK GCMP-256

    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0", "ndi0") as pub, \
        NanDevice(wpas2, "nan1", "ndi1") as sub:

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        # First service discovery and NDP
        pid, sid, paddr, saddr = _nan_discover_service(pub, sub, "test_service",
                                                       pssi, sssi, ttl=10,
                                                       data_path=True)

        logger.info("Starting first NDP connection...")
        ndp_id1, init_ndi1 = _nan_ndp_request_and_accept(pub, sub, pid, sid,
                                                         paddr, saddr,
                                                         req_ssi="aabbcc",
                                                         resp_ssi="ddeeff",
                                                         csid=csid1,
                                                         password=pwd,
                                                         configure_schedule=True)

        logger.info(f"First NDP established: ndp_id={ndp_id1}, init_ndi={init_ndi1}")
        _nan_test_connectivity(pub, sub)

        # Terminate the first NDP
        logger.info("Terminating first NDP...")
        _nan_ndp_terminate(pub, sub, paddr, init_ndi1, ndp_id1)
        logger.info("First NDP terminated")

        # Clear any pending events
        pub.wpas.dump_monitor()
        sub.wpas.dump_monitor()

        # Second NDP with password
        logger.info("Starting second NDP connection (reconnect after terminate)...")
        ndp_id2, init_ndi2 = _nan_ndp_request_and_accept(pub, sub, pid, sid,
                                                         paddr, saddr,
                                                         req_ssi="112233",
                                                         resp_ssi="445566",
                                                         csid=csid2,
                                                         password=pwd,
                                                         configure_schedule=False)

        logger.info(f"Second NDP established: ndp_id={ndp_id2}, init_ndi={init_ndi2}")
        _nan_test_connectivity(pub, sub)

        # Cleanup
        _nan_ndp_terminate(pub, sub, paddr, init_ndi2, ndp_id2)

def test_nan_ndp_reconnect_after_terminate(dev, apdev, params):
    """NAN NDP reconnection after termination"""
    set_country("US")
    try:
        _run_nan_ndp_reconnect_after_terminate()
    finally:
        set_country("00")

@long_duration_test
def test_nan_dp_max_idle_period(dev, apdev, params):
    """NAN DP open with max idle period verification"""
    run_nan_dp(use_interface_id=True, verify_max_idle_period=True)

def test_nan_dp_sk_ccmp128_with_gtk(dev, apdev, params):
    """NAN DP - 2way NDL + SK CCMP security with GTK"""
    run_nan_dp(csid=1, gtk_csid=5, mgmt_group_cipher="BIP-CMAC-128")

def test_nan_dp_sk_gcmp256_with_gtk(dev, apdev, params):
    """NAN DP - 2way NDL + SK GCMP-256 security with GTK"""
    run_nan_dp(csid=2, gtk_csid=6, mgmt_group_cipher="BIP-GMAC-256")

def _run_nan_prot_mcast_followup(dev, apdev, mgmt_group_cipher):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0", "ndi0", mgmt_group_cipher=mgmt_group_cipher) as pub, \
        NanDevice(wpas2, "nan1", "ndi1", mgmt_group_cipher=mgmt_group_cipher) as sub:

        pid, sid, paddr, saddr = nan_sync_discovery(pub, sub, "test_service",
                                                    pssi="aabbccdd",
                                                    sssi="ddbbccaa",
                                                    unsolicited=0)

        ndp_id, init_ndi = _nan_ndp_request_and_accept(pub, sub, pid, sid,
                                                       paddr, saddr,
                                                       password="NAN",
                                                       req_ssi="aabbcc",
                                                       resp_ssi="ddeeff",
                                                       csid=1)
        _nan_test_connectivity(pub, sub)

        # Configure the NAN DE to send multicast followup frames as Protected
        # Dual of Public Action frames and send a multicast follow-up frame. The
        # follow-up frame should be protected with the group key and accepted by
        # the peer.
        sub.set("tx_mcast_follow_up_prot", "1")
        pub.set("tx_mcast_follow_up_prot", "1")
        sub.transmit(handle=sid, req_instance_id=pid,
                     address="ff:ff:ff:ff:ff:ff",
                     ssi="aabbccddeeff")

        ev = pub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
        if ev is None or f"address={saddr}" not in ev or "ssi=aabbccddeeff" not in ev :
            raise Exception("NAN-RECEIVE followup event not seen or invalid format")

        pub.transmit(handle=pid, req_instance_id=sid,
                     address="ff:ff:ff:ff:ff:ff",
                     ssi="ffeeddccbbaa")

        ev = sub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
        if ev is None or f"address={paddr}" not in ev or "ssi=ffeeddccbbaa" not in ev:
            raise Exception("NAN-RECEIVE followup event not seen or invalid format")

        _nan_ndp_terminate(pub, sub, paddr, init_ndi, ndp_id)

def test_nan_prot_mcast_followup_bip_cmac128(dev, apdev, params):
    """NAN NDP with multicast management frame protection using BIP-CMAC-128"""
    set_country("US")
    try:
        _run_nan_prot_mcast_followup(dev, apdev,
                                     mgmt_group_cipher="BIP-CMAC-128")
    finally:
        set_country("00")

def test_nan_prot_mcast_followup_bip_gmac256(dev, apdev, params):
    """NAN NDP with multicast management frame protection using BIP-GMAC-256"""
    set_country("US")
    try:
        _run_nan_prot_mcast_followup(dev, apdev,
                                     mgmt_group_cipher="BIP-GMAC-256")
    finally:
        set_country("00")

def verify_potential_availability(potential, expected_entries):
        lines = potential.strip().split('\n')
        entries = []
        current_entry = None

        for line in lines:
            line = line.strip()
            if line.startswith('entry['):
                # Parse entry line: "entry[0]: rx_nss=2 pref=3 util=7"
                pref = None
                for part in line.split():
                    if part.startswith('pref='):
                        pref = int(part.split('=')[1])
                        break
                current_entry = {'pref': pref, 'chans': []}
                entries.append(current_entry)
            elif line.startswith('chan[') and current_entry is not None:
                # Parse chan line: "chan[0]: op_class=81 chan_bitmap=0x0020"
                op_class = None
                chan_bitmap = None
                for part in line.split():
                    if part.startswith('op_class='):
                        op_class = int(part.split('=')[1])
                    elif part.startswith('chan_bitmap='):
                        chan_bitmap = part.split('=')[1]
                current_entry['chans'].append((op_class, chan_bitmap))

        # Verify number of entries
        if len(entries) != len(expected_entries):
            raise Exception(f"Expected {len(expected_entries)} entries, got {len(entries)}")

        # Verify each entry
        for i, (exp_pref, exp_op_class, exp_bitmap) in enumerate(expected_entries):
            entry = entries[i]
            if entry['pref'] != exp_pref:
                raise Exception(f"Entry {i}: expected pref={exp_pref}, got pref={entry['pref']}")
            if len(entry['chans']) != 1:
                raise Exception(f"Entry {i}: expected 1 channel, got {len(entry['chans'])}")
            op_class, bitmap = entry['chans'][0]
            if op_class != exp_op_class:
                raise Exception(f"Entry {i}: expected op_class={exp_op_class}, got op_class={op_class}")
            if bitmap != exp_bitmap:
                raise Exception(f"Entry {i}: expected chan_bitmap={exp_bitmap}, got chan_bitmap={bitmap}")

def test_nan_override_potential_availability(dev, apdev, params):
    """NAN override potential availability configuration"""
    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0", "ndi0") as pub, \
        NanDevice(wpas2, "nan1", "ndi1") as sub:
        pssi = "aabbccdd"
        sssi = "ddbbccaa"

        # Test invalid formats
        pub.set("override_potential_availability", "81:0x20", ok=False)
        pub.set("override_potential_availability", "81-0x20-3", ok=False)
        pub.set("override_potential_availability", "81:0x20:5", ok=False)
        pub.set("override_potential_availability", "256:0x20:3", ok=False)
        pub.set("override_potential_availability", "81:6:3", ok=False)

        # Discover service - this should trigger potential availability exchange
        pid, sid, paddr, _ = nan_sync_discovery(pub, sub, "test_service",
                                                pssi=pssi, sssi=sssi,
                                                unsolicited=0)
        old_potential = sub.wpas.request("NAN_PEER_INFO " + paddr + " potential")
        logger.info("Publisher potential availability before override:\n" + old_potential)

        pub.set("override_potential_availability", "81:0x20:3,115:0x04:0")
        # Wait a bit to ensure new availability is populated and processed
        time.sleep(2)
        expected = [
            (3, 81, "0x0020"),
            (0, 115, "0x0004"),
        ]

        potential = sub.wpas.request("NAN_PEER_INFO " + paddr + " potential")
        logger.info("Publisher potential availability:\n" + potential)
        verify_potential_availability(potential, expected)

        # Clear override and verify it accepts empty string
        pub.set("override_potential_availability", "")
        # Wait a bit to ensure new availability is populated and processed
        time.sleep(2)
        potential = sub.wpas.request("NAN_PEER_INFO " + paddr + " potential")
        logger.info("Publisher potential availability after clearing override:\n" + potential)

        # This check is not 100% safe (e.g., regulatory updates could change
        # the channel set), but it is good enough for the test as we don't
        # expect any changes during the test execution.
        if potential != old_potential:
            raise Exception("Potential availability did not revert to original after clearing override")

def test_nan_stopped_on_iface_removal(dev, apdev, params):
    """NAN cluster and discovery followed by radio destruction reports NAN-STOPPED"""
    controller = HWSimController()
    radio1 = HWSimRadio(n_channels=3, use_nan=True)
    radio1_id, ifname1 = radio1.__enter__()
    radio1_destroyed = False

    try:
        with HWSimRadio(n_channels=3, use_nan=True) as (radio2_id, ifname2):
            wpas1 = WpaSupplicant(global_iface="/tmp/wpas-wlan5")
            wpas1.interface_add(ifname1)
            wpas2 = WpaSupplicant(global_iface="/tmp/wpas-wlan6")
            wpas2.interface_add(ifname2)

            nan_ifname = "nan0"

            logger.info("Starting NAN on publisher")
            pub = NanDevice(wpas1, nan_ifname)
            pub.start()

            with NanDevice(wpas2, "nan1") as sub:
                logger.info("Verifying service discovery")
                nan_sync_discovery(pub, sub, "test_service",
                                   pssi="aabbccdd", sssi="ddbbccaa")

                logger.info("Destroying publisher radio")
                wpas1.dump_monitor()
                controller.destroy_radio(radio1_id)
                radio1_destroyed = True

                logger.info("Waiting for NAN-STOPPED event on publisher")
                ev = wpas1.wait_global_event(["NAN-STOPPED"], timeout=5)
                if ev is None:
                    raise Exception("NAN-STOPPED event not received after radio destruction")
                if f"ifname={nan_ifname}" not in ev:
                    raise Exception(f"Unexpected NAN-STOPPED event content: {ev}")

                logger.info("Removing old interface and adding new radio")
                sub.wpas.dump_monitor()
                wpas1.interface_remove(ifname1)

                radio1 = HWSimRadio(n_channels=3, use_nan=True)
                radio1_id, ifname1_new = radio1.__enter__()
                radio1_destroyed = False
                wpas1.interface_add(ifname1_new)

                logger.info("Starting NAN on re-added radio")
                pub = NanDevice(wpas1, nan_ifname)
                pub.start()

                logger.info("Verifying service discovery on re-added radio")
                nan_sync_discovery(pub, sub, "test_service2",
                                   pssi="11223344", sssi="44332211")
    finally:
        if not radio1_destroyed:
            radio1.__exit__(None, None, None)

def test_nan_stopped_on_iface_removal_with_ndp(dev, apdev, params):
    """NAN cluster, NDP establishment, then radio destruction reports NAN-STOPPED"""
    set_country("US")
    controller = HWSimController()
    radio1 = HWSimRadio(n_channels=3, use_nan=True)
    radio1_id, ifname1 = radio1.__enter__()
    radio1_destroyed = False

    try:
        with HWSimRadio(n_channels=3, use_nan=True) as (radio2_id, ifname2):
            wpas1 = WpaSupplicant(global_iface="/tmp/wpas-wlan5")
            wpas1.interface_add(ifname1)
            wpas2 = WpaSupplicant(global_iface="/tmp/wpas-wlan6")
            wpas2.interface_add(ifname2)

            nan_ifname = "nan0"
            ndi_name = "ndi0"

            logger.info("Starting NAN on publisher with NDI")
            pub = NanDevice(wpas1, nan_ifname, ndi_name)
            pub.start()

            with NanDevice(wpas2, "nan1", "ndi1") as sub:
                logger.info("Establishing NDP between publisher and subscriber")
                pid, sid, paddr, saddr = _nan_discover_service(
                    pub, sub, "test_service", "aabbccdd", "ddbbccaa",
                    data_path=True)
                ndp_id, init_ndi = _nan_ndp_request_and_accept(
                    pub, sub, pid, sid, paddr, saddr,
                    req_ssi="aabbcc", resp_ssi="ddeeff")

                logger.info("Verifying connectivity over NDP")
                _nan_test_connectivity(pub, sub)

                logger.info("Destroying publisher radio while NDP is active")
                wpas1.dump_monitor()
                sub.wpas.dump_monitor()
                controller.destroy_radio(radio1_id)
                radio1_destroyed = True

                logger.info("Waiting for NAN-STOPPED event on publisher")
                ev = wpas1.wait_global_event(["NAN-STOPPED"], timeout=5)
                if ev is None:
                    raise Exception("NAN-STOPPED event not received after radio destruction")
                if f"ifname={nan_ifname}" not in ev:
                    raise Exception(f"Unexpected NAN-STOPPED event content: {ev}")

                logger.info("Terminating NDP on subscriber")
                sub.ndp_terminate(paddr, init_ndi, ndp_id)
                ev = sub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
                if ev is None:
                    raise Exception("NAN-NDP-DISCONNECTED not received on subscriber")

                logger.info("Removing old interface and adding new radio")
                sub.wpas.dump_monitor()
                wpas1.interface_remove(ifname1)

                radio1 = HWSimRadio(n_channels=3, use_nan=True)
                radio1_id, ifname1_new = radio1.__enter__()
                radio1_destroyed = False

                wpas1.interface_add(ifname1_new)

                logger.info("Starting NAN on re-added radio with NDI")
                pub = NanDevice(wpas1, nan_ifname, ndi_name)
                pub.start()

                logger.info("Establishing NDP on re-added radio")
                pid, sid, paddr, saddr = _nan_discover_service(
                    pub, sub, "test_service2", "11223344", "44332211",
                    data_path=True)
                ndp_id, init_ndi = _nan_ndp_request_and_accept(
                    pub, sub, pid, sid, paddr, saddr,
                    req_ssi="aabbcc", resp_ssi="ddeeff")

                logger.info("Verifying connectivity on re-added radio")
                _nan_test_connectivity(pub, sub)

                logger.info("NDP recovery after radio destruction verified successfully")
    finally:
        if not radio1_destroyed:
            radio1.__exit__(None, None, None)
        set_country("00")

# Public Key Records, given as a PKRA body holding one signed record
# (Wi-Fi Aware spec R5, Table 34 (PKR format) and Table 155 (PKRA format)):
#   Number of PKRs | Length | Version | Record Control | Cipher Version |
#   IPK | IIK | Valid Duration | Number of GIKs | GIK | Record Signature
PKR_A = (
    "01" "0093" "00" "040000" "00"
    "02c3165f0e14546cf26bda70924c83bd8eb8206465c1df26a13ddd057ee36acf9b"
    "12d234d66a46474285f4146a0d2d24bc"
    "00002760" "0001" "0f3c1a64ff696c98edceab43ad593d3b"
    "30450220075a3f15893e9be8dd32708b7ea12b83edecd39fe7f3050a4be4a9590137dea2"
    "022100b083388c39bde39f745c4f189a1afd87cb174ea75338cccddeb56a3a5d97422d")
ISK_A = "15d1e60d88274c670b8f8fb0a3c6955cb2df36764ee6ad47433a9c590d832c55"
IIK_A = "12d234d66a46474285f4146a0d2d24bc"

PKR_B = (
    "01" "0093" "00" "040000" "00"
    "0246d63a143a1b2618363b1c689ce1e8acb4dfd1ae3ebf39f431c389a0d29bbc96"
    "d69871c9cb705290dc72c359d968b101"
    "00002760" "0001" "0f3c1a64ff696c98edceab43ad593d3b"
    "3045022100f040bf58daa52777abce0000807eb3991824afe276926ae62030f73718d9b23e"
    "022035f002cb0d7b1d824f9008204b4e7efaa679610c90a02d50700a98c70efcc9e9")
ISK_B = "324dba74c41f1a8507733be7f2637837f40e7ca15c387cd18447aaccdccb48b8"
IIK_B = "d69871c9cb705290dc72c359d968b101"
GIK = "0f3c1a64ff696c98edceab43ad593d3b"

SERVICE_NAME = "pkbst_test"

def pkbst_config(dev, method, self_pkr=None, self_isk=None, peer_pkr=None):
    dev.set("pairing_setup", "1")
    dev.set("extended_pkbst_method", str(method))
    if self_pkr:
        dev.set("self_pkr", self_pkr)
    if self_isk:
        dev.set("self_isk", self_isk)
    if peer_pkr:
        dev.set("peer_pkr", peer_pkr)

def pkbst_discover_bootstrap(pub, sub, method, pub_pbm=0, randomized=False):
    for dev in (pub, sub):
        if "OK" not in dev.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule")

    pid = pub.publish(SERVICE_NAME, ssi="aabbccdd", unsolicited=0,
                      pbm=pub_pbm, extended_pbm=method,
                      randomized_service_id=1 if randomized else 0)
    sid = sub.subscribe(SERVICE_NAME, ssi="ddbbccaa", active=1,
                        extended_pbm=method,
                        randomized_service_id=1 if randomized else 0)

    ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
    if ev is None:
        raise Exception("NAN-DISCOVERY-RESULT not seen")
    paddr = pub.wpas.own_addr()
    nan_sync_verify_event(ev, paddr, pid, sid, "aabbccdd")
    if pub.wpas.wait_event(["NAN-REPLIED"], timeout=2) is None:
        raise Exception("NAN-REPLIED not seen")

    sub.bootstrap(paddr, sid, pid, method)
    for dev in (sub, pub):
        if dev.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2) is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS not seen")
    return pid, sid

def pkbst_pair(pub, sub, method, pub_pbm=0, randomized=False):
    pid, sid = pkbst_discover_bootstrap(pub, sub, method, pub_pbm,
                                        randomized)
    # The SAE password is derived from the IPKs; the configured password
    # must not be used.
    return run_nan_pairing(sub, pub, pid, sid, "SAE", password="unused")

def pkbst_pair_fails(pub, sub, method):
    pid, sid = pkbst_discover_bootstrap(pub, sub, method)
    try:
        run_nan_pairing(sub, pub, pid, sid, "SAE", password="unused")
    except Exception as e:
        logger.info("Pairing failed as expected: " + str(e))
        return
    raise Exception("PKBST pairing succeeded unexpectedly")

def test_nan_pkbst_provisioning(dev, apdev):
    """NAN PKBST record provisioning"""
    with hwsim_nan_radios(count=1) as [wpas1], \
         NanDevice(wpas1, "nan0") as nan:
        if "FAIL" not in nan.wpas.request("NAN_GET self_pkr"):
            raise Exception("Export without a record")
        nan.set("self_pkr", PKR_A)
        if "FAIL" not in nan.wpas.request("NAN_GET self_pkr"):
            raise Exception("Export without an ISK")
        nan.set("self_isk", ISK_A)
        blob = nan.wpas.request("NAN_GET self_pkr").strip()
        if "FAIL" in blob or ISK_A in blob or IIK_A not in blob:
            raise Exception("Invalid export: " + blob)

        # Tampered, unsigned, and multi-record blobs are rejected
        bad = PKR_A[:-2] + ("00" if PKR_A[-2:] != "00" else "01")
        unsigned = "01" + "004e" + PKR_A[6:6 + 2 * 0x4e]
        for val in (bad, unsigned, "02" + PKR_A[2:] + PKR_A[2:]):
            if "FAIL" not in nan.wpas.request("NAN_SET peer_pkr " + val):
                raise Exception("Invalid record accepted")

        # Installing another record drops the ISK of the previous one
        nan.set("self_pkr", PKR_B)
        if "FAIL" not in nan.wpas.request("NAN_GET self_pkr"):
            raise Exception("ISK kept for a different record")

def test_nan_pkbst_one_way_subscriber(dev, apdev):
    """NAN one-way PKBST, subscriber knows the publisher record"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1, self_pkr=PKR_A, self_isk=ISK_A)
        pkbst_config(sub, 1, peer_pkr=PKR_A)
        pkbst_pair(pub, sub, 1, pub_pbm=0x06)

def test_nan_pkbst_one_way_publisher(dev, apdev):
    """NAN one-way PKBST, publisher group identity resolved by subscriber"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1, self_pkr=PKR_B, self_isk=ISK_B)
        pkbst_config(sub, 1, peer_pkr=PKR_B)
        sub.set("group_nik", GIK + " 1")
        pkbst_pair(pub, sub, 1)

def test_nan_pkbst_mutual(dev, apdev):
    """NAN mutual PKBST"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_config(sub, 2, self_pkr=PKR_A, self_isk=ISK_A, peer_pkr=PKR_B)
        pkbst_pair(pub, sub, 2)

def test_nan_pkbst_mutual_service_id_randomization(dev, apdev):
    """NAN mutual PKBST with Service ID randomization"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_config(sub, 2, self_pkr=PKR_A, self_isk=ISK_A, peer_pkr=PKR_B)
        pkbst_pair(pub, sub, 2, randomized=True)

def test_nan_pkbst_mutual_roles_swapped(dev, apdev):
    """NAN mutual PKBST with the records of the two devices swapped"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 2, self_pkr=PKR_A, self_isk=ISK_A, peer_pkr=PKR_B)
        pkbst_config(sub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_pair(pub, sub, 2, pub_pbm=0x06)

def test_nan_pkbst_wrong_isk(dev, apdev):
    """NAN one-way PKBST fails when the publisher does not hold the ISK"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1, self_pkr=PKR_A, self_isk=ISK_B)
        pkbst_config(sub, 1, peer_pkr=PKR_A)
        pkbst_pair_fails(pub, sub, 1)

def test_nan_pkbst_mutual_wrong_isk(dev, apdev):
    """NAN mutual PKBST fails when the subscriber does not hold the ISK"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_config(sub, 2, self_pkr=PKR_A, self_isk=ISK_B, peer_pkr=PKR_B)
        pkbst_pair_fails(pub, sub, 2)

def test_nan_pkbst_missing_peer_record(dev, apdev):
    """NAN one-way PKBST fails without the publisher record"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1, self_pkr=PKR_A, self_isk=ISK_A)
        pkbst_config(sub, 1)
        pkbst_pair_fails(pub, sub, 1)

def test_nan_pkbst_generated_record(dev, apdev):
    """NAN one-way PKBST with a locally generated record"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1)
        pub.set("generate_self_pkr", "1")
        blob = pub.wpas.request("NAN_GET self_pkr").strip()
        if "FAIL" in blob or blob[:2] != "01":
            raise Exception("Invalid export: " + blob)
        if int(blob[2:6], 16) * 2 + 6 != len(blob):
            raise Exception("Inconsistent record length")
        if blob[16:18] not in ("02", "03"):
            raise Exception("IPK is not a compressed P-256 point")
        pkbst_config(sub, 1, peer_pkr=blob)
        pkbst_pair(pub, sub, 1, pub_pbm=0x06)

def test_nan_pkbst_pik_verification(dev, apdev):
    """NAN PKBST pairing setup followed by PIK-based pairing verification"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_config(sub, 2, self_pkr=PKR_A, self_isk=ISK_A, peer_pkr=PKR_B)
        for dev in (pub, sub):
            dev.set("npk_caching", "1")
            dev.set("pik_caching", "1")
            dev.set("pairing_verification", "1")
        pid, sid = pkbst_discover_bootstrap(pub, sub, 2)
        run_nan_pairing(sub, pub, pid, sid, "SAE", password="unused")
        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)
        pub.wpas.dump_monitor()
        sub.wpas.dump_monitor()

        # Rediscovery with PNTags and verification with the cached NPK
        pid = pub.publish(SERVICE_NAME, ssi="aabbccee", unsolicited=0)
        sid = sub.subscribe(SERVICE_NAME, ssi="ddbbccee", active=1)
        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is None:
            raise Exception("Rediscovery not seen")
        pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        run_nan_pairing(sub, pub, pid, sid, "PMK")

def test_nan_pkbst_pik_verification_restart(dev, apdev):
    """NAN PIK-based pairing verification after NAN restart"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1, self_pkr=PKR_A, self_isk=ISK_A)
        pkbst_config(sub, 1, peer_pkr=PKR_A)
        for dev in (pub, sub):
            dev.set("npk_caching", "1")
            dev.set("pik_caching", "1")
            dev.set("pairing_verification", "1")
        pid, sid = pkbst_discover_bootstrap(pub, sub, 1, pub_pbm=0x06)
        run_nan_pairing(sub, pub, pid, sid, "SAE", password="unused")

        # The pairwise identity is kept across NAN restart
        for dev in (pub, sub):
            if "OK" not in dev.wpas.request("NAN_STOP"):
                raise Exception("NAN_STOP failed")
            dev.wpas.dump_monitor()
            if "OK" not in dev.wpas.request("NAN_START"):
                raise Exception("NAN_START failed")
            if dev.wpas.wait_event(["NAN-CLUSTER-JOIN"], timeout=5) is None:
                raise Exception("NAN-CLUSTER-JOIN not seen")
            if "OK" not in dev.schedule_config((2437, "0e000000")):
                raise Exception("Failed to configure schedule")

        pid = pub.publish(SERVICE_NAME, ssi="aabbccee", unsolicited=0)
        sid = sub.subscribe(SERVICE_NAME, ssi="ddbbccee", active=1)
        if sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5) is None:
            raise Exception("Rediscovery not seen")
        pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        run_nan_pairing(sub, pub, pid, sid, "PMK")

def pkbst_paired(pub, sub, mutual=False):
    if mutual:
        pkbst_config(pub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_config(sub, 2, self_pkr=PKR_A, self_isk=ISK_A, peer_pkr=PKR_B)
        method = 2
    else:
        pkbst_config(pub, 1, self_pkr=PKR_A, self_isk=ISK_A)
        pkbst_config(sub, 1, peer_pkr=PKR_A)
        method = 1
    pid, sid = pkbst_discover_bootstrap(pub, sub, method, pub_pbm=0x06)
    run_nan_pairing(sub, pub, pid, sid, "SAE", password="unused")
    # Allow keys to be installed before protected frames are sent
    time.sleep(0.2)
    pub.wpas.dump_monitor()
    sub.wpas.dump_monitor()

def run_nan_pkbst_record_update(mutual, sender, send_revoked):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_paired(pub, sub, mutual=mutual)
        if sender == "pub":
            tx, rx = pub, sub
            old_iik = IIK_B if mutual else IIK_A
        else:
            tx, rx = sub, pub
            old_iik = IIK_A

        command = "NAN_UPDATE_PKR peer_nmi=%s generate=1 send=1" % \
            rx.wpas.own_addr()
        if send_revoked:
            command += " send_revoked=1"
        if "OK" not in tx.wpas.request(command):
            raise Exception("NAN_UPDATE_PKR failed: " + command)

        new = tx.wpas.request("NAN_GET self_pkr").strip()
        new_iik = new[82:114]
        peer_addr = tx.wpas.own_addr()

        if send_revoked:
            ev = rx.wpas.wait_event(["NAN-PKR-UPDATE"], timeout=3)
            if ev is None or "addr=" + peer_addr not in ev or \
               "iik=" + old_iik not in ev or "revoked=1" not in ev:
                raise Exception("Unexpected revocation event: " + str(ev))

        ev = rx.wpas.wait_event(["NAN-PKR-UPDATE"], timeout=3)
        if ev is None or "addr=" + peer_addr not in ev or \
           "iik=" + new_iik not in ev or "revoked=0" not in ev:
            raise Exception("Unexpected update event: " + str(ev))

def test_nan_pkbst_record_update(dev, apdev):
    """NAN one-way PKBST update with revocation from the publisher"""
    run_nan_pkbst_record_update(False, "pub", True)

def test_nan_pkbst_record_update_one_way(dev, apdev):
    """NAN one-way PKBST update without revocation"""
    run_nan_pkbst_record_update(False, "pub", False)

def test_nan_pkbst_record_update_mutual_publisher(dev, apdev):
    """NAN mutual PKBST update with revocation from the publisher"""
    run_nan_pkbst_record_update(True, "pub", True)

def test_nan_pkbst_record_update_mutual_publisher_no_revoke(dev, apdev):
    """NAN mutual PKBST update without revocation from the publisher"""
    run_nan_pkbst_record_update(True, "pub", False)

def test_nan_pkbst_record_update_mutual_subscriber(dev, apdev):
    """NAN mutual PKBST update with revocation from the subscriber"""
    run_nan_pkbst_record_update(True, "sub", True)

def test_nan_pkbst_record_update_mutual_subscriber_no_revoke(dev, apdev):
    """NAN mutual PKBST update without revocation from the subscriber"""
    run_nan_pkbst_record_update(True, "sub", False)

def test_nan_pkbst_record_update_not_paired(dev, apdev):
    """NAN PKBST record update is not sent to a peer that is not paired"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 1, self_pkr=PKR_A, self_isk=ISK_A)
        pkbst_config(sub, 1, peer_pkr=PKR_A)
        pkbst_discover_bootstrap(pub, sub, 1, pub_pbm=0x06)
        if "FAIL" not in pub.wpas.request(
                "NAN_UPDATE_PKR peer_nmi=%s send=1" %
                sub.wpas.own_addr()):
            raise Exception("Update to an unpaired peer accepted")
        if "FAIL" not in pub.wpas.request(
                "NAN_UPDATE_PKR generate=1 send=1"):
            raise Exception("Update without peer accepted")

NAN_CM_CAPAS = ("default_ka", "deauth_sa_query", "ndtk_rekey",
                "termination_notif")

def nan_cm_info(dev, peer):
    res = dev.wpas.request("NAN_PEER_INFO %s cm" % peer.wpas.own_addr())
    if "FAIL" in res:
        raise Exception("NAN_PEER_INFO cm failed")
    return dict(line.split('=', 1) for line in res.splitlines())

def nan_cm_check_capa(pub, sub, *capas):
    """Verify that both devices can use the CM capabilities with each other"""
    for dev, peer in ((pub, sub), (sub, pub)):
        info = nan_cm_info(dev, peer)
        for capa in capas:
            if info.get(capa) != "1":
                raise Exception("NAN CM %s not usable on %s: %s" %
                                (capa, dev.ifname, info))

def nan_cm_pair_ndp(pub, sub, *capas):
    """Pair the devices and set up an NDP

    The Connection Management capabilities listed in capas are verified to be
    usable between the paired devices."""
    for dev in (pub, sub):
        if "OK" not in dev.schedule_config((2437, "0e000000")):
            raise Exception("Failed to configure schedule")

    paddr = pub.wpas.own_addr()
    saddr = sub.wpas.own_addr()
    pid = pub.publish("test_service", ssi="aabbccdd", unsolicited=0,
                      pbm=0x1, data_path=True)
    sid = sub.subscribe("test_service", ssi="ddbbccaa")
    ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
    if ev is None:
        raise Exception("NAN-DISCOVERY-RESULT event not seen")
    ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
    if ev is None:
        raise Exception("NAN-REPLIED event not seen")

    sub.bootstrap(paddr, sid, pid, 0x1)
    for dev in (sub, pub):
        ev = dev.wpas.wait_event(["NAN-BOOTSTRAP-SUCCESS"], timeout=2)
        if ev is None:
            raise Exception("NAN-BOOTSTRAP-SUCCESS event not seen")

    nd_pmk = run_nan_pairing(sub, pub, pid, sid, "SAE",
                             password="password123")
    nan_cm_check_capa(pub, sub, *capas)
    ndp_id, init_ndi = _nan_ndp_request_and_accept(pub, sub, pid, sid,
                                                   paddr, saddr,
                                                   req_ssi="aabbcc",
                                                   resp_ssi="ddeeff",
                                                   csid=1, pmk=nd_pmk)
    return pid, sid, ndp_id, init_ndi

def test_nan_cm_keepalive(dev, apdev):
    """NAN Connection Management keep alive with a paired peer"""
    set_country("US")
    try:
        with hwsim_nan_radios() as (wpas1, wpas2), \
             NanDevice(wpas1, "nan0", "ndi0") as pub, \
             NanDevice(wpas2, "nan1", "ndi1") as sub:
            nan_cm_pair_ndp(pub, sub, "default_ka")

            for dev, peer in ((pub, sub), (sub, pub)):
                info = nan_cm_info(dev, peer)
                if info.get("nm_tksa") != "1" or \
                   info.get("ka_active") != "1":
                    raise Exception("Unexpected CM state on %s: %s" %
                                    (dev.ifname, info))

            # The NDP is reported in the KAAs and must remain established
            # over several keep alive periods.
            ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=16)
            if ev is not None:
                raise Exception("NDP disconnected during keep alive: " + ev)
            _nan_test_connectivity(pub, sub)
            for dev, peer in ((pub, sub), (sub, pub)):
                if nan_cm_info(dev, peer).get("ka_active") != "1":
                    raise Exception("Keep alive stopped on " + dev.ifname)
    finally:
        set_country("00")

def test_nan_cm_keepalive_terminate_during_setup(dev, apdev):
    """NAN Connection Management keep alive NDP termination during NDP setup"""
    set_country("US")
    try:
        with hwsim_nan_radios() as (wpas1, wpas2), \
             NanDevice(wpas1, "nan0", "ndi0") as pub, \
             NanDevice(wpas2, "nan1", "ndi1") as sub:
            pid, sid, ndp_id, init_ndi = nan_cm_pair_ndp(pub, sub,
                                                         "default_ka")
            paddr = pub.wpas.own_addr()
            saddr = sub.wpas.own_addr()
            sub.cancel_subscribe(sid)
            pub.wpas.dump_monitor()
            sub.wpas.dump_monitor()

            pid2 = pub.publish("test_service2", ssi="aabbccdd", unsolicited=0,
                               data_path=True)
            sid2 = sub.subscribe("test_service2", ssi="ddbbccaa")
            ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
            if ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            ndp_id2, init_ndi2 = _nan_ndp_request_and_accept(
                pub, sub, pid2, sid2, paddr, saddr, req_ssi="112233",
                resp_ssi="445566", csid=1, password="password123",
                configure_schedule=False)

            # The subscriber removes the second NDP without the publisher
            # processing the NDP Termination, so the publisher learns about
            # it only from the KAAs.
            pub.wpas.request("SET ext_mgmt_frame_handling 1")
            sub.ndp_terminate(paddr, init_ndi2, ndp_id2)
            ev = sub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
            if ev is None:
                raise Exception("NDP not terminated on subscriber")
            ev = pub.wpas.wait_event(["MGMT-RX"], timeout=5)
            if ev is None:
                raise Exception("NDP Termination not seen on publisher")
            pub.wpas.request("SET ext_mgmt_frame_handling 0")
            pub.wpas.dump_monitor()

            # Start a new NDP setup and keep it in progress on the publisher
            # while the KAAs from the subscriber no longer report the second
            # NDP.
            if "OK" not in sub.ndp_request(sub.ndi_name, sid2, paddr, pid2,
                                           "223344", csid=1,
                                           password="password123"):
                raise Exception("NDP request failed")
            ev = pub.wpas.wait_event(["NAN-NDP-REQUEST"], timeout=5)
            if ev is None:
                raise Exception("NAN-NDP-REQUEST not seen on publisher")
            data = split_nan_event(ev)
            ndp_id3 = data['ndp_id']
            init_ndi3 = data['init_ndi']

            ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=16)
            if ev is None:
                raise Exception("NDP missing from KAAs not terminated")
            data = split_nan_event(ev)
            if data.get("ndp_id") != str(ndp_id2) or \
               data.get("peer_ndi") != init_ndi2:
                raise Exception("Unexpected NDP terminated: " + ev)

            # The NDP setup in progress is not affected
            if "OK" not in pub.ndp_response("accept", saddr, ndi=pub.ndi_name,
                                            ndp_id=ndp_id3,
                                            init_ndi=init_ndi3, handle=pid2,
                                            ssi="556677", csid=1,
                                            password="password123"):
                raise Exception("NDP response (accept) failed")
            for d in (pub, sub):
                ev = d.wpas.wait_event(["NAN-NDP-CONNECTED",
                                        "NAN-NDP-DISCONNECTED"], timeout=5)
                if ev is None or "NAN-NDP-CONNECTED" not in ev or \
                   "ndp_id=%s " % ndp_id3 not in ev:
                    raise Exception("NDP not connected on %s: %s" %
                                    (d.ifname, ev))

            # The remaining NDPs are reported in the KAAs and stay
            # established.
            ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=11)
            if ev is not None:
                raise Exception("NDP disconnected after the setup: " + ev)
            _nan_test_connectivity(pub, sub)
    finally:
        set_country("00")

def test_nan_cm_keepalive_not_supported(dev, apdev):
    """NAN Connection Management keep alive not used without peer support"""
    set_country("US")
    try:
        with hwsim_nan_radios() as (wpas1, wpas2), \
             NanDevice(wpas1, "nan0", "ndi0") as pub, \
             NanDevice(wpas2, "nan1", "ndi1") as sub:
            sub.set("connection_mgmt", "2", ok=False)
            sub.set("connection_mgmt", "0")
            nan_cm_pair_ndp(pub, sub)

            # No capability is used with the peer on either device
            for dev, peer in ((pub, sub), (sub, pub)):
                info = nan_cm_info(dev, peer)
                for capa in NAN_CM_CAPAS:
                    if info.get(capa) != "0":
                        raise Exception("CM %s used on %s: %s" %
                                        (capa, dev.ifname, info))
                if info.get("nm_tksa") != "1" or \
                   info.get("ka_active") != "0":
                    raise Exception("Unexpected CM state on %s: %s" %
                                    (dev.ifname, info))

            ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=16)
            if ev is not None:
                raise Exception("NDP disconnected without keep alive: " + ev)

            # The peer indicated the capabilities, so they can be used once
            # enabled locally
            sub.set("connection_mgmt", "1")
            info = nan_cm_info(sub, pub)
            for capa in NAN_CM_CAPAS:
                if info.get(capa) != "1":
                    raise Exception("CM %s not enabled again: %s" %
                                    (capa, info))
    finally:
        set_country("00")

def nan_cm_wait_info(dev, peer, field, value, timeout):
    for i in range(timeout * 10):
        if nan_cm_info(dev, peer).get(field) == value:
            return
        time.sleep(0.1)
    raise Exception("%s did not reach %s=%s: %s" %
                    (dev.ifname, field, value, nan_cm_info(dev, peer)))

def nan_cm_wait_terminated(dev, peer, sa, local, extra=None, ndp=False):
    """Wait for NAN-CM-TERMINATED and, with ndp=True, NAN-NDP-DISCONNECTED"""
    data = None
    for i in range(2 if ndp else 1):
        ev = dev.wpas.wait_event(["NAN-CM-TERMINATED",
                                  "NAN-NDP-DISCONNECTED"], timeout=5)
        if ev is None:
            raise Exception("Termination events not seen on " + dev.ifname)
        if "NAN-NDP-DISCONNECTED" in ev:
            if not ndp:
                raise Exception("Unexpected NDP disconnection on " +
                                dev.ifname)
            ndp = False
            continue
        data = split_nan_event(ev)
    if ndp or data is None:
        raise Exception("Termination events not seen on " + dev.ifname)
    if data.get("addr") != peer.wpas.own_addr() or data.get("sa") != sa or \
       data.get("locally_generated") != ("1" if local else "0"):
        raise Exception("Unexpected NAN-CM-TERMINATED on %s: %s" %
                        (dev.ifname, data))
    for key, val in (extra or {}).items():
        if data.get(key) != val:
            raise Exception("Unexpected NAN-CM-TERMINATED on %s: %s" %
                            (dev.ifname, data))
    return data

def run_nan_cm_terminate(test, *capas):
    set_country("US")
    try:
        with hwsim_nan_radios() as (wpas1, wpas2), \
             NanDevice(wpas1, "nan0", "ndi0") as pub, \
             NanDevice(wpas2, "nan1", "ndi1") as sub:
            pid, sid, ndp_id, init_ndi = nan_cm_pair_ndp(pub, sub, *capas)
            pub.wpas.dump_monitor()
            sub.wpas.dump_monitor()
            test(pub, sub, init_ndi)
    finally:
        set_country("00")

def test_nan_cm_terminate_nd_tksa(dev, apdev):
    """NAN Connection Management ND-TKSA termination"""
    def test(pub, sub, init_ndi):
        resp_ndi = pub.dev.get_iface_addr(pub.ndi_name)
        ndis = {"init_ndi": init_ndi, "resp_ndi": resp_ndi}

        if "FAIL" not in sub.wpas.request(
                "NAN_CM_TERMINATE peer_nmi=%s sa=nd_tksa" %
                pub.wpas.own_addr()):
            raise Exception("ND-TKSA termination without NDIs accepted")
        if "FAIL" not in sub.wpas.request(
                "NAN_CM_TERMINATE peer_nmi=%s sa=nd_tksa init_ndi=%s resp_ndi=%s"
                % (pub.wpas.own_addr(), resp_ndi, init_ndi)):
            raise Exception("Termination of an unknown ND-TKSA accepted")

        if "OK" not in sub.wpas.request(
                "NAN_CM_TERMINATE peer_nmi=%s sa=nd_tksa init_ndi=%s resp_ndi=%s"
                % (pub.wpas.own_addr(), init_ndi, resp_ndi)):
            raise Exception("NAN_CM_TERMINATE failed")
        nan_cm_wait_terminated(sub, pub, "nd_tksa", True, ndis, ndp=True)
        nan_cm_wait_terminated(pub, sub, "nd_tksa", False, ndis, ndp=True)

        # The NM-TKSA and keep alive continue without NDPs
        for dev, peer in ((pub, sub), (sub, pub)):
            info = nan_cm_info(dev, peer)
            if info["nm_tksa"] != "1" or info["ka_active"] != "1" or \
               info["npksa"] != "1":
                raise Exception("Unexpected CM state on %s: %s" %
                                (dev.ifname, info))
        if pub.wpas.wait_event(["NAN-CM-TERMINATED"], timeout=11):
            raise Exception("Unexpected termination after ND-TKSA")
    run_nan_cm_terminate(test, "default_ka", "termination_notif")

def test_nan_cm_terminate_nm_tksa(dev, apdev):
    """NAN Connection Management NM-TKSA termination"""
    def test(pub, sub, init_ndi):
        if "OK" not in pub.wpas.request(
                "NAN_CM_TERMINATE peer_nmi=%s sa=nm_tksa" %
                sub.wpas.own_addr()):
            raise Exception("NAN_CM_TERMINATE failed")
        nan_cm_wait_terminated(pub, sub, "nm_tksa", True, ndp=True)
        nan_cm_wait_terminated(sub, pub, "nm_tksa", False, ndp=True)

        for dev, peer in ((pub, sub), (sub, pub)):
            info = nan_cm_info(dev, peer)
            if info["nm_tksa"] != "0" or info["ka_active"] != "0" or \
               info["npksa"] != "1":
                raise Exception("Unexpected CM state on %s: %s" %
                                (dev.ifname, info))

        if "FAIL" not in pub.wpas.request(
                "NAN_CM_TERMINATE peer_nmi=%s sa=nm_tksa" %
                sub.wpas.own_addr()):
            raise Exception("Second NM-TKSA termination accepted")
    run_nan_cm_terminate(test, "termination_notif")

def test_nan_cm_terminate_npksa(dev, apdev):
    """NAN Connection Management NPKSA termination"""
    def test(pub, sub, init_ndi):
        if "OK" not in sub.wpas.request(
                "NAN_CM_TERMINATE peer_nmi=%s sa=npksa" %
                pub.wpas.own_addr()):
            raise Exception("NAN_CM_TERMINATE failed")
        nan_cm_wait_terminated(sub, pub, "npksa", True)
        nan_cm_wait_terminated(pub, sub, "npksa", False)

        # The NM-TKSA and the NDP continue
        for dev, peer in ((pub, sub), (sub, pub)):
            info = nan_cm_info(dev, peer)
            if info["npksa"] != "0" or info["nm_tksa"] != "1" or \
               info["ka_active"] != "1":
                raise Exception("Unexpected CM state on %s: %s" %
                                (dev.ifname, info))
        if pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=1):
            raise Exception("NDP disconnected on NPKSA termination")
        _nan_test_connectivity(pub, sub)
    run_nan_cm_terminate(test, "default_ka", "termination_notif")

def test_nan_cm_keepalive_timeout(dev, apdev):
    """NAN Connection Management keep alive timeout"""
    def test(pub, sub, init_ndi):
        # Stop NAN on the subscriber without notifying the publisher
        sub.wpas.request("NAN_STOP")
        nan_cm_wait_info(pub, sub, "nm_tksa", "0", 20)
        nan_cm_wait_terminated(pub, sub, "nm_tksa", True, ndp=True)
        if nan_cm_info(pub, sub)["ka_active"] != "0":
            raise Exception("Keep alive not stopped")
        sub.wpas.request("NAN_START")
    run_nan_cm_terminate(test, "default_ka")

def test_nan_cm_deauth(dev, apdev):
    """NAN Connection Management Deauthentication and SA Query timeout"""
    def test(pub, sub, init_ndi):
        if "FAIL" not in pub.wpas.request("NAN_CM_DEAUTH peer_nmi=" +
                                          pub.wpas.own_addr()):
            raise Exception("Deauthentication of an unknown peer accepted")
        if "OK" not in pub.wpas.request("NAN_CM_DEAUTH peer_nmi=" +
                                        sub.wpas.own_addr()):
            raise Exception("NAN_CM_DEAUTH failed")
        nan_cm_wait_terminated(pub, sub, "nm_tksa", True, ndp=True)

        # The subscriber gets no response to its protected SA Query
        # Request, so it accepts the Deauthentication.
        nan_cm_wait_terminated(sub, pub, "nm_tksa", False, ndp=True)
        if nan_cm_info(sub, pub)["nm_tksa"] != "0":
            raise Exception("NM-TKSA not deleted on the subscriber")
        if "FAIL" not in pub.wpas.request("NAN_CM_DEAUTH peer_nmi=" +
                                          sub.wpas.own_addr()):
            raise Exception("Deauthentication without NM-TKSA accepted")
    run_nan_cm_terminate(test, "deauth_sa_query")

def test_nan_cm_deauth_sa_query(dev, apdev):
    """NAN Connection Management Deauthentication rejected by SA Query"""
    def test(pub, sub, init_ndi):
        # Send the Deauthentication NAF, but keep the NM-TKSA so that the
        # SA Query Request from the subscriber gets a response.
        if "OK" not in pub.wpas.request(
                "NAN_CM_DEAUTH peer_nmi=%s keep_nm_tksa=1" %
                sub.wpas.own_addr()):
            raise Exception("NAN_CM_DEAUTH failed")
        ev = sub.wpas.wait_event(["NAN-CM-TERMINATED",
                                  "NAN-NDP-DISCONNECTED"], timeout=4)
        if ev is not None:
            raise Exception("Spurious Deauthentication accepted: " + ev)
        for dev, peer in ((pub, sub), (sub, pub)):
            info = nan_cm_info(dev, peer)
            if info["nm_tksa"] != "1" or info["ka_active"] != "1":
                raise Exception("Unexpected CM state on %s: %s" %
                                (dev.ifname, info))
        _nan_test_connectivity(pub, sub)
    run_nan_cm_terminate(test, "default_ka", "deauth_sa_query")

def test_nan_cm_deauth_pik(dev, apdev):
    """NAN Connection Management Deauthentication with PNTag"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
         NanDevice(wpas1, "nan0") as pub, \
         NanDevice(wpas2, "nan1") as sub:
        pkbst_config(pub, 2, self_pkr=PKR_B, self_isk=ISK_B, peer_pkr=PKR_A)
        pkbst_config(sub, 2, self_pkr=PKR_A, self_isk=ISK_A, peer_pkr=PKR_B)
        for dev in (pub, sub):
            dev.set("npk_caching", "1")
            dev.set("pik_caching", "1")
        pid, sid = pkbst_discover_bootstrap(pub, sub, 2)
        run_nan_pairing(sub, pub, pid, sid, "SAE", password="unused")
        nan_cm_check_capa(pub, sub, "deauth_sa_query")
        pub.wpas.dump_monitor()
        sub.wpas.dump_monitor()

        # The Deauthentication NAF carries a PNTag derived from the PIK
        if "OK" not in pub.wpas.request("NAN_CM_DEAUTH peer_nmi=" +
                                        sub.wpas.own_addr()):
            raise Exception("NAN_CM_DEAUTH failed")
        nan_cm_wait_terminated(pub, sub, "nm_tksa", True)
        nan_cm_wait_terminated(sub, pub, "nm_tksa", False)

        # The NPKSA and the PIK remain for pairing verification
        for dev, peer in ((pub, sub), (sub, pub)):
            if nan_cm_info(dev, peer)["npksa"] != "1":
                raise Exception("NPKSA lost on " + dev.ifname)

def nan_cm_wait_rekeyed(dev, peer, ndp_id, init_ndi):
    ev = dev.wpas.wait_event(["NAN-CM-ND-TK-REKEYED", "NAN-NDP-DISCONNECTED",
                              "NAN-NDP-CONNECTED", "NAN-NDP-REQUEST"],
                             timeout=5)
    if ev is None or "NAN-CM-ND-TK-REKEYED" not in ev:
        raise Exception("ND-TK rekey not completed on %s: %s" %
                        (dev.ifname, ev))
    data = split_nan_event(ev)
    if data.get("addr") != peer.wpas.own_addr() or \
       data.get("ndp_id") != str(ndp_id) or \
       data.get("init_ndi") != init_ndi:
        raise Exception("Unexpected rekey event on %s: %s" %
                        (dev.ifname, ev))

def run_nan_cm_rekey(by_initiator):
    def test(pub, sub, init_ndi):
        ndp_id = 1
        if "FAIL" not in sub.wpas.request(
                "NAN_CM_REKEY peer_nmi=%s init_ndi=%s ndp_id=%d" %
                (pub.wpas.own_addr(), init_ndi, ndp_id + 1)):
            raise Exception("Rekey of an unknown NDP accepted")

        # The subscriber is the NDP initiator and sets up the rekey. When
        # requested on the publisher, it sends an ND-TK rekey indication.
        dev, peer = (sub, pub) if by_initiator else (pub, sub)
        for i in range(2):
            if "OK" not in dev.wpas.request(
                    "NAN_CM_REKEY peer_nmi=%s init_ndi=%s ndp_id=%d" %
                    (peer.wpas.own_addr(), init_ndi, ndp_id)):
                raise Exception("NAN_CM_REKEY failed")
            nan_cm_wait_rekeyed(sub, pub, ndp_id, init_ndi)
            nan_cm_wait_rekeyed(pub, sub, ndp_id, init_ndi)
            _nan_test_connectivity(pub, sub)

        for dev, peer in ((pub, sub), (sub, pub)):
            info = nan_cm_info(dev, peer)
            if info["nm_tksa"] != "1" or info["ka_active"] != "1":
                raise Exception("Unexpected CM state on %s: %s" %
                                (dev.ifname, info))

        # The NDP continues over keep alive periods after the rekey
        if pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=11):
            raise Exception("NDP disconnected after ND-TK rekey")
        _nan_ndp_terminate(pub, sub, pub.wpas.own_addr(), init_ndi, ndp_id)
    run_nan_cm_terminate(test, "default_ka", "ndtk_rekey")

def test_nan_cm_rekey_initiator(dev, apdev):
    """NAN Connection Management ND-TK rekey by the NDP initiator"""
    run_nan_cm_rekey(True)

def test_nan_cm_rekey_responder(dev, apdev):
    """NAN Connection Management ND-TK rekey indicated by the NDP responder"""
    run_nan_cm_rekey(False)

def test_nan_cm_rekey_not_supported(dev, apdev):
    """NAN Connection Management ND-TK rekey without peer support"""
    set_country("US")
    try:
        with hwsim_nan_radios() as (wpas1, wpas2), \
             NanDevice(wpas1, "nan0", "ndi0") as pub, \
             NanDevice(wpas2, "nan1", "ndi1") as sub:
            pub.set("ndtk_rekey", "0")
            # The other capabilities are not changed
            pid, sid, ndp_id, init_ndi = nan_cm_pair_ndp(pub, sub,
                                                         "default_ka",
                                                         "deauth_sa_query",
                                                         "termination_notif")
            for dev, peer in ((sub, pub), (pub, sub)):
                info = nan_cm_info(dev, peer)
                if info.get("ndtk_rekey") != "0":
                    raise Exception("ND-TK rekey used on %s: %s" %
                                    (dev.ifname, info))
                if "FAIL" not in dev.wpas.request(
                        "NAN_CM_REKEY peer_nmi=%s init_ndi=%s ndp_id=%s" %
                        (peer.wpas.own_addr(), init_ndi, ndp_id)):
                    raise Exception("Rekey without support accepted")
            _nan_test_connectivity(pub, sub)

            # The peer indicated ND-TK rekey, so it can be used once enabled
            # locally
            pub.set("ndtk_rekey", "1")
            if nan_cm_info(pub, sub).get("ndtk_rekey") != "1":
                raise Exception("ND-TK rekey not enabled again")
    finally:
        set_country("00")

def test_nan_dp_non_overlapping_schedule(dev, apdev, params):
    """NAN NDP rejected when peer schedules never overlap"""
    with hwsim_nan_radios() as (wpas1, wpas2), \
        NanDevice(wpas1, "nan0", "ndi0") as pub, \
        NanDevice(wpas2, "nan1", "ndi1") as sub:

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid, sid, paddr, saddr = _nan_discover_service(
            pub, sub, "test_service", pssi, sssi, data_path=True)

        sub_bitmap = "f0ffffff"
        pub_bitmap = "0e000000"

        if "OK" not in sub.schedule_config((2437, sub_bitmap)):
            raise Exception("Failed to configure schedule (sub)")

        if "OK" not in sub.ndp_request(sub.ndi_name, sid, paddr, pid,
                                       "aabbcc"):
            raise Exception("NDP request failed")

        ev = pub.wpas.wait_event(["NAN-NDP-REQUEST"], timeout=5)
        if ev is None:
            raise Exception("NAN-NDP-REQUEST event not seen")

        data = split_nan_event(ev)
        ndp_id = data['ndp_id']
        init_ndi = data['init_ndi']

        if "OK" not in pub.schedule_config((2437, pub_bitmap)):
            raise Exception("Failed to configure schedule (pub)")

        if "OK" not in pub.ndp_response("accept", saddr, ndi=pub.ndi_name,
                                        ndp_id=ndp_id, init_ndi=init_ndi,
                                        handle=pid, ssi="ddeeff"):
            raise Exception("NDP response (accept) failed")

        ev = sub.wpas.wait_event(["NAN-NDP-COUNTER-REQUEST"], timeout=5)
        if ev is None:
            raise Exception("NAN-NDP-COUNTER-REQUEST event not seen")

        data = split_nan_event(ev)
        ndp_id = data['ndp_id']
        init_ndi = data['init_ndi']

        if "OK" not in sub.ndp_response("accept", paddr, ndi=sub.ndi_name,
                                        ndp_id=ndp_id, init_ndi=init_ndi,
                                        handle=sid, ssi="11223344"):
            raise Exception("NDP response (confirm) failed")

        ev = sub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
        if ev is None or "failure=1" not in ev:
            raise Exception("NDP not rejected on subscriber: %s" % ev)

        ev = pub.wpas.wait_event(["NAN-NDP-DISCONNECTED"], timeout=5)
        if ev is None or "failure=1" not in ev:
            raise Exception("NDP not rejected on publisher: %s" % ev)
