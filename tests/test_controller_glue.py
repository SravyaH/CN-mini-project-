"""Drives the real FirewallController class with fake OpenFlow messages.

Uses tests/ryu_stubs.py when Ryu is not installed. This verifies OUR code path
(packet-in -> engine -> flow-mods -> events -> flow-removed) and the exact flow
priorities/timeouts; it cannot verify Ryu/OVS API behaviour itself.
"""
import importlib
import os
import sys
import types
import unittest

from tests import ryu_stubs as S

S.install()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
fc = importlib.import_module("controller.firewall_controller")

H = {1: "00:00:00:00:00:01", 2: "00:00:00:00:00:02", 3: "00:00:00:00:00:03"}
SRV_MAC = "00:00:00:00:00:0a"
IP = {1: "10.0.0.1", 2: "10.0.0.2", 3: "10.0.0.3"}
SRV = "10.0.0.10"
UPLINK = 4
NORMAL = ("apply", [("output", S.Ofp.OFPP_NORMAL)])


class Ev(object):
    def __init__(self, msg):
        self.msg = msg


def make(mode="dynamic", **env):
    for k in ("FW_THRESHOLD", "FW_BLOCK_TIME", "FW_WINDOW"):
        os.environ.pop(k, None)
    os.environ.update({"FW_MODE": mode, "FW_THRESHOLD": "5", "FW_BLOCK_TIME": "20", "FW_WINDOW": "10"})
    os.environ.update(env)
    ctrl = fc.FirewallController()
    events = []
    ctrl.sender = types.SimpleNamespace(send=events.append, start=lambda: None)
    s1, s2 = S.FakeDatapath(1), S.FakeDatapath(2)
    for dp in (s1, s2):
        ctrl._switch_features(Ev(S.Msg(datapath=dp)))
    return ctrl, s1, s2, events


def packet_in(ctrl, dp, port, data):
    msg = S.Msg(datapath=dp, match={"in_port": port}, data=data, buffer_id=S.Ofp.OFP_NO_BUFFER)
    ctrl._packet_in(Ev(msg))


def syn(src, sport, dport, dst=SRV, dst_mac=SRV_MAC):
    return S.tcp_packet(H[src], dst_mac, IP[src], dst, sport, dport)


class DynamicTests(unittest.TestCase):
    def setUp(self):
        self.ctrl, self.s1, self.s2, self.events = make()
        packet_in(self.ctrl, self.s1, UPLINK, S.arp_frame(SRV_MAC, H[1]))       # learn the server
        for i in (1, 2, 3):
            packet_in(self.ctrl, self.s1, i, S.arp_frame(H[i], "ff:ff:ff:ff:ff:ff"))
        self.s1.clear()
        self.events[:] = []

    def adds(self, dp=None, **want):
        return (dp or self.s1).flows(command=0, **want)

    def test_bringup(self):
        ctrl, s1, s2, _ = make()
        self.assertEqual(len(s1.flows(command=3, table_id=S.Ofp.OFPTT_ALL)), 1)
        miss = s1.flows(command=0, priority=0)
        self.assertEqual(miss[0].instructions, [("apply", [("output", S.Ofp.OFPP_CONTROLLER)])])
        self.assertEqual(len(s2.flows(command=0, priority=0)), 1)

    def test_arp_is_forwarded_without_flows(self):
        packet_in(self.ctrl, self.s1, 1, S.arp_frame(H[1], SRV_MAC))
        self.assertEqual(self.adds(), [])
        self.assertEqual(self.s1.packet_outs()[0].actions, [("output", UPLINK)])

    def test_allowed_client_gets_forward_and_reverse_flows(self):
        packet_in(self.ctrl, self.s1, 1, syn(1, 40000, 5000))
        fl = self.adds(priority=fc.PRIO_ALLOW)
        self.assertEqual(len(fl), 2)
        fwd = [f for f in fl if "tcp_dst" in f.match][0]
        rev = [f for f in fl if "tcp_src" in f.match][0]
        self.assertEqual(dict(fwd.match), {"eth_type": 0x800, "ipv4_src": IP[1], "ipv4_dst": SRV,
                                           "ip_proto": 6, "tcp_dst": 5000})
        self.assertEqual(fwd.instructions, [("apply", [("output", UPLINK)])])
        self.assertEqual(dict(rev.match), {"eth_type": 0x800, "ipv4_src": SRV, "ipv4_dst": IP[1],
                                           "ip_proto": 6, "tcp_src": 5000})
        self.assertEqual(rev.instructions, [("apply", [("output", 1)])])
        self.assertEqual((fwd.idle_timeout, fwd.hard_timeout), (30, 0))
        self.assertEqual(self.s1.packet_outs()[0].actions, [("output", UPLINK)])
        self.assertEqual([(e["type"], e["action"], e["port"]) for e in self.events],
                         [("RULE_ADDED", "allow", 5000)])

    def test_reply_traffic_without_existing_flow(self):
        packet_in(self.ctrl, self.s1, UPLINK, S.tcp_packet(SRV_MAC, H[1], SRV, IP[1], 5000, 40000))
        fl = self.adds(priority=fc.PRIO_ALLOW)
        self.assertEqual(len(fl), 1)
        self.assertEqual(dict(fl[0].match)["tcp_src"], 5000)
        self.assertEqual(fl[0].instructions, [("apply", [("output", 1)])])
        self.assertEqual(self.events, [])

    def test_forbidden_port_is_dropped_and_logged(self):
        packet_in(self.ctrl, self.s1, 3, syn(3, 41000, 5001))
        fl = self.adds(priority=fc.PRIO_DENY)
        self.assertEqual(len(fl), 1)
        self.assertEqual(fl[0].instructions, [])                      # drop
        self.assertEqual((fl[0].idle_timeout, dict(fl[0].match)["tcp_dst"], dict(fl[0].match)["tcp_src"]),
                         (5, 5001, 41000))
        self.assertEqual(self.s1.packet_outs(), [])                   # packet not forwarded
        self.assertEqual([(e["action"], e["port"]) for e in self.events], [("deny", 5001)])

    def test_per_source_classification(self):
        packet_in(self.ctrl, self.s1, 2, syn(2, 40001, 5002))
        packet_in(self.ctrl, self.s1, 1, syn(1, 40002, 5002))
        self.assertEqual([e["action"] for e in self.events], ["allow", "deny"])

    def test_full_attack_lifecycle(self):
        for i in range(5):
            packet_in(self.ctrl, self.s1, 3, syn(3, 42000 + i, 5001))
        # 4 deny drop flows, then the block replaces them
        self.assertEqual(len(self.adds(priority=fc.PRIO_DENY)), 4)
        block = self.adds(priority=fc.PRIO_BLOCK)
        self.assertEqual(len(block), 1)
        b = block[0]
        self.assertEqual(dict(b.match), {"in_port": 3, "eth_src": H[3]})
        self.assertEqual((b.instructions, b.hard_timeout, b.cookie, b.flags),
                         ([], 20, fc.COOKIE_BLOCK, S.Ofp.OFPFF_SEND_FLOW_REM))
        cleanup = self.s1.flows(command=3)
        self.assertEqual(dict(cleanup[0].match), {"eth_type": 0x800, "ipv4_src": IP[3]})
        barriers = [m for m in self.s1.sent if m.kind == "barrier"]
        self.assertEqual(len(barriers), 1)
        self.assertEqual([e["action"] for e in self.events], ["deny"] * 5 + ["block"])
        self.assertTrue(self.ctrl.engine.is_blocked(IP[3]))

        # switch confirms the rule -> response time event
        self.ctrl._barrier_reply(Ev(S.Msg(datapath=self.s1, xid=barriers[0].xid)))
        info = self.events[-1]
        self.assertEqual((info["type"], info["action"], info["detail"]["what"]), ("CONTROLLER", "info", "block_active"))
        self.assertGreaterEqual(info["detail"]["response_ms"], 0)

        # legitimate client unaffected while h3 is blocked
        self.s1.clear()
        packet_in(self.ctrl, self.s1, 1, syn(1, 40010, 5000))
        self.assertEqual(len(self.adds(priority=fc.PRIO_ALLOW)), 2)
        # blocked host racing the drop rule produces nothing
        packet_in(self.ctrl, self.s1, 3, syn(3, 42100, 5000))
        self.assertEqual(len(self.adds(priority=fc.PRIO_ALLOW)), 2)

        # hard timeout fires in the switch -> recovery
        n = len(self.events)
        self.ctrl._flow_removed(Ev(S.Msg(datapath=self.s1, cookie=fc.COOKIE_BLOCK,
                                         match={"eth_src": H[3]}, packet_count=77)))
        rec = self.events[n]
        self.assertEqual((rec["type"], rec["action"], rec["detail"]["dropped_packets"]),
                         ("RULE_EXPIRED", "unblock", 77))
        self.s1.clear()
        packet_in(self.ctrl, self.s1, 3, syn(3, 42200, 5000))
        self.assertEqual(len(self.adds(priority=fc.PRIO_ALLOW)), 2)       # recovered

    def test_other_cookies_in_flow_removed_are_ignored(self):
        self.ctrl._flow_removed(Ev(S.Msg(datapath=self.s1, cookie=fc.COOKIE_ALLOW,
                                         match={"eth_src": H[1]}, packet_count=1)))
        self.assertEqual(self.events, [])

    def test_icmp_and_group_addresses(self):
        packet_in(self.ctrl, self.s1, 2, S.arp_frame(H[2], H[1]))
        self.s1.clear()
        self.events[:] = []
        packet_in(self.ctrl, self.s1, 1, S.icmp_packet(H[1], H[2], IP[1], IP[2]))
        icmp_flows = self.adds(priority=fc.PRIO_ALLOW)
        self.assertEqual(len(icmp_flows), 2)
        self.assertTrue(all(dict(f.match)["ip_proto"] == 1 for f in icmp_flows))
        self.s1.clear()
        self.events[:] = []
        packet_in(self.ctrl, self.s1, 1, S.ip_packet(H[1], "01:00:5e:00:00:fb", IP[1], "224.0.0.251", 17,
                                                      b"\x14\xe9\x14\xe9\x00\x08\x00\x00"))
        self.assertEqual((self.adds(), self.events), ([], []))
        self.assertEqual(self.s1.packet_outs()[0].actions, [("output", S.Ofp.OFPP_FLOOD)])

    def test_core_switch_is_plain_learning_switch(self):
        packet_in(self.ctrl, self.s2, 1, S.arp_frame(SRV_MAC, H[1]))     # learn srv on port 1
        self.s2.clear()
        packet_in(self.ctrl, self.s2, 2, syn(1, 40000, 5001))             # even 'denied' traffic is not s2's job
        fl = self.adds(self.s2, priority=fc.PRIO_L2)
        self.assertEqual(dict(fl[0].match), {"eth_dst": SRV_MAC})
        self.assertEqual(fl[0].instructions, [("apply", [("output", 1)])])
        self.s2.clear()
        packet_in(self.ctrl, self.s2, 1, S.arp_frame(SRV_MAC, "00:00:00:00:00:77"))   # unknown dst
        self.assertEqual(self.adds(self.s2), [])
        self.assertEqual(self.s2.packet_outs()[0].actions, [("output", S.Ofp.OFPP_FLOOD)])


class OtherModeTests(unittest.TestCase):
    def test_static_acl_compiled_once(self):
        ctrl, s1, s2, events = make("static")
        adds = s1.flows(command=0)
        miss = [f for f in adds if f.priority == 0]
        self.assertEqual(miss[0].instructions, [])                      # default drop, no controller
        self.assertFalse(any(("output", S.Ofp.OFPP_CONTROLLER) in a[1] for f in adds for a in f.instructions))
        allow = [f for f in adds if dict(f.match).get("tcp_dst") == 5000]
        deny = [f for f in adds if dict(f.match).get("tcp_dst") == 5001]
        self.assertEqual(allow[0].instructions, [NORMAL])
        self.assertEqual(deny[0].instructions, [])
        self.assertTrue(any(dict(f.match).get("tcp_src") == 5000 and f.instructions == [NORMAL] for f in adds))
        only_h2 = [f for f in adds if dict(f.match).get("tcp_dst") == 5002]
        self.assertEqual([dict(f.match)["ipv4_src"] for f in only_h2], [IP[2]])
        self.assertTrue(any(dict(f.match).get("ip_proto") == 1 for f in adds))       # icmp
        self.assertTrue(any(dict(f.match) == {"eth_type": 0x806} for f in adds))      # arp
        self.assertEqual([f.priority for f in s2.flows(command=0)], [1])               # core = NORMAL
        self.assertEqual(events, [])

    def test_nofw_is_plain_normal(self):
        ctrl, s1, s2, events = make("nofw")
        for dp in (s1, s2):
            fl = dp.flows(command=0)
            self.assertEqual([(f.priority, f.instructions) for f in fl], [(1, [NORMAL])])

    def test_bad_mode_rejected(self):
        os.environ["FW_MODE"] = "turbo"
        with self.assertRaises(ValueError):
            fc.FirewallController()
        os.environ["FW_MODE"] = "dynamic"


if __name__ == "__main__":
    unittest.main()
