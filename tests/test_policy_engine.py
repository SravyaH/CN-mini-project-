import os
import unittest

from common.engine import FirewallEngine, PacketInfo
from common.policy import PolicyTable, Rule

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRV, LOG = "10.0.0.10", "10.0.0.100"


class Clock(object):
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def tcp(src, dst, dport, sport=40000):
    n = int(src.split(".")[-1])
    return PacketInfo("00:00:00:00:00:%02x" % n, "00:00:00:00:00:0a", src, dst, "tcp", sport, dport)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = PolicyTable.from_file(os.path.join(ROOT, "policy.json"))

    def test_policy_table(self):
        L = self.p.lookup
        self.assertEqual(L("10.0.0.1", SRV, "tcp", 5000)[0], "allow")
        self.assertEqual(L("10.0.0.3", SRV, "tcp", 5000)[0], "allow")
        self.assertEqual(L("10.0.0.1", SRV, "tcp", 5001)[0], "deny")       # explicit deny
        self.assertEqual(L("10.0.0.2", SRV, "tcp", 5002)[0], "allow")      # h2 only
        self.assertEqual(L("10.0.0.1", SRV, "tcp", 5002), ("deny", None))  # per-source
        self.assertEqual(L("10.0.0.1", SRV, "tcp", 22), ("deny", None))    # default
        self.assertEqual(L("10.0.0.1", LOG, "tcp", 9999)[0], "deny")
        self.assertEqual(L("10.0.0.1", "10.0.0.2", "icmp", 0)[0], "allow")
        self.assertEqual(L("10.0.0.1", SRV, "udp", 5000)[0], "deny")

    def test_specificity_and_fail_closed(self):
        t = PolicyTable([Rule("10.0.0.0/24", SRV, "tcp", 80, "deny"),
                         Rule("10.0.0.7", SRV, "tcp", 80, "allow")])
        self.assertEqual(t.lookup("10.0.0.7", SRV, "tcp", 80)[0], "allow")   # exact beats CIDR
        self.assertEqual(t.lookup("10.0.0.8", SRV, "tcp", 80)[0], "deny")
        tie = PolicyTable([Rule("*", "*", "tcp", 80, "allow"), Rule("*", "*", "tcp", 80, "deny")],
                          default_action="allow")
        self.assertEqual(tie.lookup("1.1.1.1", "2.2.2.2", "tcp", 80)[0], "deny")

    def test_bad_policy_rejected(self):
        for rule in [lambda: Rule("*", "*", "tcp", 80, "maybe"),
                     lambda: Rule("not-an-ip", "*", "tcp", 80, "allow"),
                     lambda: Rule("*", "*", "sctp", 80, "allow"),
                     lambda: Rule("*", "*", "tcp", 99999, "allow")]:
            with self.assertRaises(ValueError):
                rule()


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.clk = Clock()
        pol = PolicyTable.from_file(os.path.join(ROOT, "policy.json"))
        self.e = FirewallEngine(pol, threshold=5, window=10, block_time=20, clock=self.clk)

    def test_allow_installs_reverse_and_logs(self):
        d = self.e.classify(1, 1, tcp("10.0.0.1", SRV, 5000))
        self.assertEqual((d.action, d.forward, d.install_reverse), ("allow", True, True))
        ev = d.events[0]
        self.assertEqual((ev["type"], ev["action"], ev["port"]), ("RULE_ADDED", "allow", 5000))

    def test_reply_traffic_recognised(self):
        d = self.e.classify(1, 6, tcp(SRV, "10.0.0.1", 40000, sport=5000))
        self.assertEqual((d.action, d.forward, d.events), ("reply", True, []))
        # the admin port never gets a reply path
        d = self.e.classify(1, 6, tcp(SRV, "10.0.0.1", 40000, sport=5001))
        self.assertEqual(d.action, "deny")

    def test_deny_then_escalate_on_fifth(self):
        actions = []
        for i in range(5):
            d = self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5001, sport=41000 + i))
            actions.append(d.action)
            self.clk.advance(0.1)
        self.assertEqual(actions, ["deny"] * 4 + ["block"])
        self.assertTrue(self.e.is_blocked("10.0.0.3"))
        block = d.block
        self.assertEqual((block.ip, block.in_port, block.duration), ("10.0.0.3", 3, 20))
        types = [(e["type"], e["action"]) for e in d.events]
        self.assertEqual(types, [("RULE_ADDED", "deny"), ("RULE_ESCALATED", "block")])
        esc = d.events[1]
        self.assertEqual(esc["detail"]["violations"], 5)
        self.assertAlmostEqual(esc["detail"]["detection_ms"], 400, delta=1)

    def test_attacker_isolated_from_legit_clients(self):
        for i in range(5):
            self.e.classify(1, 3, tcp("10.0.0.3", SRV, 22 + i, sport=42000 + i))   # port sweep
        self.assertTrue(self.e.is_blocked("10.0.0.3"))
        d = self.e.classify(1, 1, tcp("10.0.0.1", SRV, 5000))
        self.assertEqual(d.action, "allow")
        self.assertFalse(self.e.is_blocked("10.0.0.1"))
        self.assertEqual(self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5000)).action, "ignored")

    def test_slow_probing_does_not_escalate(self):
        for i in range(12):
            d = self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5001, sport=43000 + i))
            self.assertEqual(d.action, "deny")
            self.clk.advance(3.0)                       # 4 hits per 10 s window < 5
        self.assertFalse(self.e.is_blocked("10.0.0.3"))

    def test_unblock_resets_state_and_logs_recovery(self):
        for i in range(5):
            self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5001, sport=44000 + i))
        self.clk.advance(20)
        ev = self.e.unblock("10.0.0.3", dropped_packets=123)
        self.assertEqual((ev["type"], ev["action"]), ("RULE_EXPIRED", "unblock"))
        self.assertEqual(ev["detail"]["dropped_packets"], 123)
        self.assertAlmostEqual(ev["detail"]["blocked_for_s"], 20, delta=0.01)
        self.assertIsNone(self.e.unblock("10.0.0.3"))              # idempotent
        # counting starts from zero again: 4 denies are not enough
        for i in range(4):
            self.assertEqual(self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5001, sport=45000 + i)).action, "deny")
        self.assertEqual(self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5000)).action, "allow")

    def test_expire_fallback_after_grace(self):
        for i in range(5):
            self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5001, sport=46000 + i))
        self.clk.advance(20 + 1)
        self.assertEqual(self.e.expire(), [])                      # still inside grace
        self.clk.advance(3)
        out = self.e.expire()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][1]["detail"]["reason"], "timeout_fallback")
        self.assertFalse(self.e.is_blocked("10.0.0.3"))

    def test_block_active_event_reports_response_time(self):
        for i in range(5):
            d = self.e.classify(1, 3, tcp("10.0.0.3", SRV, 5001, sport=47000 + i))
            self.clk.advance(0.05)
        ev = self.e.block_active_event(d.block, d.block.decision_ts + 0.002)
        self.assertEqual(ev["detail"]["what"], "block_active")
        self.assertAlmostEqual(ev["detail"]["install_ms"], 2, delta=0.01)
        self.assertAlmostEqual(ev["detail"]["response_ms"], 202, delta=0.5)

    def test_per_source_classification(self):
        self.assertEqual(self.e.classify(1, 2, tcp("10.0.0.2", SRV, 5002)).action, "allow")
        self.assertEqual(self.e.classify(1, 1, tcp("10.0.0.1", SRV, 5002)).action, "deny")

    def test_icmp_allowed(self):
        p = PacketInfo("00:00:00:00:00:01", "00:00:00:00:00:02", "10.0.0.1", "10.0.0.2", "icmp")
        self.assertEqual(self.e.classify(1, 1, p).action, "allow")


if __name__ == "__main__":
    unittest.main()
