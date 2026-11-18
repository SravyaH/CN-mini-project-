"""Firewall decision engine (no OpenFlow, no sockets).

The Ryu application is a thin adapter around this class: it turns packet-ins
into PacketInfo objects, asks the engine what to do, and translates the answer
into flow-mods. Keeping the logic here makes it testable without Mininet.
"""
import collections
import time

from common.protocol import make_event


class PacketInfo(object):
    __slots__ = ("eth_src", "eth_dst", "ip_src", "ip_dst", "proto", "sport", "dport")

    def __init__(self, eth_src, eth_dst, ip_src, ip_dst, proto, sport=0, dport=0):
        self.eth_src, self.eth_dst = eth_src, eth_dst
        self.ip_src, self.ip_dst = ip_src, ip_dst
        self.proto, self.sport, self.dport = proto, sport, dport


class BlockInfo(object):
    def __init__(self, ip, mac, dpid, in_port, duration, first_violation_ts, decision_ts):
        self.ip, self.mac, self.dpid, self.in_port = ip, mac, dpid, in_port
        self.duration = duration
        self.first_violation_ts = first_violation_ts
        self.decision_ts = decision_ts
        self.until = decision_ts + duration


class Decision(object):
    """What the adapter must do for one packet-in."""

    def __init__(self, action, events=None, forward=False, install_reverse=False, block=None):
        self.action = action              # allow | reply | deny | block | ignored
        self.events = events or []        # security events to ship to the logger
        self.forward = forward            # forward the triggering packet
        self.install_reverse = install_reverse
        self.block = block                # BlockInfo when action == 'block'


class EscalationTracker(object):
    """Sliding-window counter of denied attempts per source IP."""

    def __init__(self, threshold=5, window=10.0):
        self.threshold, self.window = threshold, window
        self._hits = collections.defaultdict(collections.deque)

    def record(self, src, now):
        q = self._hits[src]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q), q[0]

    def reset(self, src):
        self._hits.pop(src, None)

    def count(self, src):
        return len(self._hits.get(src, ()))


class FirewallEngine(object):
    def __init__(self, policy, threshold=5, window=10.0, block_time=20.0,
                 expire_grace=3.0, clock=time.time):
        self.policy = policy
        self.tracker = EscalationTracker(threshold, window)
        self.block_time = block_time
        self.expire_grace = expire_grace
        self.clock = clock
        self.blocked = {}
        self.counters = collections.Counter()

    # ------------------------------------------------------------------
    def is_blocked(self, ip):
        return ip in self.blocked

    def classify(self, dpid, in_port, p):
        now = self.clock()
        if p.ip_src in self.blocked:
            # raced the block flow-mod; the switch will drop the rest
            self.counters["ignored"] += 1
            return Decision("ignored")

        action, rule = self.policy.lookup(p.ip_src, p.ip_dst, p.proto, p.dport)

        # Return traffic of an allowed TCP service (server -> client) has no
        # rule of its own; recognise it by checking the forward direction.
        if rule is None and p.proto == "tcp":
            r_action, r_rule = self.policy.lookup(p.ip_dst, p.ip_src, "tcp", p.sport)
            if r_rule is not None and r_action == "allow":
                self.counters["reply"] += 1
                return Decision("reply", forward=True)

        note = rule.note if rule is not None else "default policy"
        if action == "allow":
            self.counters["allow"] += 1
            ev = make_event("RULE_ADDED", p.ip_src, p.ip_dst, p.dport, "allow", ts=now,
                            dpid=dpid, proto=p.proto, sport=p.sport, rule=note)
            return Decision("allow", [ev], forward=True, install_reverse=True)

        # ---- deny ------------------------------------------------------
        self.counters["deny"] += 1
        events = [make_event("RULE_ADDED", p.ip_src, p.ip_dst, p.dport, "deny", ts=now,
                             dpid=dpid, proto=p.proto, sport=p.sport, rule=note)]
        count, first_ts = self.tracker.record(p.ip_src, now)
        if count < self.tracker.threshold:
            return Decision("deny", events)

        # ---- escalate to block ----------------------------------------
        self.counters["block"] += 1
        self.tracker.reset(p.ip_src)
        info = BlockInfo(p.ip_src, p.eth_src, dpid, in_port, self.block_time, first_ts, now)
        self.blocked[p.ip_src] = info
        events.append(make_event(
            "RULE_ESCALATED", p.ip_src, "*", 0, "block", ts=now, dpid=dpid,
            violations=count, window_s=self.tracker.window, block_time_s=self.block_time,
            first_violation_ts=round(first_ts, 6),
            detection_ms=round((now - first_ts) * 1000.0, 3)))
        return Decision("block", events, block=info)

    # ------------------------------------------------------------------
    def block_active_event(self, info, active_ts):
        """Event emitted once the drop rule is confirmed active in the switch."""
        return make_event(
            "CONTROLLER", info.ip, "*", 0, "info", ts=active_ts, dpid=info.dpid,
            what="block_active",
            response_ms=round((active_ts - info.first_violation_ts) * 1000.0, 3),
            install_ms=round((active_ts - info.decision_ts) * 1000.0, 3))

    def unblock(self, ip, reason="timeout", dropped_packets=None):
        info = self.blocked.pop(ip, None)
        if info is None:
            return None
        self.tracker.reset(ip)
        self.counters["unblock"] += 1
        now = self.clock()
        extra = {"reason": reason, "blocked_for_s": round(now - info.decision_ts, 3)}
        if dropped_packets is not None:
            extra["dropped_packets"] = dropped_packets
        return make_event("RULE_EXPIRED", ip, "*", 0, "unblock", ts=now, dpid=info.dpid, **extra)

    def expire(self):
        """Safety net if a FlowRemoved message was lost. Returns unblock events."""
        now = self.clock()
        events = []
        for ip, info in list(self.blocked.items()):
            if now >= info.until + self.expire_grace:
                ev = self.unblock(ip, reason="timeout_fallback")
                if ev:
                    events.append((info, ev))
        return events
