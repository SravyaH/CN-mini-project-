"""Policy table: (src, dst, proto, port) -> allow | deny.

Pure Python, no SDN dependencies, so it is unit-testable and reused by the
controller (dynamic mode), the static-ACL compiler and the documentation.
"""
import ipaddress
import json

VALID_ACTIONS = ("allow", "deny")
VALID_PROTOS = ("tcp", "udp", "icmp", "*")


def _net(value, field):
    if value == "*":
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError("policy %s %r is not an IP address / CIDR / '*'" % (field, value))


class Rule(object):
    def __init__(self, src, dst, proto, port, action, note=""):
        if action not in VALID_ACTIONS:
            raise ValueError("policy action must be one of %s, got %r" % (VALID_ACTIONS, action))
        proto = str(proto).lower()
        if proto not in VALID_PROTOS:
            raise ValueError("policy proto must be one of %s, got %r" % (VALID_PROTOS, proto))
        if port in ("*", "-", None, 0):
            port = "*"
        else:
            try:
                port = int(port)
            except (TypeError, ValueError):
                raise ValueError("policy port must be an integer or '*', got %r" % (port,))
            if not 1 <= port <= 65535:
                raise ValueError("policy port out of range: %r" % port)
        self.src, self.dst, self.proto, self.port = src, dst, proto, port
        self.action, self.note = action, note
        self.src_net, self.dst_net = _net(src, "src"), _net(dst, "dst")

    # ------------------------------------------------------------------
    @staticmethod
    def _addr_match(net, ip):
        return net is None or ipaddress.ip_address(ip) in net

    @staticmethod
    def _addr_score(net):
        if net is None:
            return 0
        return 1 if net.prefixlen < net.max_prefixlen else 2

    def matches(self, src, dst, proto, port):
        if self.proto not in ("*", proto):
            return False
        if self.port != "*" and self.port != port:
            return False
        return self._addr_match(self.src_net, src) and self._addr_match(self.dst_net, dst)

    def specificity(self):
        return (self._addr_score(self.src_net) + self._addr_score(self.dst_net)
                + (1 if self.port != "*" else 0) + (1 if self.proto != "*" else 0))

    def as_tuple(self):
        return (self.src, self.dst, self.proto, self.port, self.action)

    def __repr__(self):
        return "Rule(%s -> %s %s/%s %s)" % (self.src, self.dst, self.proto, self.port, self.action)


class PolicyTable(object):
    def __init__(self, rules, default_action="deny"):
        if default_action not in VALID_ACTIONS:
            raise ValueError("default_action must be allow or deny")
        self.rules = list(rules)
        self.default_action = default_action

    @classmethod
    def from_dict(cls, data):
        rules = []
        for i, r in enumerate(data.get("rules", [])):
            try:
                rules.append(Rule(r["src"], r["dst"], r.get("proto", "tcp"),
                                  r.get("port", "*"), r["action"], r.get("note", "")))
            except KeyError as exc:
                raise ValueError("policy rule #%d is missing %s" % (i, exc))
        return cls(rules, data.get("default_action", "deny"))

    @classmethod
    def from_file(cls, path):
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    def lookup(self, src, dst, proto, port):
        """Return (action, rule). rule is None when the default applied.

        The most specific matching rule wins; on a tie an earlier rule wins and,
        failing that, 'deny' beats 'allow' (fail closed).
        """
        best, best_key = None, None
        for idx, rule in enumerate(self.rules):
            if not rule.matches(src, dst, proto, port):
                continue
            key = (rule.specificity(), 1 if rule.action == "deny" else 0, -idx)
            if best_key is None or key > best_key:
                best, best_key = rule, key
        if best is None:
            return self.default_action, None
        return best.action, best

    def table(self):
        """Rows for documentation: (src, dst, proto, port, action)."""
        rows = [r.as_tuple() for r in self.rules]
        rows.append(("*", "*", "*", "*", self.default_action + " (default)"))
        return rows
