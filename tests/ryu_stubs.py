"""Minimal stand-ins for the parts of Ryu the controller touches.

They let tests/test_controller_glue.py drive the *real* controller class with
fake OpenFlow messages on machines that do not have Ryu installed (CI, laptops).
Only installed when `import ryu` fails. They do NOT validate Ryu's real API.
"""
import logging
import struct
import sys
import types


def install():
    try:
        import ryu  # noqa: F401
        return False
    except ImportError:
        pass

    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        sys.modules[name] = m
        return m

    # -- base / handler / hub ---------------------------------------------
    class RyuApp(object):
        def __init__(self, *a, **k):
            self.logger = logging.getLogger("ryu-stub")

    mod("ryu")
    mod("ryu.base")
    mod("ryu.base.app_manager", RyuApp=RyuApp)
    mod("ryu.controller")

    class _Ev(object):
        def __init__(self, msg):
            self.msg = msg

    mod("ryu.controller.ofp_event", EventOFPSwitchFeatures=type("F", (_Ev,), {}),
        EventOFPPacketIn=type("P", (_Ev,), {}), EventOFPBarrierReply=type("B", (_Ev,), {}),
        EventOFPFlowRemoved=type("R", (_Ev,), {}))
    mod("ryu.controller.handler", CONFIG_DISPATCHER="config", MAIN_DISPATCHER="main",
        set_ev_cls=lambda ev, disp=None: (lambda fn: fn))
    mod("ryu.lib")
    mod("ryu.lib.hub", spawn=lambda fn, *a, **k: None, sleep=lambda s: None)

    # -- packet library -----------------------------------------------------
    class ethernet_(object):
        def __init__(self, dst, src, ethertype):
            self.dst, self.src, self.ethertype = dst, src, ethertype

    class ipv4_(object):
        def __init__(self, src, dst, proto):
            self.src, self.dst, self.proto = src, dst, proto

    class tcp_(object):
        def __init__(self, sp, dp):
            self.src_port, self.dst_port = sp, dp

    class udp_(object):
        def __init__(self, sp, dp):
            self.src_port, self.dst_port = sp, dp

    def mac(b):
        return ":".join("%02x" % x for x in b)

    def ip(b):
        return ".".join(str(x) for x in b)

    class Packet(object):
        def __init__(self, data):
            self.p = {}
            dst, src, et = data[0:6], data[6:12], struct.unpack("!H", data[12:14])[0]
            self.p[ethernet_] = ethernet_(mac(dst), mac(src), et)
            if et == 0x0800:
                ihl = (data[14] & 0x0F) * 4
                proto = data[23]
                self.p[ipv4_] = ipv4_(ip(data[26:30]), ip(data[30:34]), proto)
                l4 = data[14 + ihl:]
                if proto in (6, 17) and len(l4) >= 4:
                    sp, dp = struct.unpack("!HH", l4[:4])
                    self.p[tcp_ if proto == 6 else udp_] = (tcp_ if proto == 6 else udp_)(sp, dp)

        def get_protocol(self, cls):
            return self.p.get(cls)

    mod("ryu.lib.packet")
    mod("ryu.lib.packet.ether_types", ETH_TYPE_IP=0x0800, ETH_TYPE_ARP=0x0806, ETH_TYPE_LLDP=0x88CC)
    mod("ryu.lib.packet.in_proto", IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1)
    mod("ryu.lib.packet.ethernet", ethernet=ethernet_)
    mod("ryu.lib.packet.ipv4", ipv4=ipv4_)
    mod("ryu.lib.packet.tcp", tcp=tcp_)
    mod("ryu.lib.packet.udp", udp=udp_)
    mod("ryu.lib.packet.packet", Packet=Packet)
    pk = sys.modules["ryu.lib.packet"]
    for n in ("ether_types", "in_proto", "ethernet", "ipv4", "tcp", "udp", "packet"):
        setattr(pk, n, sys.modules["ryu.lib.packet." + n])
    mod("ryu.ofproto")
    mod("ryu.ofproto.ofproto_v1_3", OFP_VERSION=4)
    return True


# -- fake OpenFlow datapath ---------------------------------------------------
class Ofp(object):
    OFPP_NORMAL, OFPP_CONTROLLER, OFPP_FLOOD, OFPP_ANY = 0xFFFFFFFA, 0xFFFFFFFD, 0xFFFFFFFB, 0xFFFFFFFF
    OFPCML_NO_BUFFER, OFPTT_ALL, OFPFC_DELETE, OFPG_ANY = 0xFFFF, 0xFF, 3, 0xFFFFFFFF
    OFPIT_APPLY_ACTIONS, OFP_NO_BUFFER, OFPFF_SEND_FLOW_REM = 4, 0xFFFFFFFF, 1


class Msg(object):
    def __init__(self, **kw):
        self.xid = None
        self.__dict__.update(kw)


class Match(dict):
    pass


class Parser(object):
    OFPMatch = Match

    @staticmethod
    def OFPFlowMod(**kw):
        kw.setdefault("command", 0)
        kw.setdefault("priority", 0)
        kw.setdefault("instructions", [])
        kw.setdefault("hard_timeout", 0)
        kw.setdefault("idle_timeout", 0)
        kw.setdefault("flags", 0)
        kw.setdefault("cookie", 0)
        return Msg(kind="flow_mod", **kw)

    @staticmethod
    def OFPActionOutput(port, max_len=0):
        return ("output", port)

    @staticmethod
    def OFPInstructionActions(typ, actions):
        return ("apply", actions)

    @staticmethod
    def OFPPacketOut(**kw):
        return Msg(kind="packet_out", **kw)

    @staticmethod
    def OFPBarrierRequest(dp):
        return Msg(kind="barrier")


class FakeDatapath(object):
    ofproto, ofproto_parser = Ofp, Parser

    def __init__(self, dpid):
        self.id, self.sent, self._xid = dpid, [], 100

    def send_msg(self, msg):
        if msg.xid is None:
            self._xid += 1
            msg.xid = self._xid
        self.sent.append(msg)

    # helpers for assertions
    def flows(self, **want):
        out = []
        for m in self.sent:
            if getattr(m, "kind", "") != "flow_mod":
                continue
            if all(getattr(m, k, None) == v for k, v in want.items()):
                out.append(m)
        return out

    def packet_outs(self):
        return [m for m in self.sent if getattr(m, "kind", "") == "packet_out"]

    def clear(self):
        self.sent[:] = []


# -- raw frame builders -----------------------------------------------------------
def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def _ip(s):
    return bytes(int(x) for x in s.split("."))


def eth_frame(src, dst, ethertype, payload=b""):
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def ip_packet(src_mac, dst_mac, src_ip, dst_ip, proto, l4=b""):
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, _ip(src_ip), _ip(dst_ip))
    return eth_frame(src_mac, dst_mac, 0x0800, hdr + l4)


def tcp_packet(src_mac, dst_mac, src_ip, dst_ip, sport, dport):
    l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x02, 8192, 0, 0)
    return ip_packet(src_mac, dst_mac, src_ip, dst_ip, 6, l4)


def icmp_packet(src_mac, dst_mac, src_ip, dst_ip):
    return ip_packet(src_mac, dst_mac, src_ip, dst_ip, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1))


def arp_frame(src_mac, dst_mac):
    return eth_frame(src_mac, dst_mac, 0x0806, b"\x00" * 28)
