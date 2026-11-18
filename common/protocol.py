"""Wire formats shared by the application, the controller and the logger.

Two small, line-oriented protocols (UTF-8, '\n' terminated):

1. Application protocol   (client <-> server, TCP)
       PING                -> PONG
       ECHO <text>         -> ECHO <text>
       TIME                -> TIME <iso-8601 utc>
       GET <nbytes>        -> OK <nbytes>\n followed by exactly nbytes of payload
       QUIT                -> BYE   (server closes)
       anything else       -> ERR <code> <message>

2. Security-event protocol (controller -> logger, TCP)
       one JSON object per line:
       {"eid": "...", "ts": 1761197460.123, "type": "RULE_ADDED",
        "src": "10.0.0.1", "dst": "10.0.0.10", "port": 5001,
        "action": "deny", "dpid": 1, "detail": {...}}
       logger replies per line:  ACK <eid>   |   ERR <code>
"""
import ipaddress
import json
import time

APP_MAX_LINE = 1024
APP_MAX_GET = 64 * 1024 * 1024          # 64 MiB cap on GET payloads
EVENT_MAX_LINE = 8192

APP_COMMANDS = ("PING", "ECHO", "TIME", "GET", "QUIT")

EVENT_TYPES = ("RULE_ADDED", "RULE_ESCALATED", "RULE_EXPIRED", "CONTROLLER")
EVENT_ACTIONS = ("allow", "deny", "block", "unblock", "info")
EVENT_REQUIRED = ("ts", "type", "src", "dst", "port", "action")


class ProtocolError(ValueError):
    """Raised for malformed input. .code is a short machine-readable token."""

    def __init__(self, code, message=""):
        super().__init__(message or code)
        self.code = code


# --------------------------------------------------------------------------
# Application protocol
# --------------------------------------------------------------------------
def parse_request(line):
    """Parse one request line (bytes or str) -> (command, argument_str)."""
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError("bad_encoding", "request is not valid UTF-8")
    line = line.rstrip("\r\n")
    if not line.strip():
        raise ProtocolError("empty", "empty request")
    if len(line) > APP_MAX_LINE:
        raise ProtocolError("too_long", "request exceeds %d bytes" % APP_MAX_LINE)
    cmd, _, arg = line.partition(" ")
    cmd = cmd.upper()
    if cmd not in APP_COMMANDS:
        raise ProtocolError("unknown_command", "unknown command %r" % cmd[:32])
    if cmd == "GET":
        try:
            n = int(arg.strip())
        except ValueError:
            raise ProtocolError("bad_argument", "GET needs an integer byte count")
        if n < 0 or n > APP_MAX_GET:
            raise ProtocolError("bad_argument", "GET size out of range")
        return cmd, str(n)
    return cmd, arg


def err_line(code, message=""):
    msg = (message or code).replace("\n", " ")[:200]
    return ("ERR %s %s\n" % (code, msg)).encode()


# --------------------------------------------------------------------------
# Security-event protocol
# --------------------------------------------------------------------------
def make_event(type_, src, dst, port, action, ts=None, eid=None, dpid=None, **detail):
    ev = {
        "ts": round(time.time() if ts is None else ts, 6),
        "type": type_,
        "src": str(src),
        "dst": str(dst),
        "port": int(port),
        "action": action,
    }
    if eid is not None:
        ev["eid"] = eid
    if dpid is not None:
        ev["dpid"] = dpid
    if detail:
        ev["detail"] = detail
    return ev


def _check_addr(value, field):
    if not isinstance(value, str) or not value:
        raise ProtocolError("bad_field", "%s must be a non-empty string" % field)
    if value == "*":
        return
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ProtocolError("bad_field", "%s is not an IP address: %r" % (field, value[:40]))


def validate_event(ev):
    """Raise ProtocolError unless ev is a well-formed security event."""
    if not isinstance(ev, dict):
        raise ProtocolError("bad_json", "event must be a JSON object")
    for key in EVENT_REQUIRED:
        if key not in ev:
            raise ProtocolError("missing_field", "missing field %r" % key)
    ts = ev["ts"]
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts <= 0:
        raise ProtocolError("bad_field", "ts must be a positive number")
    if ev["type"] not in EVENT_TYPES:
        raise ProtocolError("bad_field", "unknown type %r" % str(ev["type"])[:32])
    if ev["action"] not in EVENT_ACTIONS:
        raise ProtocolError("bad_field", "unknown action %r" % str(ev["action"])[:32])
    _check_addr(ev["src"], "src")
    _check_addr(ev["dst"], "dst")
    port = ev["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ProtocolError("bad_field", "port must be an integer 0..65535")
    if "detail" in ev and not isinstance(ev["detail"], dict):
        raise ProtocolError("bad_field", "detail must be an object")
    return ev


def encode_event(ev):
    return (json.dumps(ev, separators=(",", ":"), sort_keys=True) + "\n").encode()


def decode_event(line):
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError("bad_encoding", "event is not valid UTF-8")
    line = line.strip()
    if not line:
        raise ProtocolError("empty", "empty line")
    if len(line) > EVENT_MAX_LINE:
        raise ProtocolError("too_long", "event too long")
    try:
        ev = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError("bad_json", "invalid JSON: %s" % exc.msg)
    return validate_event(ev)
