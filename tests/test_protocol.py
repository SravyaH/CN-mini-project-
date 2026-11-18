import unittest

from common import protocol as P


class AppProtocol(unittest.TestCase):
    def test_valid_commands(self):
        self.assertEqual(P.parse_request(b"PING\n"), ("PING", ""))
        self.assertEqual(P.parse_request("echo hello world\r\n"), ("ECHO", "hello world"))
        self.assertEqual(P.parse_request("GET 1024"), ("GET", "1024"))
        self.assertEqual(P.parse_request("quit"), ("QUIT", ""))

    def test_bad_input(self):
        for raw, code in [(b"\n", "empty"), (b"   \n", "empty"),
                          (b"HACK now\n", "unknown_command"),
                          (b"GET abc\n", "bad_argument"), (b"GET -5\n", "bad_argument"),
                          (b"GET 99999999999\n", "bad_argument"),
                          (b"\xff\xfe\n", "bad_encoding"),
                          (b"ECHO " + b"a" * 2000 + b"\n", "too_long")]:
            with self.assertRaises(P.ProtocolError) as cm:
                P.parse_request(raw)
            self.assertEqual(cm.exception.code, code, raw[:20])

    def test_err_line(self):
        self.assertEqual(P.err_line("x", "multi\nline"), b"ERR x multi line\n")


class EventProtocol(unittest.TestCase):
    def good(self, **kw):
        ev = P.make_event("RULE_ADDED", "10.0.0.1", "10.0.0.10", 5000, "allow", dpid=1)
        ev.update(kw)
        return ev

    def test_roundtrip(self):
        ev = self.good(eid="a-1")
        self.assertEqual(P.decode_event(P.encode_event(ev)), ev)

    def test_wildcards_and_detail(self):
        ev = P.make_event("RULE_ESCALATED", "10.0.0.3", "*", 0, "block", violations=5)
        self.assertEqual(P.decode_event(P.encode_event(ev))["detail"]["violations"], 5)

    def test_rejects(self):
        cases = [
            (b"not json\n", "bad_json"), (b"[1,2]\n", "bad_json"), (b"\n", "empty"),
            (P.encode_event({k: v for k, v in self.good().items() if k != "port"}), "missing_field"),
            (P.encode_event(self.good(ts="now")), "bad_field"),
            (P.encode_event(self.good(ts=-1)), "bad_field"),
            (P.encode_event(self.good(type="NOPE")), "bad_field"),
            (P.encode_event(self.good(action="explode")), "bad_field"),
            (P.encode_event(self.good(src="999.1.1.1")), "bad_field"),
            (P.encode_event(self.good(port=70000)), "bad_field"),
            (P.encode_event(self.good(port="80")), "bad_field"),
            (P.encode_event(self.good(port=True)), "bad_field"),
            (P.encode_event(self.good(detail="x")), "bad_field"),
            (b"\xff\xff\n", "bad_encoding"),
            (b"{" + b"a" * 9000 + b"}\n", "too_long"),
        ]
        for raw, code in cases:
            with self.assertRaises(P.ProtocolError) as cm:
                P.decode_event(raw)
            self.assertEqual(cm.exception.code, code, raw[:40])


if __name__ == "__main__":
    unittest.main()
