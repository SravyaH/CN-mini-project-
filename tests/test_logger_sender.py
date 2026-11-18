import json
import os
import shutil
import socket
import tempfile
import time
import unittest

from common import protocol as P
from common.eventsender import EventSender
from logger.logger_server import LoggerServer


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def ev(i=0, **kw):
    return P.make_event("RULE_ADDED", "10.0.0.1", "10.0.0.10", 5000 + i, "allow", dpid=1, **kw)


def lines(path):
    with open(path) as fh:
        return [json.loads(x) for x in fh if x.strip()]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def conn(self, srv):
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=2)
        return s, s.makefile("rb")


class LoggerTests(Base):
    def setUp(self):
        super().setUp()
        self.srv = LoggerServer("127.0.0.1", 0, self.tmp, idle_timeout=0.6).start()

    def tearDown(self):
        self.srv.stop()
        super().tearDown()

    def test_valid_event_acked_and_stored_with_timestamp(self):
        s, f = self.conn(self.srv)
        s.sendall(P.encode_event(ev(eid="e1")))
        self.assertEqual(f.readline().strip(), b"ACK e1")
        rec = lines(os.path.join(self.tmp, "events.jsonl"))[0]
        self.assertEqual(rec["port"], 5000)
        self.assertIn("recv_ts", rec)
        self.assertIn("RULE_ADDED", open(os.path.join(self.tmp, "events.log")).read())

    def test_bad_input_does_not_kill_connection(self):
        s, f = self.conn(self.srv)
        s.sendall(b"garbage\n")
        self.assertEqual(f.readline().strip(), b"ERR bad_json")
        s.sendall(b'{"ts":1}\n')
        self.assertEqual(f.readline().strip(), b"ERR missing_field")
        s.sendall(P.encode_event(ev(eid="e2")))
        self.assertEqual(f.readline().strip(), b"ACK e2")
        self.assertEqual(len(lines(os.path.join(self.tmp, "events.jsonl"))), 1)

    def test_duplicates_are_acked_but_stored_once(self):
        s, f = self.conn(self.srv)
        for _ in range(3):
            s.sendall(P.encode_event(ev(eid="dup")))
            self.assertEqual(f.readline().strip(), b"ACK dup")
        self.assertEqual(len(lines(os.path.join(self.tmp, "events.jsonl"))), 1)
        self.assertEqual(self.srv.stats["duplicates"], 2)

    def test_oversize_line_closes_connection(self):
        s, f = self.conn(self.srv)
        s.sendall(b"x" * (P.EVENT_MAX_LINE + 100))
        self.assertEqual(f.readline().strip(), b"ERR too_long")
        self.assertEqual(f.readline(), b"")                      # closed

    def test_idle_timeout(self):
        s, f = self.conn(self.srv)
        self.assertEqual(f.readline().strip(), b"ERR idle_timeout")

    def test_abrupt_disconnect_and_concurrent_clients(self):
        s, _ = self.conn(self.srv)
        s.sendall(b'{"partial":')
        s.close()
        conns = [self.conn(self.srv) for _ in range(5)]
        for i, (c, f) in enumerate(conns):
            c.sendall(P.encode_event(ev(i, eid="c%d" % i)))
        for i, (c, f) in enumerate(conns):
            self.assertEqual(f.readline().strip(), ("ACK c%d" % i).encode())
        self.assertEqual(len(lines(os.path.join(self.tmp, "events.jsonl"))), 5)

    def test_dedupe_survives_logger_restart(self):
        s, f = self.conn(self.srv)
        s.sendall(P.encode_event(ev(eid="persist")))
        self.assertEqual(f.readline().strip(), b"ACK persist")
        self.srv.stop()
        srv2 = LoggerServer("127.0.0.1", 0, self.tmp).start()
        try:
            s, f = self.conn(srv2)
            s.sendall(P.encode_event(ev(eid="persist")))
            self.assertEqual(f.readline().strip(), b"ACK persist")
            self.assertEqual(len(lines(os.path.join(self.tmp, "events.jsonl"))), 1)
        finally:
            srv2.stop()
        self.srv = LoggerServer("127.0.0.1", 0, self.tmp + "_x").start()   # for tearDown

    def test_stats_command(self):
        s, f = self.conn(self.srv)
        s.sendall(P.encode_event(ev(eid="s1")))
        f.readline()
        s.sendall(b"STATS\n")
        out = json.loads(f.readline())
        self.assertEqual(out["by_action"]["allow"], 1)


class SenderTests(Base):
    def test_delivers_in_order(self):
        srv = LoggerServer("127.0.0.1", 0, self.tmp).start()
        snd = EventSender("127.0.0.1", srv.port)
        snd.start()
        for i in range(50):
            snd.send(ev(i))
        self.assertTrue(snd.flush(5))
        srv.stop()
        ports = [r["port"] for r in lines(os.path.join(self.tmp, "events.jsonl"))]
        self.assertEqual(ports, [5000 + i for i in range(50)])
        self.assertEqual(snd.acked, 50)

    def test_logger_unreachable_never_blocks_then_recovers(self):
        port = free_port()                                       # nothing listens yet
        spool = os.path.join(self.tmp, "spool.jsonl")
        snd = EventSender("127.0.0.1", port, spool_path=spool, connect_timeout=0.2)
        snd.start()
        t0 = time.time()
        for i in range(2000):
            snd.send(ev(i % 100))
        self.assertLess(time.time() - t0, 0.5, "send() must not block when the logger is down")
        self.assertGreater(snd.backlog, 0)
        self.assertEqual(snd.spooled, 2000)                      # nothing lost locally
        self.assertFalse(snd.connected)

        out = os.path.join(self.tmp, "late")
        srv = LoggerServer("127.0.0.1", port, out).start()       # logger comes back
        self.assertTrue(snd.flush(15))
        srv.stop()
        self.assertEqual(len(lines(os.path.join(out, "events.jsonl"))), 2000)

    def test_reconnects_after_logger_restart(self):
        port = free_port()
        a = os.path.join(self.tmp, "a")
        b = os.path.join(self.tmp, "b")
        srv = LoggerServer("127.0.0.1", port, a).start()
        snd = EventSender("127.0.0.1", port, connect_timeout=0.2)
        snd.start()
        snd.send(ev(1))
        self.assertTrue(snd.flush(3))
        srv.stop()
        time.sleep(0.2)
        snd.send(ev(2))
        snd.send(ev(3))
        time.sleep(0.4)
        srv2 = LoggerServer("127.0.0.1", port, b).start()
        self.assertTrue(snd.flush(10))
        srv2.stop()
        self.assertEqual([r["port"] for r in lines(os.path.join(a, "events.jsonl"))], [5001])
        self.assertEqual([r["port"] for r in lines(os.path.join(b, "events.jsonl"))], [5002, 5003])

    def test_queue_is_bounded(self):
        snd = EventSender("127.0.0.1", free_port(), max_queue=10, connect_timeout=0.1)
        for i in range(25):
            snd.send(ev(i))
        self.assertEqual(snd.backlog, 10)
        self.assertEqual(snd.dropped, 15)


if __name__ == "__main__":
    unittest.main()
