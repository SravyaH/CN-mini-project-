import argparse
import socket
import threading
import time
import unittest

from app.client import run
from app.server import AppServer


def args(port, **kw):
    d = dict(host="127.0.0.1", port=port, mode="ping", count=5, interval=0.0, size=100000, timeout=2.0)
    d.update(kw)
    return argparse.Namespace(**d)


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = AppServer("127.0.0.1", [0, 0], idle_timeout=0.6).start()
        cls.port = cls.srv.ports[0]

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def raw(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        return s, s.makefile("rb")

    def test_ping_echo_get(self):
        r = run(args(self.port, mode="ping", count=10))
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["rtts_ms"]), 10)
        self.assertTrue(run(args(self.port, mode="echo", count=3))["ok"])
        g = run(args(self.port, mode="get", size=3000000))
        self.assertTrue(g["ok"])
        self.assertEqual(g["bytes"], 3000000)
        self.assertGreater(g["mbps"], 0)

    def test_every_listening_port_serves(self):
        for p in self.srv.ports:
            self.assertTrue(run(args(p))["ok"])

    def test_protocol_errors(self):
        s, f = self.raw()
        s.sendall(b"BOGUS\n")
        self.assertTrue(f.readline().startswith(b"ERR unknown_command"))
        s.sendall(b"GET abc\n")
        self.assertTrue(f.readline().startswith(b"ERR bad_argument"))
        s.sendall(b"PING\n")                                    # still usable
        self.assertEqual(f.readline().strip(), b"PONG")
        s.sendall(b"QUIT\n")
        self.assertEqual(f.readline().strip(), b"BYE")
        self.assertEqual(f.readline(), b"")

    def test_repeated_garbage_closes_connection(self):
        s, f = self.raw()
        for _ in range(5):
            s.sendall(b"???\n")
        replies = [f.readline() for _ in range(7)]
        self.assertTrue(any(b"too_many_errors" in r for r in replies))

    def test_oversized_line(self):
        s, f = self.raw()
        s.sendall(b"ECHO " + b"a" * 5000)
        self.assertTrue(f.readline().startswith(b"ERR too_long"))
        self.assertEqual(f.readline(), b"")

    def test_idle_timeout(self):
        s, f = self.raw()
        self.assertTrue(f.readline().startswith(b"ERR timeout"))

    def test_client_disconnect_mid_transfer_does_not_hurt_server(self):
        s, f = self.raw()
        s.sendall(b"GET 50000000\n")
        f.readline()
        s.close()
        time.sleep(0.2)
        self.assertTrue(run(args(self.port))["ok"])

    def test_many_concurrent_clients(self):
        results = []

        def worker():
            results.append(run(args(self.port, count=20, interval=0.005))["ok"])
        threads = [threading.Thread(target=worker) for _ in range(30)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sum(results), 30)

    def test_client_reports_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
        s.close()
        r = run(args(closed))
        self.assertFalse(r["ok"])
        self.assertEqual((r["error"], r["exit"]), ("refused", 3))


if __name__ == "__main__":
    unittest.main()
