#!/usr/bin/env python3
"""Concurrent TCP application server (one thread per client).

Listens on several ports so the firewall has something real to protect:
    5000  main service       (allowed for every client)
    5001  admin service      (denied by policy)
    5002  restricted service (allowed for h2 only)
Every port speaks the same line protocol (see common/protocol.py).

Usage:  python3 app/server.py [--host 0.0.0.0] [--ports 5000 5001 5002]
"""
import argparse
import datetime
import os
import signal
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.netutil import LineReader, set_nodelay  # noqa: E402
from common.protocol import APP_MAX_LINE, ProtocolError, err_line, parse_request  # noqa: E402

PAYLOAD_CHUNK = b"x" * 65536
MAX_CONSECUTIVE_ERRORS = 5


class AppServer(object):
    def __init__(self, host="0.0.0.0", ports=(5000,), idle_timeout=30.0, max_clients=256,
                 verbose=False):
        self.host, self.ports = host, list(ports)
        self.idle_timeout, self.max_clients, self.verbose = idle_timeout, max_clients, verbose
        self._listeners = []
        self._running = False
        self._lock = threading.Lock()
        self.active = 0
        self.total = 0
        self.bytes_sent = 0
        self.errors = 0

    # -- lifecycle -----------------------------------------------------
    def start(self):
        self._running = True
        bound = []
        for port in self.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, port))
            s.listen(128)
            bound.append(s.getsockname()[1])
            self._listeners.append(s)
            threading.Thread(target=self._accept_loop, args=(s,), daemon=True).start()
        self.ports = bound
        return self

    def stop(self):
        self._running = False
        for s in self._listeners:
            try:
                s.close()
            except OSError:
                pass

    def _log(self, msg):
        if self.verbose:
            print("%s %s" % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3], msg), flush=True)

    # -- connection handling ---------------------------------------------
    def _accept_loop(self, listener):
        port = listener.getsockname()[1]
        while self._running:
            try:
                conn, addr = listener.accept()
            except OSError:
                return
            with self._lock:
                full = self.active >= self.max_clients
                if not full:
                    self.active += 1
                    self.total += 1
            if full:
                try:
                    conn.sendall(err_line("busy", "too many clients"))
                finally:
                    conn.close()
                continue
            threading.Thread(target=self._handle, args=(conn, addr, port), daemon=True).start()

    def _handle(self, conn, addr, port):
        peer = "%s:%d" % addr
        self._log("connect  %s -> :%d" % (peer, port))
        conn.settimeout(self.idle_timeout)
        set_nodelay(conn)
        reader = LineReader(conn, APP_MAX_LINE)
        bad = 0
        try:
            while True:
                try:
                    raw = reader.readline()
                except socket.timeout:
                    conn.sendall(err_line("timeout", "idle for %.0fs" % self.idle_timeout))
                    self._log("timeout  %s" % peer)
                    return
                except ProtocolError as exc:
                    conn.sendall(err_line(exc.code, str(exc)))
                    self._count_error()
                    self._graceful_close(conn)   # framing lost: close
                    return
                if raw is None:
                    return                       # client closed
                try:
                    cmd, arg = parse_request(raw)
                except ProtocolError as exc:
                    self._count_error()
                    bad += 1
                    conn.sendall(err_line(exc.code, str(exc)))
                    if bad >= MAX_CONSECUTIVE_ERRORS:
                        conn.sendall(err_line("too_many_errors", "closing"))
                        self._graceful_close(conn)
                        return
                    continue
                bad = 0
                if cmd == "PING":
                    conn.sendall(b"PONG\n")
                elif cmd == "ECHO":
                    conn.sendall(("ECHO %s\n" % arg).encode())
                elif cmd == "TIME":
                    conn.sendall(("TIME %s\n" % datetime.datetime.now(
                        datetime.timezone.utc).isoformat()).encode())
                elif cmd == "GET":
                    self._send_payload(conn, int(arg))
                elif cmd == "QUIT":
                    conn.sendall(b"BYE\n")
                    return
        except (ConnectionError, OSError):
            self._log("dropped  %s" % peer)
        finally:
            with self._lock:
                self.active -= 1
            try:
                conn.close()
            except OSError:
                pass
            self._log("closed   %s" % peer)

    @staticmethod
    def _graceful_close(conn):
        """Flush our error reply, then swallow unread input so close() does not
        turn into a TCP RST that would destroy the reply before the client reads it."""
        try:
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(0.3)
            left = 1 << 20
            while left > 0:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                left -= len(chunk)
        except OSError:
            pass

    def _send_payload(self, conn, n):
        conn.sendall(("OK %d\n" % n).encode())
        left = n
        while left > 0:
            chunk = PAYLOAD_CHUNK[:min(left, len(PAYLOAD_CHUNK))]
            conn.sendall(chunk)
            left -= len(chunk)
        with self._lock:
            self.bytes_sent += n

    def _count_error(self):
        with self._lock:
            self.errors += 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--ports", type=int, nargs="+", default=[5000, 5001, 5002])
    ap.add_argument("--idle-timeout", type=float, default=30.0)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    srv = AppServer(args.host, args.ports, args.idle_timeout, verbose=args.verbose).start()
    print("app server on %s ports %s (thread per client)" % (args.host, srv.ports), flush=True)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()
    srv.stop()
    print("app server stopped: total=%d bytes_sent=%d errors=%d" % (srv.total, srv.bytes_sent, srv.errors))


if __name__ == "__main__":
    main()
