#!/usr/bin/env python3
"""Central security-event logger (TCP, thread per connection).

Receives newline-delimited JSON events from the SDN controller, validates
them, de-duplicates on 'eid', timestamps the reception and writes them to

    <out-dir>/events.jsonl   machine-readable (one JSON object per line)
    <out-dir>/events.log     human-readable

and answers every line with  "ACK <eid>"  or  "ERR <code>".
A line containing just STATS returns a JSON counter summary.

Usage:  python3 logger/logger_server.py [--host 0.0.0.0] [--port 9999] [--out-dir logs]
"""
import argparse
import collections
import datetime
import json
import os
import signal
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.protocol import EVENT_MAX_LINE, ProtocolError, decode_event  # noqa: E402


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LoggerServer(object):
    def __init__(self, host="0.0.0.0", port=9999, out_dir="logs", idle_timeout=60.0,
                 echo=False, max_seen=100000):
        self.host, self.port = host, port
        self.out_dir, self.idle_timeout, self.echo = out_dir, idle_timeout, echo
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "events.jsonl")
        self._seen = collections.OrderedDict()
        self._max_seen = max_seen
        if os.path.exists(path):                    # remember ids across restarts (de-duplication)
            with open(path) as old:
                for line in old:
                    try:
                        self._seen[json.loads(line)["eid"]] = True
                    except (ValueError, KeyError):
                        pass
            while len(self._seen) > max_seen:
                self._seen.popitem(last=False)
        self._jsonl = open(path, "a", buffering=1)
        self._text = open(os.path.join(out_dir, "events.log"), "a", buffering=1)
        self._lock = threading.Lock()
        self.stats = collections.Counter()
        self.by_action = collections.Counter()
        self._sock = None
        self._running = False
        self._clients = set()

    # -- lifecycle -----------------------------------------------------
    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(64)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        for c in list(self._clients):
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except OSError:
                pass
        with self._lock:
            self._jsonl.close()
            self._text.close()

    # -- internals -----------------------------------------------------
    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                return
            self.stats["connections"] += 1
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _serve(self, conn, addr):
        conn.settimeout(self.idle_timeout)
        self._clients.add(conn)
        buf = b""
        try:
            while True:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    self.stats["idle_timeouts"] += 1
                    self._send(conn, b"ERR idle_timeout\n")
                    return
                if not chunk:
                    return                              # clean disconnect
                buf += chunk
                while b"\n" in buf:
                    line, _, buf = buf.partition(b"\n")
                    if not self._handle_line(conn, line):
                        return
                if len(buf) > EVENT_MAX_LINE:           # no newline in sight
                    self.stats["too_long"] += 1
                    self._send(conn, b"ERR too_long\n")
                    return
        except (ConnectionError, OSError):
            self.stats["disconnects"] += 1
        finally:
            self._clients.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _send(conn, data):
        try:
            conn.sendall(data)
            return True
        except OSError:
            return False

    def _handle_line(self, conn, line):
        if line.strip() == b"STATS":
            return self._send(conn, (json.dumps(self.summary()) + "\n").encode())
        try:
            ev = decode_event(line)
        except ProtocolError as exc:
            self.stats["rejected"] += 1
            return self._send(conn, ("ERR %s\n" % exc.code).encode())
        eid = ev.get("eid")
        with self._lock:
            duplicate = eid is not None and eid in self._seen
            if not duplicate:
                if eid is not None:
                    self._seen[eid] = True
                    if len(self._seen) > self._max_seen:
                        self._seen.popitem(last=False)
                try:
                    self._write(ev)
                except ValueError:                      # files closed during shutdown
                    return False
        if duplicate:
            self.stats["duplicates"] += 1
        return self._send(conn, ("ACK %s\n" % (eid or "-")).encode())

    def _write(self, ev):
        recv = time.time()
        rec = dict(ev)
        rec["recv_ts"] = round(recv, 6)
        self._jsonl.write(json.dumps(rec, sort_keys=True) + "\n")
        detail = ev.get("detail", {})
        extra = " ".join("%s=%s" % kv for kv in sorted(detail.items()))
        text = "%s %-14s %-7s %s -> %s:%s [dpid=%s] %s" % (
            iso(ev["ts"]), ev["type"], ev["action"], ev["src"], ev["dst"], ev["port"],
            ev.get("dpid", "-"), extra)
        self._text.write(text + "\n")
        self.stats["events"] += 1
        self.by_action[ev["action"]] += 1
        if self.echo:
            print(text, flush=True)

    def summary(self):
        with self._lock:
            return {"stats": dict(self.stats), "by_action": dict(self.by_action)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--out-dir", default="logs")
    ap.add_argument("--idle-timeout", type=float, default=60.0)
    ap.add_argument("--quiet", action="store_true", help="do not echo events to stdout")
    args = ap.parse_args()

    srv = LoggerServer(args.host, args.port, args.out_dir, args.idle_timeout, echo=not args.quiet)
    srv.start()
    print("logger listening on %s:%d, writing to %s/" % (args.host, srv.port, args.out_dir),
          flush=True)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()
    srv.stop()
    print("logger stopped: %s" % json.dumps(srv.stats), flush=True)


if __name__ == "__main__":
    main()
