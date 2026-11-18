"""Non-blocking, self-healing client for the central logger.

* send() never blocks and never raises, so the controller keeps enforcing the
  firewall even if the logger is down.
* Events wait in a bounded in-memory queue; if the logger is unreachable they
  are also appended to a local spool file so nothing is silently lost.
* A background loop reconnects with exponential back-off and replays the
  queue in order (at-least-once; the logger de-duplicates on 'eid').

The loop only uses `time.sleep`-style cooperative calls through injectable
`spawn` / `sleep` functions, so it works with real threads (tests) and with
eventlet green threads (Ryu: pass ryu.lib.hub.spawn / hub.sleep).
"""
import collections
import json
import os
import socket
import threading
import time

from common.protocol import encode_event


class EventSender(object):
    def __init__(self, host, port, spool_path=None, max_queue=20000, connect_timeout=1.0,
                 ack_timeout=1.0, spawn=None, sleep=time.sleep, sender_id=None, log=None):
        self.host, self.port = host, port
        self.spool_path = spool_path
        self.max_queue = max_queue
        self.connect_timeout, self.ack_timeout = connect_timeout, ack_timeout
        self._sleep = sleep
        self._spawn = spawn or self._thread_spawn
        self._log = log or (lambda msg: None)
        self.sender_id = sender_id or ("%d-%d" % (os.getpid(), int(time.time())))
        self._seq = 0
        self._q = collections.deque()
        self._sock = None
        self._rbuf = b""
        self._running = False
        self._spooled = set()
        # counters (read by tests / README demo)
        self.sent = 0
        self.acked = 0
        self.dropped = 0
        self.spooled = 0
        self.connect_failures = 0

    # -- lifecycle -------------------------------------------------------
    @staticmethod
    def _thread_spawn(fn):
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        return t

    def start(self):
        if not self._running:
            self._running = True
            self._spawn(self._loop)

    def stop(self):
        self._running = False
        self._close()

    @property
    def connected(self):
        return self._sock is not None

    @property
    def backlog(self):
        return len(self._q)

    # -- public API ------------------------------------------------------
    def send(self, event):
        """Queue an event. Safe to call from the controller hot path."""
        self._seq += 1
        event = dict(event)
        event.setdefault("eid", "%s-%d" % (self.sender_id, self._seq))
        if len(self._q) >= self.max_queue:
            self._q.popleft()
            self.dropped += 1
        self._q.append(event)
        if self._sock is None:
            self._spool(event)

    def flush(self, timeout=5.0):
        """Wait until the queue is empty (used by tests and clean shutdown)."""
        end = time.time() + timeout
        while self._q and time.time() < end:
            time.sleep(0.02)
        return not self._q

    # -- internals -------------------------------------------------------
    def _spool(self, event):
        if not self.spool_path or event["eid"] in self._spooled:
            return
        try:
            with open(self.spool_path, "a") as fh:
                fh.write(json.dumps(event, sort_keys=True) + "\n")
            self._spooled.add(event["eid"])
            self.spooled += 1
        except OSError:
            pass

    def _close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock, self._rbuf = None, b""

    def _connect(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
            s.settimeout(self.ack_timeout)
            self._sock, self._rbuf = s, b""
            self._log("logger connected %s:%s" % (self.host, self.port))
            return True
        except OSError:
            self.connect_failures += 1
            return False

    def _read_line(self):
        while b"\n" not in self._rbuf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("logger closed the connection")
            self._rbuf += chunk
        line, _, self._rbuf = self._rbuf.partition(b"\n")
        return line.decode("utf-8", "replace").strip()

    def _deliver(self, event):
        self._sock.sendall(encode_event(event))
        self.sent += 1
        reply = self._read_line()
        if reply.startswith("ACK"):
            self.acked += 1
        elif reply.startswith("ERR"):
            # malformed on the logger's side: retrying will not help, drop it
            self._log("logger rejected event: %s" % reply)
        else:
            raise ConnectionError("unexpected logger reply %r" % reply[:40])

    def _loop(self):
        backoff = 0.2
        while self._running:
            if not self._q:
                self._sleep(0.02)
                continue
            if self._sock is None:
                if not self._connect():
                    self._sleep(backoff)
                    backoff = min(backoff * 2, 3.0)
                    continue
                backoff = 0.2
            event = self._q[0]
            try:
                self._deliver(event)
                if self._q and self._q[0] is event:   # overflow may have dropped it
                    self._q.popleft()
            except (OSError, ConnectionError):
                self._log("logger connection lost; %d events queued" % len(self._q))
                self._close()
                for pending in list(self._q):          # make sure nothing is only in RAM
                    self._spool(pending)
                self._sleep(backoff)
