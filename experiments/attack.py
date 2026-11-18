#!/usr/bin/env python3
"""Connection-attempt generator: burst against one port, or a port sweep.

Fires non-blocking TCP connects at a fixed rate and never waits for answers,
so a firewall that drops SYNs cannot slow the attacker down. Prints ONE JSON
line with wall-clock timestamps (same clock as the controller's events, since
all Mininet hosts share the kernel clock).

    python3 experiments/attack.py --target 10.0.0.10 --mode burst --port 5001 --rate 100 --count 300
    python3 experiments/attack.py --target 10.0.0.10 --mode sweep --ports 1000-1999 --rate 200
"""
import argparse
import collections
import errno
import json
import select
import socket
import sys
import time


def parse_ports(spec):
    out = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return out


def classify(sock):
    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if err == 0:
        return "connected"
    if err in (errno.ECONNREFUSED, errno.ECONNRESET):
        return "refused"
    return "error"


def run(target, ports, rate, count, duration, wait):
    pending = {}                      # fd -> (sock, t_start)
    outcomes = collections.Counter()
    first_ts = last_ts = None
    sent = 0
    start = time.perf_counter()
    interval = 1.0 / rate
    total = count if count else int(duration * rate)

    def reap(block_s=0.0):
        if not pending:
            return
        _, writable, _ = select.select([], [s for s, _ in pending.values()], [], block_s)
        for s in writable:
            outcomes[classify(s)] += 1
            pending.pop(s.fileno())
            s.close()

    def expire(now):
        """A SYN unanswered for `wait` seconds was dropped; close it (no retransmits)."""
        while pending:
            fd, (s, t0) = next(iter(pending.items()))
            if now - t0 <= wait:
                break
            outcomes["dropped"] += 1
            pending.pop(fd)
            s.close()

    while sent < total:
        due = start + sent * interval
        now = time.perf_counter()
        expire(now)
        if now < due:
            reap(min(due - now, 0.01))
            continue
        port = ports[sent % len(ports)]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        if first_ts is None:
            first_ts = time.time()
        try:
            s.connect_ex((target, port))
        except OSError:
            outcomes["error"] += 1
            s.close()
        else:
            pending[s.fileno()] = (s, now)
        last_ts = time.time()
        sent += 1
    while pending:
        reap(0.02)
        expire(time.perf_counter())
    elapsed = time.perf_counter() - start
    return {
        "target": target, "attempts": sent, "target_rate": rate,
        "achieved_rate": round(sent / max(last_ts - first_ts, 1e-6), 1) if sent > 1 else rate,
        "first_attempt_ts": first_ts, "last_attempt_ts": last_ts,
        "outcomes": dict(outcomes), "elapsed_s": round(elapsed, 3),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", choices=("burst", "sweep"), default="burst")
    ap.add_argument("--port", type=int, default=5001, help="burst: the forbidden port")
    ap.add_argument("--ports", default="1-1024", help="sweep: e.g. 1000-1999 or 22,80,443")
    ap.add_argument("--rate", type=float, default=100, help="attempts per second")
    ap.add_argument("--count", type=int, default=0, help="total attempts (else rate*duration)")
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--wait", type=float, default=1.0, help="seconds before an unanswered SYN counts as dropped")
    a = ap.parse_args()
    ports = [a.port] if a.mode == "burst" else parse_ports(a.ports)
    print(json.dumps(run(a.target, ports, a.rate, a.count, a.duration, a.wait)))


if __name__ == "__main__":
    sys.exit(main())
