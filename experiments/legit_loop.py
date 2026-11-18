#!/usr/bin/env python3
"""A well-behaved client: many short sessions to the allowed port.

Each session = connect + a few PING round trips + QUIT. Prints ONE JSON line
(success rate, connect-time and RTT distributions) used to quantify how much an
attack hurts legitimate users.

    python3 experiments/legit_loop.py --host 10.0.0.10 --duration 5 --pings 5
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.client import run as client_run  # noqa: E402


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 3)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--duration", type=float, default=5.0)
    ap.add_argument("--pings", type=int, default=5)
    ap.add_argument("--gap", type=float, default=0.05, help="pause between sessions")
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()

    ns = argparse.Namespace(host=a.host, port=a.port, mode="ping", count=a.pings, interval=0.0,
                            size=0, timeout=a.timeout)
    sessions = ok = 0
    connect, rtts, errors = [], [], {}
    end = time.time() + a.duration
    first_connect = None
    while time.time() < end:
        r = client_run(ns)
        sessions += 1
        if r["ok"]:
            ok += 1
            connect.append(r["connect_ms"])
            rtts.extend(r["rtts_ms"])
            if first_connect is None:
                first_connect = r["connect_ms"]
        else:
            errors[r["error"]] = errors.get(r["error"], 0) + 1
        time.sleep(a.gap)
    print(json.dumps({
        "host": a.host, "sessions": sessions, "ok": ok,
        "success_rate": round(ok / sessions, 4) if sessions else None,
        "errors": errors, "first_connect_ms": first_connect,
        "connect_ms_p50": pct(connect, 50), "connect_ms_p95": pct(connect, 95),
        "rtt_ms_p50": pct(rtts, 50), "rtt_ms_p95": pct(rtts, 95), "rtt_ms_max": max(rtts) if rtts else None,
        "rtt_samples": len(rtts), "rtts": rtts, "connects": connect,
    }))


if __name__ == "__main__":
    main()
