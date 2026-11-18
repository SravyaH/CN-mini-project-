#!/usr/bin/env python3
"""TCP application client.

Connects, runs a short workload, prints ONE JSON summary line and exits with a
code that tells the firewall outcome apart:

    0  success
    2  connect timeout      (SYN silently dropped  -> deny / block rule)
    3  connection refused or reset (no listener / RST)
    4  protocol or I/O error after connecting

Modes:  connect | ping | echo | get
Usage:  python3 app/client.py --host 10.0.0.10 --port 5000 --mode ping --count 20
"""
import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.netutil import LineReader, set_nodelay  # noqa: E402
from common.protocol import APP_MAX_LINE  # noqa: E402


def run(args):
    res = {"host": args.host, "port": args.port, "mode": args.mode, "ok": False,
           "connect_ms": None, "rtts_ms": [], "bytes": 0, "mbps": None, "error": None}
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
    except socket.timeout:
        res["error"], res["exit"] = "connect_timeout", 2
        return res
    except (ConnectionRefusedError, ConnectionResetError):
        res["error"], res["exit"] = "refused", 3
        return res
    except OSError as exc:
        res["error"], res["exit"] = "connect_error: %s" % exc, 3
        return res
    res["connect_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    sock.settimeout(args.timeout)
    set_nodelay(sock)
    reader = LineReader(sock, APP_MAX_LINE)
    try:
        if args.mode in ("ping", "echo"):
            for i in range(args.count):
                msg = b"PING\n" if args.mode == "ping" else ("ECHO hello-%d\n" % i).encode()
                t1 = time.perf_counter()
                sock.sendall(msg)
                reply = reader.readline()
                res["rtts_ms"].append(round((time.perf_counter() - t1) * 1000, 3))
                if reply is None or reply.startswith(b"ERR"):
                    raise ValueError("server replied %r" % (reply,))
                if args.interval and i + 1 < args.count:
                    time.sleep(args.interval)
        elif args.mode == "get":
            t1 = time.perf_counter()
            sock.sendall(("GET %d\n" % args.size).encode())
            head = reader.readline()
            if head is None or not head.startswith(b"OK"):
                raise ValueError("server replied %r" % (head,))
            res["bytes"] = reader.drain(int(head.split()[1]))
            dt = time.perf_counter() - t1
            res["mbps"] = round(res["bytes"] * 8 / dt / 1e6, 3) if dt > 0 else None
        try:
            sock.sendall(b"QUIT\n")
        except OSError:
            pass
        res["ok"], res["exit"] = True, 0
    except socket.timeout:
        res["error"], res["exit"] = "io_timeout", 4
    except (ConnectionError, OSError, ValueError) as exc:
        res["error"], res["exit"] = "io_error: %s" % exc, 4
    finally:
        sock.close()
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--mode", choices=("connect", "ping", "echo", "get"), default="ping")
    ap.add_argument("--count", type=int, default=5, help="requests for ping/echo")
    ap.add_argument("--interval", type=float, default=0.0, help="seconds between requests")
    ap.add_argument("--size", type=int, default=1000000, help="bytes for get")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()
    res = run(args)
    code = res.pop("exit")
    print(json.dumps(res))
    sys.exit(code)


if __name__ == "__main__":
    main()
