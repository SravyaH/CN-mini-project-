#!/usr/bin/env python3
"""Narrated, reproducible demo (about 60 s). Run via ./demo.sh (needs root)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments import render                       # noqa: E402
from topo import constants as C                      # noqa: E402
from topo.harness import Lab                         # noqa: E402

OUT = os.path.join(C.ROOT, "results", "demo")


def say(msg):
    print("\n\033[1;36m>>> %s\033[0m" % msg, flush=True)


def show_flows(lab, title):
    print("   s1 flow table (%s):" % title)
    for line in render.table_lines(lab.dump_flows("s1")):
        print("     " + line)


def show_events(lab, n=8):
    print("   last events seen by the logger:")
    for e in lab.events()[-n:]:
        d = e.get("detail", {})
        extra = d.get("what") or d.get("reason") or d.get("rule") or ""
        print("     %-14s %-7s %s -> %s:%s  %s" % (e["type"], e["action"], e["src"], e["dst"], e["port"], extra))


def main():
    if os.geteuid() != 0:
        sys.exit("run with sudo (./demo.sh)")
    os.makedirs(OUT, exist_ok=True)
    with Lab("dynamic", clients=3, out_dir=OUT, block_time=10) as lab:
        say("1. Network is up. Only the table-miss rule exists; the controller learns on demand.")
        lab.net.pingAll(timeout="2")
        show_flows(lab, "before any TCP traffic")

        say("2. Allowed traffic: h1 -> server:5000")
        print("  ", lab.client("h1", 5000, "ping", count=5))
        say("3. Denied traffic: h1 -> server:5001 (admin port) - SYN is silently dropped")
        r = lab.client("h1", 5001, "connect", timeout=1.5)
        print("  ", r["error"], "(exit %d)" % r["exit"])
        say("4. Per-source classification: port 5002 is open for h2 only")
        print("   h2 ->", lab.client("h2", 5002, "ping", count=2)["ok"], "  h1 ->", lab.client("h1", 5002, "connect", timeout=1.5)["error"])
        show_flows(lab, "allow + deny rules appeared at runtime")
        time.sleep(1)
        show_events(lab)

        say("5. Attack: h3 sweeps 1000 ports at 200/s while h1 and h2 keep working")
        legit = [lab.legit("h%d" % h, duration=6, background=True) for h in (1, 2)]
        time.sleep(1)
        sweep = lab.attack("h3", "sweep", ports="1000-1999", rate=200, count=1000, background=True)
        lab.wait_for(lambda: lab.has_flow("priority=300"), 5)
        show_flows(lab, "h3 BLOCKED: prio 300 rule, hard_timeout=10")
        a = sweep.result()
        for h, j in zip((1, 2), legit):
            r = j.result()
            rtt = r.get("rtt_ms_p95")
            rtt_text = "%.2f ms" % rtt if isinstance(rtt, (int, float)) else "N/A"
            print("   h%d legit sessions: %s/%s ok, rtt p95 %s" % (h, r.get("ok"), r.get("sessions"), rtt_text))
        print("   attacker outcomes:", a["outcomes"])
        print("   blocked h3 -> allowed port:", lab.client("h3", 5000, "connect", timeout=1.5)["error"])

        say("6. Automatic recovery: the block rule expires by itself")
        lab.wait_for(lambda: not lab.has_flow("priority=300"), 15)
        show_flows(lab, "block rule gone")
        print("   h3 -> allowed port again:", lab.client("h3", 5000, "ping", count=2)["ok"])
        time.sleep(1)
        show_events(lab, 10)
        render.save_png(lab.dump_flows("s1"), os.path.join(OUT, "flows_final.png"), "s1 flow table at the end of the demo")
        say("done. logs: %s/logger/events.log" % OUT)


if __name__ == "__main__":
    main()
