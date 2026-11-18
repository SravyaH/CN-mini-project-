#!/usr/bin/env python3
"""End-to-end tests on the real stack (Mininet + OVS + Ryu). Run as root:

    sudo python3 tests/mininet_functional.py            # all groups
    sudo python3 tests/mininet_functional.py basic      # one group: basic | autoblock | hard

Each group starts its own controller + network, prints PASS/FAIL per check,
saves flow-table dumps/screenshots to results/functional/ and exits non-zero
if any check failed. docs/TESTS.md lists the expected output of every check.
"""
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments import render                      # noqa: E402
from topo.harness import Lab                        # noqa: E402
from topo import topo as T                          # noqa: E402

OUT = os.path.join(T.ROOT, "results", "functional")
MAC = {i: "00:00:00:00:00:%02x" % i for i in range(1, 7)}
IP = {i: T.client_ip(i) for i in range(1, 7)}


class Report(object):
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append({"name": name, "ok": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name, (" -- " + str(detail)) if detail else ""),
              flush=True)
        return ok

    def section(self, title):
        print("\n== %s" % title, flush=True)

    @property
    def failed(self):
        return [r for r in self.rows if not r["ok"]]


def snapshot(lab, name, title):
    lines = lab.dump_flows("s1")
    render.save_text(lines, os.path.join(OUT, name + ".txt"), title)
    render.save_png(lines, os.path.join(OUT, name + ".png"), title)
    return lines


def find_events(lab, **want):
    out = []
    for e in lab.events():
        if all((e.get(k) == v) if k != "detail" else True for k, v in want.items()):
            out.append(e)
    return out


def has_event(lab, type_, action, src=None, dst=None, port=None):
    for e in lab.events():
        if e["type"] == type_ and e["action"] == action and (src is None or e["src"] == src) \
                and (dst is None or e["dst"] == dst) and (port is None or e["port"] == port):
            return e
    return None


def wait_event(lab, timeout=5, **kw):
    ok, _ = lab.wait_for(lambda: has_event(lab, **kw) is not None, timeout)
    return has_event(lab, **kw) if ok else None


# ----------------------------------------------------------------------
def group_basic(rep):
    rep.section("GROUP basic: allowed / denied / per-source classification / logger sees events")
    with Lab("dynamic", clients=3, out_dir=os.path.join(OUT, "basic"), block_time=8) as lab:
        loss = lab.net.pingAll(timeout="2")
        rep.check("pingall (ICMP allowed by policy)", loss == 0, "%.0f%% loss" % loss)

        r = lab.client("h1", 5000, "ping", count=10)
        rep.check("h1 -> server:5000 allowed", r["ok"] and r["exit"] == 0, "connect %.1f ms" % r["connect_ms"])

        r = lab.client("h1", 5001, "connect", timeout=1.5)
        rep.check("h1 -> server:5001 denied (SYN dropped)", r["exit"] == 2 and r["error"] == "connect_timeout",
                  "error=%s" % r["error"])
        flows = lab.dump_flows("s1")
        rep.check("dump-flows shows the drop rule (prio 200, tp_dst=5001, actions=drop)",
                  any("priority=200" in l and "tp_dst=5001" in l and "actions=drop" in l for l in flows))
        rep.check("dump-flows shows the allow rule (prio 100, tp_dst=5000, output)",
                  any("priority=100" in l and "tp_dst=5000" in l and "actions=output" in l for l in flows))

        r = lab.client("h1", 22, "connect", timeout=1.5)
        rep.check("h1 -> server:22 denied by default policy (timeout, not refused)", r["exit"] == 2,
                  "error=%s" % r["error"])
        r = lab.client("h2", 5002, "ping", count=3)
        rep.check("h2 -> server:5002 allowed (per-source rule)", r["ok"])
        r = lab.client("h1", 5002, "connect", timeout=1.5)
        rep.check("h1 -> server:5002 denied (same port, different source)", r["exit"] == 2)
        r = lab.client("h1", 9999, "connect", timeout=1.5, target=T.LOGGER_IP)
        rep.check("h1 -> logger:9999 denied (clients may not reach the logger)", r["exit"] == 2)

        rep.check("logger received ALLOW h1->server:5000",
                  wait_event(lab, type_="RULE_ADDED", action="allow", src=IP[1], dst=T.SRV_IP, port=5000) is not None)
        rep.check("logger received DENY  h1->server:5001",
                  wait_event(lab, type_="RULE_ADDED", action="deny", src=IP[1], dst=T.SRV_IP, port=5001) is not None)
        rep.check("logger received DENY  h1->server:22 (default policy)",
                  has_event(lab, "RULE_ADDED", "deny", IP[1], T.SRV_IP, 22) is not None)
        rep.check("logger received DENY  h1->server:5002 and DENY h1->logger:9999",
                  has_event(lab, "RULE_ADDED", "deny", IP[1], T.SRV_IP, 5002) is not None
                  and has_event(lab, "RULE_ADDED", "deny", IP[1], T.LOGGER_IP, 9999) is not None)
        rep.check("no BLOCK yet (4 denies < threshold 5)", has_event(lab, "RULE_ESCALATED", "block") is None)
        snapshot(lab, "flows_basic", "s1 flow table after basic tests (allow + deny rules)")


# ----------------------------------------------------------------------
def group_autoblock(rep):
    rep.section("GROUP autoblock: concurrency, escalation, timed recovery, runtime rule changes, logs")
    with Lab("dynamic", clients=3, out_dir=os.path.join(OUT, "autoblock"), block_time=12) as lab:
        lab.net.pingAll(timeout="2")
        snapshot(lab, "flows_1_before", "s1 flow table BEFORE the attack")

        # --- several clients at once ---------------------------------------
        jobs = {h: lab.popen_json("h%d" % h, ["python3", "app/client.py", "--host", T.SRV_IP, "--port", "5000",
                                              "--mode", "ping", "--count", "40", "--interval", "0.02"])
                for h in (1, 2, 3)}
        deny = {h: lab.popen_json("h%d" % h, ["python3", "app/client.py", "--host", T.SRV_IP, "--port", "5001",
                                              "--mode", "connect", "--timeout", "1.5"]) for h in (1, 2, 3)}
        res = {h: j.result() for h, j in jobs.items()}
        den = {h: j.result() for h, j in deny.items()}
        rep.check("3 clients served concurrently on :5000", all(r["ok"] for r in res.values()),
                  "rtts=%s" % {h: len(r["rtts_ms"]) for h, r in res.items()})
        rep.check("3 concurrent forbidden attempts all dropped", all(r["error"] == "connect_timeout" for r in den.values()))
        ok = all(wait_event(lab, 5, type_="RULE_ADDED", action="deny", src=IP[h], dst=T.SRV_IP, port=5001)
                 for h in (1, 2, 3))
        rep.check("logger has one DENY per client (per-source classification)", ok)
        rep.check("logger has ALLOW events for all three clients",
                  all(has_event(lab, "RULE_ADDED", "allow", IP[h], T.SRV_IP, 5000) for h in (1, 2, 3)))

        # --- threshold escalation: h3 keeps probing --------------------------
        time.sleep(lab.window + 1)                       # let the counters from above expire
        t_attack = time.time()
        attack = lab.attack("h3", "burst", port=5001, rate=5, count=8, background=True)
        ok, waited = lab.wait_for(lambda: lab.has_flow("priority=300"), 8)
        t_block_seen = time.time()
        rep.check("repeated forbidden attempts escalate to a BLOCK rule (prio 300)", ok,
                  "visible %.2fs after first attempt" % (t_block_seen - t_attack))
        flows = lab.dump_flows("s1")
        block_line = next((l for l in flows if "priority=300" in l), "")
        rep.check("block rule matches in_port + source MAC, drops everything, hard_timeout=%d" % lab.block_time,
                  "in_port=" in block_line and MAC[3] in block_line and "actions=drop" in block_line
                  and "hard_timeout=%d" % lab.block_time in block_line, block_line[-110:])
        snapshot(lab, "flows_2_during_block", "s1 flow table DURING the block (prio 300 rule for h3)")
        attack.result()

        # --- isolation while blocked --------------------------------------
        r = lab.client("h3", 5000, "connect", timeout=1.5)
        rep.check("blocked h3 cannot even reach the ALLOWED port", r["exit"] == 2)
        rep.check("blocked h3 cannot ping (drop everything)", not lab.ping("h3", T.SRV_IP))
        r1, r2 = lab.client("h1", 5000, "ping", count=5), lab.client("h2", 5000, "ping", count=5)
        rep.check("other clients (h1, h2) unaffected during the block", r1["ok"] and r2["ok"])
        rep.check("h3's per-flow rules were cleaned up (table stays small)",
                  not any("nw_src=%s" % IP[3] in l for l in lab.dump_flows("s1")))
        rep.check("no block rule for h1 or h2", not any(MAC[h] in l and "priority=300" in l
                                                       for h in (1, 2) for l in lab.dump_flows("s1")))

        esc = wait_event(lab, 5, type_="RULE_ESCALATED", action="block", src=IP[3])
        rep.check("logger received BLOCK for h3 with violation count", esc is not None
                  and esc["detail"]["violations"] == 5, esc and esc["detail"])
        act = None
        ok, _ = lab.wait_for(lambda: any(e["type"] == "CONTROLLER" and e.get("detail", {}).get("what") == "block_active"
                                         and e["src"] == IP[3] for e in lab.events()), 5)
        if ok:
            act = [e for e in lab.events() if e.get("detail", {}).get("what") == "block_active"][-1]
        rep.check("logger received 'block_active' (barrier-confirmed) with response time", act is not None,
                  act and "response_ms=%.2f install_ms=%.2f" % (act["detail"]["response_ms"], act["detail"]["install_ms"]))

        # --- automatic recovery ---------------------------------------------
        gone, _ = lab.wait_for(lambda: not lab.has_flow("priority=300"), lab.block_time + 8)
        rep.check("block rule disappears by itself (hard timeout)", gone,
                  "visible for ~%.1fs (configured %ss)" % (time.time() - t_block_seen, lab.block_time))
        snapshot(lab, "flows_3_after_recovery", "s1 flow table AFTER automatic recovery")
        unb = wait_event(lab, 5, type_="RULE_EXPIRED", action="unblock", src=IP[3])
        rep.check("logger received UNBLOCK for h3 (with dropped-packet count)", unb is not None
                  and unb["detail"].get("dropped_packets", 0) >= 1, unb and unb["detail"])
        r = lab.client("h3", 5000, "ping", count=5)
        rep.check("h3 works again after recovery", r["ok"])

        # --- counters restart after recovery ----------------------------------
        lab.attack("h3", "burst", port=5001, rate=5, count=4)
        time.sleep(1.5)
        rep.check("after recovery 4 denies do NOT re-block (counter was reset)", not lab.has_flow("priority=300"))

        # --- log completeness -------------------------------------------------
        evs = lab.events()
        rep.check("every event has ts, type, src, dst, port, action and a receive timestamp",
                  all(all(k in e for k in ("ts", "type", "src", "dst", "port", "action", "recv_ts")) for e in evs),
                  "%d events" % len(evs))
        ts = [e["ts"] for e in evs]
        rep.check("event timestamps are non-decreasing in arrival order", ts == sorted(ts))
        rep.check("no duplicate event ids", len({e["eid"] for e in evs}) == len(evs))
        lag = max(e["recv_ts"] - e["ts"] for e in evs if e["ts"] >= lab.started)
        rep.check("live events reach the logger quickly (max lag < 1 s)", lag < 1.0, "max lag %.0f ms" % (lag * 1000))
        shutil.copy(os.path.join(lab.out_dir, "logger", "events.log"), os.path.join(OUT, "events_autoblock.log"))


# ----------------------------------------------------------------------
def group_hard(rep):
    rep.section("GROUP hard: port sweep during legitimate traffic, then logger unreachable")
    with Lab("dynamic", clients=3, out_dir=os.path.join(OUT, "hard"), block_time=8) as lab:
        lab.net.pingAll(timeout="2")
        legit = {h: lab.legit("h%d" % h, duration=7, pings=5, background=True) for h in (1, 2)}
        time.sleep(1.0)
        t0 = time.time()
        sweep = lab.attack("h3", "sweep", ports="1000-1999", rate=200, count=1000, background=True)
        ok, _ = lab.wait_for(lambda: lab.has_flow("priority=300"), 5)
        rep.check("attacker (h3, port sweep @200/s) is blocked within 5 s", ok, "after %.2fs" % (time.time() - t0))
        a = sweep.result()
        lg = {h: j.result() for h, j in legit.items()}
        rep.check("legitimate clients kept 100% success during the sweep",
                  all(r["success_rate"] == 1.0 for r in lg.values()),
                  {h: "%d/%d sessions, rtt p95 %.2f ms" % (r["ok"], r["sessions"], r["rtt_ms_p95"]) for h, r in lg.items()})
        rep.check("sweep SYNs were dropped, not answered", a["outcomes"].get("dropped", 0) > 500, a["outcomes"])
        denies = [e for e in lab.events() if e["action"] == "deny" and e["src"] == IP[3]]
        rep.check("controller saw only ~threshold packet-ins from the attacker (rule took over)",
                  5 <= len(denies) <= 12, "%d deny events for 1000 attempts" % len(denies))
        rep.check("h1/h2 never blocked", not any(MAC[h] in l and "priority=300" in l for h in (1, 2) for l in lab.dump_flows("s1")))
        gone, _ = lab.wait_for(lambda: not lab.has_flow("priority=300"), lab.block_time + 8)
        unb = wait_event(lab, 5, type_="RULE_EXPIRED", action="unblock", src=IP[3])
        rep.check("attacker recovers after the timeout", gone and unb is not None,
                  unb and "dropped %s packets while blocked" % unb["detail"].get("dropped_packets"))
        rep.check("h3 can use the allowed service again", lab.client("h3", 5000, "ping", count=3)["ok"])
        snapshot(lab, "flows_hard_after", "s1 flow table after the sweep scenario")

        # --- logger unreachable ----------------------------------------------
        time.sleep(lab.window + 1)
        n_before = len(lab.events())
        t_kill = time.time()
        lab.kill_logger()
        time.sleep(0.5)
        t0 = time.time()
        sweep2 = lab.attack("h3", "sweep", ports="2000-2299", rate=200, count=300, background=True)
        ok, _ = lab.wait_for(lambda: lab.has_flow("priority=300"), 5)
        rep.check("logger DOWN: attacker is still blocked (enforcement does not depend on the logger)", ok,
                  "after %.2fs" % (time.time() - t0))
        rep.check("logger DOWN: legitimate client unaffected", lab.client("h1", 5000, "ping", count=5)["ok"])
        sweep2.result()
        rep.check("logger DOWN: no events were stored by the (dead) logger meanwhile", len(lab.events()) == n_before)
        spooled = [e for e in lab.spool() if e["ts"] > t_kill]
        rep.check("logger DOWN: controller kept the events (queue + local spool file)", len(spooled) >= 1,
                  "%d events in controller_spool.jsonl" % len(spooled))
        lab.start_logger()
        ok, _ = lab.wait_for(lambda: any(e["type"] == "RULE_ESCALATED" and e["src"] == IP[3] and e["ts"] > t_kill
                                         for e in lab.events()), 20)
        rep.check("logger back: queued events are delivered (BLOCK of the second sweep arrives)", ok)
        late = [e for e in lab.events() if e["ts"] > t_kill]
        rep.check("logger back: delayed events keep their ORIGINAL timestamp (recv_ts is later)",
                  bool(late) and max(e["recv_ts"] - e["ts"] for e in late) > 0.5,
                  "max delivery delay %.1fs" % max(e["recv_ts"] - e["ts"] for e in late) if late else "")
        lab.wait_for(lambda: {e["eid"] for e in spooled} <= {e["eid"] for e in lab.events()}, 10)
        ids = [e["eid"] for e in lab.events()]
        rep.check("no lost / duplicated events after reconnect", len(ids) == len(set(ids))
                  and {e["eid"] for e in spooled} <= set(ids))


GROUPS = {"basic": group_basic, "autoblock": group_autoblock, "hard": group_hard}


def main():
    if os.geteuid() != 0:
        sys.exit("run with sudo (Mininet needs root)")
    names = sys.argv[1:] or list(GROUPS)
    os.makedirs(OUT, exist_ok=True)
    rep = Report()
    for n in names:
        GROUPS[n](rep)
    print("\n%d checks, %d passed, %d failed" % (len(rep.rows), len(rep.rows) - len(rep.failed), len(rep.failed)))
    with open(os.path.join(OUT, "report.json"), "w") as fh:
        json.dump(rep.rows, fh, indent=1)
    for r in rep.failed:
        print("FAILED:", r["name"], "|", r["detail"])
    sys.exit(1 if rep.failed else 0)


if __name__ == "__main__":
    main()
