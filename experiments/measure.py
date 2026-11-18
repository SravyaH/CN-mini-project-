#!/usr/bin/env python3
"""Measurements: blocking response time and network impact.

    sudo python3 experiments/measure.py                 # full run (~25 min)
    sudo python3 experiments/measure.py --quick         # smaller grid (~8 min)

Writes CSVs to results/:
    coldstart.csv   first-connection vs warm connection time per client and mode
    response.csv    dynamic mode: first violation -> active drop rule, per attack rate / threshold
    impact.csv      legit-client latency & throughput, flow-table size, attacker outcome
                    for mode x clients x attack-rate
Then run  python3 experiments/plot.py  to turn them into graphs.

Definitions
  response time   = first_violation_ts (first denied attempt seen by the controller)
                    -> barrier reply confirming the drop rule is active in the switch.
                    detection part = first violation -> threshold-th violation reaches the controller,
                    install part   = decision -> barrier reply.
  network impact  = latency (RTT p50/p95/p99 of PING round trips) and connect time of legitimate
                    sessions, bulk throughput (GET 25 MB), flow-table entries on s1, measured while an
                    attacker (h6) sends forbidden-port connection attempts at a fixed rate.
"""
import argparse
import csv
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from topo import constants as T  # noqa: E402

RESULTS = os.path.join(T.ROOT, "results")
ATTACKER = "h6"
ATTACKER_IP = T.client_ip(6)


def pct(values, p):
    if not values:
        return ""
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 3)


def mean(values):
    return round(sum(values) / len(values), 3) if values else ""


def write_csv(path, rows, fields):
    new = not os.path.exists(path)
    with open(path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if new:
            w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


class FlowSampler(threading.Thread):
    """Samples the number of flow entries on s1 while an experiment runs."""

    def __init__(self, lab, period=0.25):
        super().__init__(daemon=True)
        self.lab, self.period, self.samples, self._halt = lab, period, [], threading.Event()

    def run(self):
        while not self._halt.is_set():
            n = self.lab.flow_count("s1")
            if n >= 0:
                self.samples.append(n)
            time.sleep(self.period)

    def finish(self):
        self._halt.set()
        self.join(3)
        return self.samples


def settle(lab, mode):
    """Wait until no block is active so every run starts from the same state."""
    if mode == "dynamic":
        lab.wait_for(lambda: not lab.has_flow("priority=300"), lab.block_time + 10)
        time.sleep(1.0)
        time.sleep(max(0, lab.window - lab.block_time) + 0.5)     # make sure counters are empty


def block_event(lab, since):
    for e in lab.events():
        d = e.get("detail", {})
        if e["type"] == "CONTROLLER" and d.get("what") == "block_active" and e["src"] == ATTACKER_IP \
                and e["ts"] >= since:
            return e
    return None


# ----------------------------------------------------------------------
def exp_coldstart(lab, mode, clients):
    rows = []
    for i in range(1, clients + 1):
        h = "h%d" % i
        cold = lab.client(h, 5000, "connect", timeout=3)
        warm = lab.client(h, 5000, "connect", timeout=3)
        rows.append({"mode": mode, "client": h, "cold_connect_ms": cold.get("connect_ms", ""),
                     "warm_connect_ms": warm.get("connect_ms", "")})
    return rows


def exp_impact(lab, mode, n_clients, rate, duration):
    settle(lab, mode)
    since = time.time()
    # ---- phase A: latency / connect time under attack ------------------------
    sampler = FlowSampler(lab)
    sampler.start()
    jobs = [lab.legit("h%d" % i, duration=duration, pings=5, background=True) for i in range(1, n_clients + 1)]
    atk = None
    if rate > 0:
        time.sleep(1.0)
        atk = lab.attack(ATTACKER, "burst", port=5001, rate=rate, duration=max(1.0, duration - 1.0),
                         background=True)
    legit = [j.result() for j in jobs]
    attack = atk.result() if atk else {}
    flows = sampler.finish()
    rtts = [x for r in legit for x in r.get("rtts", [])]
    conns = [x for r in legit for x in r.get("connects", [])]
    sessions = sum(r["sessions"] for r in legit)
    ok = sum(r["ok"] for r in legit)
    ev = block_event(lab, since) if mode == "dynamic" and rate > 0 else None

    # ---- phase B: bulk throughput under attack -------------------------------
    settle(lab, mode)
    atk = None
    if rate > 0:
        atk = lab.attack(ATTACKER, "burst", port=5001, rate=rate, duration=6.0, background=True)
        time.sleep(0.5)
    gets = [lab.popen_json("h%d" % i, ["python3", "app/client.py", "--host", T.SRV_IP, "--port", "5000",
                                         "--mode", "get", "--size", "25000000", "--timeout", "20"])
            for i in range(1, n_clients + 1)]
    thr = [g.result() for g in gets]
    if atk:
        atk.result()
    mbps = [t["mbps"] for t in thr if t.get("ok") and t.get("mbps")]

    out = attack.get("outcomes", {})
    return {
        "mode": mode, "clients": n_clients, "attack_rate": rate,
        "sessions": sessions, "success_rate": round(ok / sessions, 4) if sessions else "",
        "rtt_p50_ms": pct(rtts, 50), "rtt_p95_ms": pct(rtts, 95), "rtt_p99_ms": pct(rtts, 99),
        "connect_p50_ms": pct(conns, 50), "connect_p95_ms": pct(conns, 95),
        "throughput_per_client_mbps": mean(mbps), "throughput_total_mbps": round(sum(mbps), 3) if mbps else "",
        "bulk_ok": "%d/%d" % (len(mbps), n_clients),
        "flows_max": max(flows) if flows else "", "flows_mean": mean(flows),
        "attack_attempts": attack.get("attempts", 0), "attack_reached_server": out.get("connected", 0),
        "attack_dropped": out.get("dropped", 0), "attack_refused": out.get("refused", 0),
        "blocked": "yes" if ev else ("no" if mode == "dynamic" and rate > 0 else ""),
        "response_ms": ev["detail"]["response_ms"] if ev else "",
    }


def exp_response(lab, rate, trial, threshold):
    settle(lab, "dynamic")
    t0 = time.time()
    seen = {}

    def watch():
        end = time.time() + 6
        while time.time() < end and "t" not in seen:
            if lab.has_flow("priority=300"):
                seen["t"] = time.time()
            time.sleep(0.005)

    w = threading.Thread(target=watch, daemon=True)
    w.start()
    a = lab.attack(ATTACKER, "burst", port=5001, rate=rate, count=max(40, threshold * 4), background=False)
    w.join(7)
    ok, _ = lab.wait_for(lambda: block_event(lab, t0) is not None, 5)
    ev = block_event(lab, t0)
    esc = next((e for e in lab.events() if e["type"] == "RULE_ESCALATED" and e["src"] == ATTACKER_IP
                and e["ts"] >= t0), None)
    row = {"attack_rate": rate, "threshold": threshold, "trial": trial}
    if ev and esc:
        row.update({
            "detection_ms": esc["detail"]["detection_ms"], "install_ms": ev["detail"]["install_ms"],
            "response_ms": ev["detail"]["response_ms"],
            "observed_ms": round((seen["t"] - a["first_attempt_ts"]) * 1000, 1) if "t" in seen else "",
        })
    return row


# ----------------------------------------------------------------------
def main(lab_factory=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--modes", nargs="+", default=["nofw", "static", "dynamic"])
    ap.add_argument("--clients", nargs="+", type=int, default=[1, 3, 5])
    ap.add_argument("--rates", nargs="+", type=int, default=[0, 50, 200, 1000])
    ap.add_argument("--response-rates", nargs="+", type=int, default=[10, 50, 200, 1000])
    ap.add_argument("--thresholds", nargs="+", type=int, default=[3, 5, 10, 20])
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--duration", type=float, default=6.0)
    ap.add_argument("--block-time", type=int, default=8)
    ap.add_argument("--out", default=RESULTS)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    if a.quick:
        a.clients, a.rates, a.response_rates, a.thresholds, a.trials, a.duration = [1, 5], [0, 200], [50, 500], [5, 10], 2, 4.0
    os.makedirs(a.out, exist_ok=True)
    if lab_factory is None:
        if os.geteuid() != 0:
            sys.exit("run with sudo")
        from topo.harness import Lab
        lab_factory = Lab

    cold_f = ["mode", "client", "cold_connect_ms", "warm_connect_ms"]
    imp_f = ["mode", "clients", "attack_rate", "sessions", "success_rate", "rtt_p50_ms", "rtt_p95_ms", "rtt_p99_ms",
             "connect_p50_ms", "connect_p95_ms", "throughput_per_client_mbps", "throughput_total_mbps", "bulk_ok",
             "flows_max", "flows_mean", "attack_attempts", "attack_reached_server", "attack_dropped",
             "attack_refused", "blocked", "response_ms"]
    resp_f = ["attack_rate", "threshold", "trial", "detection_ms", "install_ms", "response_ms", "observed_ms"]

    for mode in a.modes:
        print("=== mode %s" % mode, flush=True)
        with lab_factory(mode, clients=6, out_dir=os.path.join(a.out, "lab_" + mode), block_time=a.block_time) as lab:
            lab.net.pingAll(timeout="2")          # warm flows; cold start is measured in its own run below
            time.sleep(0.5)
            for n in a.clients:
                for rate in a.rates:
                    print("  impact: clients=%d rate=%d" % (n, rate), flush=True)
                    write_csv(os.path.join(a.out, "impact.csv"), [exp_impact(lab, mode, n, rate, a.duration)], imp_f)
        # cold start: fresh controller + network, no warm-up traffic at all
        with lab_factory(mode, clients=6, out_dir=os.path.join(a.out, "lab_%s_cold" % mode),
                         block_time=a.block_time) as lab:
            write_csv(os.path.join(a.out, "coldstart.csv"), exp_coldstart(lab, mode, 5), cold_f)

    if "dynamic" in a.modes:
        print("=== response time (dynamic)", flush=True)
        for th in a.thresholds:
            with lab_factory("dynamic", clients=6, out_dir=os.path.join(a.out, "lab_resp_th%d" % th),
                             block_time=a.block_time, threshold=th) as lab:
                rates = a.response_rates if th == 5 or a.quick else [200]
                for rate in rates:
                    for trial in range(1, a.trials + 1):
                        print("  threshold=%d rate=%d trial=%d" % (th, rate, trial), flush=True)
                        write_csv(os.path.join(a.out, "response.csv"), [exp_response(lab, rate, trial, th)], resp_f)
    print("done -> %s" % a.out)


if __name__ == "__main__":
    main()
