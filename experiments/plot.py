#!/usr/bin/env python3
"""Graphs + summary tables from results/*.csv.

    python3 experiments/plot.py [--in results] [--out results/graphs]
"""
import argparse
import collections
import csv
import os
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# one fixed colour per ENTITY (never per rank): categorical slots 1-3 of the default palette
COLORS = {"nofw": "#2a78d6", "static": "#eb6834", "dynamic": "#1baf7a"}
LABELS = {"nofw": "no firewall", "static": "static ACL", "dynamic": "dynamic SDN firewall"}
INK, MUTED, GRID = "#1a1a19", "#5f5e58", "#e3e2dc"


def read(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return list(csv.DictReader(fh))


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def style(ax, xlabel, ylabel, title=None):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.set_xlabel(xlabel, color=MUTED, fontsize=9)
    ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
    if title:
        ax.set_title(title, color=INK, fontsize=10, loc="left")


def save(fig, out, name):
    path = os.path.join(out, name)
    fig.savefig(path, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", path)


def by_mode_lines(rows, metric, clients_list, out, name, ylabel, title):
    rows = [r for r in rows if num(r.get(metric)) is not None]
    if not rows:
        return
    fig, axes = plt.subplots(1, len(clients_list), figsize=(4.2 * len(clients_list), 3.6), sharey=True, squeeze=False)
    for ax, n in zip(axes[0], clients_list):
        rates = sorted({int(r["attack_rate"]) for r in rows})
        for mode in ("nofw", "static", "dynamic"):
            ys = []
            for rate in rates:
                v = [num(r[metric]) for r in rows if r["mode"] == mode and int(r["clients"]) == n
                     and int(r["attack_rate"]) == rate and num(r[metric]) is not None]
                ys.append(statistics.mean(v) if v else None)
            pts = [(i, y) for i, y in enumerate(ys) if y is not None]
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], color=COLORS[mode], linewidth=2,
                        marker="o", markersize=5, markeredgecolor="white", label=LABELS[mode])
        ax.set_xticks(range(len(rates)))
        ax.set_xticklabels([str(r) for r in rates])
        style(ax, "attack rate (attempts/s)", ylabel if ax is axes[0][0] else "", "%d legitimate client%s" % (n, "" if n == 1 else "s"))
    axes[0][0].legend(frameon=False, fontsize=8, loc="best")
    fig.suptitle(title, color=INK, fontsize=11, x=0.01, y=1.04, ha="left")
    save(fig, out, name)


def plot_response(rows, out):
    rows = [r for r in rows if num(r.get("response_ms")) is not None]
    if not rows:
        return
    def agg(sel):
        groups = collections.defaultdict(list)
        for r in sel:
            groups[(int(r["attack_rate"]), int(r["threshold"]))].append(r)
        return groups
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.5, 4.2))
    other = sorted({int(r["attack_rate"]) for r in rows if r["threshold"] != "5"})
    sweep_rate = str(200 if 200 in other else (other[-1] if other else 200))
    for ax, sel, key, xl, title in (
            (a1, [r for r in rows if r["threshold"] == "5"], 0, "attack rate (attempts/s)", "threshold = 5 denies"),
            (a2, [r for r in rows if r["attack_rate"] == sweep_rate], 1, "block threshold (denies)",
             "attack rate = %s/s" % sweep_rate)):
        g = agg(sel)
        keys = sorted(g, key=lambda k: k[key])
        det = [statistics.mean(num(r["detection_ms"]) for r in g[k]) for k in keys]
        ins = [statistics.mean(num(r["install_ms"]) for r in g[k]) for k in keys]
        x = range(len(keys))
        ax.bar(x, det, color="#2a78d6", width=0.55, label="detection: 1st violation to threshold reached")
        ax.bar(x, ins, bottom=det, color="#eb6834", width=0.55, label="install: decision to barrier reply")
        for i, k in enumerate(keys):
            ax.text(i, det[i] + ins[i], "%.0f ms" % (det[i] + ins[i]), ha="center", va="bottom", fontsize=8, color=INK)
        ax.set_xticks(list(x))
        ax.set_xticklabels([str(k[key]) for k in keys])
        style(ax, xl, "time (ms)", title)
    h, l = a1.get_legend_handles_labels()
    fig.legend(h, l, frameon=False, fontsize=8, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.04))
    fig.suptitle("Blocking response time: first violation to drop rule active in the switch", color=INK,
                 fontsize=11, x=0.01, y=1.0, ha="left")
    fig.tight_layout(rect=(0, 0.05, 1, 0.96))
    save(fig, out, "response_time.png")


def plot_flows(rows, out):
    rows = [r for r in rows if num(r.get("flows_max")) is not None]
    if not rows:
        return
    n = max(int(r["clients"]) for r in rows)
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    rates = sorted({int(r["attack_rate"]) for r in rows})
    for mode in ("nofw", "static", "dynamic"):
        ys = [next((num(r["flows_max"]) for r in rows if r["mode"] == mode and int(r["clients"]) == n
                    and int(r["attack_rate"]) == rt), None) for rt in rates]
        pts = [(i, y) for i, y in enumerate(ys) if y is not None]
        if pts:
            ax.plot([p[0] for p in pts], [p[1] for p in pts], color=COLORS[mode], linewidth=2, marker="o",
                    markersize=5, markeredgecolor="white", label=LABELS[mode])
    ax.set_xticks(range(len(rates)))
    ax.set_xticklabels([str(r) for r in rates])
    style(ax, "attack rate (attempts/s)", "flow entries on s1 (peak)", "Flow-table size, %d legitimate clients" % n)
    ax.legend(frameon=False, fontsize=8)
    save(fig, out, "flow_table_size.png")


def plot_cold(rows, out):
    rows = [r for r in rows if num(r.get("cold_connect_ms")) is not None]
    if not rows:
        return
    modes = [m for m in ("nofw", "static", "dynamic") if any(r["mode"] == m for r in rows)]
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    for i, m in enumerate(modes):
        cold = statistics.median(num(r["cold_connect_ms"]) for r in rows if r["mode"] == m)
        warm = statistics.median(num(r["warm_connect_ms"]) for r in rows if r["mode"] == m)
        ax.bar(i - 0.2, cold, 0.36, color=COLORS[m], label="first connection" if i == 0 else None)
        ax.bar(i + 0.2, warm, 0.36, color=COLORS[m], alpha=0.45, label="next connection" if i == 0 else None)
        ax.text(i - 0.2, cold, "%.1f" % cold, ha="center", va="bottom", fontsize=8, color=INK)
        ax.text(i + 0.2, warm, "%.1f" % warm, ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_xticks(range(len(modes)))
    ax.set_xticklabels([LABELS[m] for m in modes], fontsize=8)
    style(ax, "", "TCP connect time (ms, median of 5 clients)", "Cost of the first packet (flow set-up via controller)")
    ax.legend(frameon=False, fontsize=8)
    save(fig, out, "cold_start.png")


def summary(impact, response, cold, out):
    lines = ["# Measurement summary", ""]
    if response:
        lines += ["## Blocking response time (dynamic mode, ms)", "",
                  "| attack rate /s | threshold | trials | detection | install | response (total) | observed externally |",
                  "|---|---|---|---|---|---|---|"]
        g = collections.defaultdict(list)
        for r in response:
            if num(r.get("response_ms")) is not None:
                g[(int(r["threshold"]), int(r["attack_rate"]))].append(r)
        for (th, rate), rs in sorted(g.items()):
            m = lambda k: statistics.mean(num(r[k]) for r in rs if num(r[k]) is not None) if any(num(r[k]) is not None for r in rs) else float("nan")
            lines.append("| %d | %d | %d | %.1f | %.1f | %.1f | %.1f |" % (rate, th, len(rs), m("detection_ms"),
                                                                           m("install_ms"), m("response_ms"), m("observed_ms")))
        lines.append("")
    if impact:
        lines += ["## Network impact", "",
                  "| mode | legit clients | attack /s | success | RTT p50 | RTT p95 | RTT p99 | conn p95 | Mbit/s per client | peak flows | attacker reached server | blocked |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in sorted(impact, key=lambda r: (r["mode"], int(r["clients"]), int(r["attack_rate"]))):
            lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
                LABELS[r["mode"]], r["clients"], r["attack_rate"], r["success_rate"], r["rtt_p50_ms"], r["rtt_p95_ms"],
                r["rtt_p99_ms"], r["connect_p95_ms"], r["throughput_per_client_mbps"], r["flows_max"],
                r["attack_reached_server"], r["blocked"] or "-"))
        lines.append("")
    if cold:
        lines += ["## First-connection cost (ms)", "", "| mode | first connection (median) | next connection (median) |", "|---|---|---|"]
        for m in ("nofw", "static", "dynamic"):
            rs = [r for r in cold if r["mode"] == m and num(r["cold_connect_ms"]) is not None]
            if rs:
                lines.append("| %s | %.2f | %.2f |" % (LABELS[m], statistics.median(num(r["cold_connect_ms"]) for r in rs),
                                                       statistics.median(num(r["warm_connect_ms"]) for r in rs)))
    with open(os.path.join(out, "summary.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote", os.path.join(out, "summary.md"))


def main():
    ap = argparse.ArgumentParser()
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    ap.add_argument("--in", dest="inp", default=here)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or os.path.join(a.inp, "graphs")
    os.makedirs(out, exist_ok=True)
    impact, response, cold = (read(os.path.join(a.inp, n + ".csv")) for n in ("impact", "response", "coldstart"))
    if not (impact or response or cold):
        sys.exit("no CSVs in %s - run experiments/measure.py first" % a.inp)
    clients = sorted({int(r["clients"]) for r in impact})
    by_mode_lines(impact, "rtt_p95_ms", clients, out, "latency_p95.png", "RTT p95 (ms)",
                  "Latency of legitimate clients while an attacker connects to a forbidden port")
    by_mode_lines(impact, "throughput_per_client_mbps", clients, out, "throughput.png", "Mbit/s per client",
                  "Bulk throughput of legitimate clients under attack")
    plot_flows(impact, out)
    plot_response(response, out)
    plot_cold(cold, out)
    summary(impact, response, cold, a.out or a.inp)


if __name__ == "__main__":
    main()
