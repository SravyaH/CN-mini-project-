#!/usr/bin/env python3
"""Draws docs/architecture.png and docs/flow.png (matplotlib only)."""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

OUT = os.path.dirname(os.path.abspath(__file__))
INK, MUTED = "#1a1a19", "#5f5e58"
BLUE, ORANGE, AQUA, GRAY, RED = "#2a78d6", "#eb6834", "#1baf7a", "#8b8a82", "#e34948"


def box(ax, x, y, w, h, text, color, fs=9, fill=0.12):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", linewidth=1.6,
                                edgecolor=color, facecolor=color, alpha=fill))
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", linewidth=1.6,
                                edgecolor=color, facecolor="none"))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK)


def arrow(ax, p, q, color=MUTED, style="-", text=None, tpos=0.5, dy=0.12, ha="center", fs=7.5):
    ax.annotate("", xy=q, xytext=p, arrowprops=dict(arrowstyle="-|>", color=color, lw=1.5, linestyle=style,
                                                    shrinkA=0, shrinkB=0))
    if text:
        ax.text(p[0] + (q[0] - p[0]) * tpos, p[1] + (q[1] - p[1]) * tpos + dy, text, ha=ha, fontsize=fs, color=color)


def architecture():
    fig, ax = plt.subplots(figsize=(11, 6.6))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6.6)
    ax.axis("off")
    ax.text(0.1, 6.35, "Dynamic firewall + security-event logger: architecture", fontsize=12, color=INK, weight="bold")

    box(ax, 3.4, 4.9, 3.0, 1.0, "SDN controller (Ryu, OpenFlow 1.3)\nfirewall engine + policy table\nescalation: deny -> block", ORANGE)
    box(ax, 8.4, 4.9, 2.5, 1.0, "Logger host  10.0.0.100:9999\nTCP logger server\nevents.jsonl / events.log", AQUA, fs=8.5)
    box(ax, 3.6, 2.9, 3.4, 0.9, "s1  EDGE switch (enforces)\nprio 300 block | 200 deny | 100 allow | 0 miss", BLUE, fs=8.5)
    box(ax, 8.0, 2.9, 2.2, 0.9, "s2  CORE switch\nL2 learning only", BLUE)
    for i, y in enumerate((3.55, 2.95, 2.35, 1.75, 1.15, 0.55)):
        name = "h%d" % (i + 1)
        role = "client" if i < 3 else ("extra client" if i < 5 else "attacker (measurements)")
        box(ax, 0.2, y, 2.6, 0.5, "%s  10.0.0.%d  %s" % (name, i + 1, role), GRAY, fs=8)
        arrow(ax, (2.8, y + 0.25), (3.6, 3.35 + (i - 2.5) * 0.1), GRAY)
    box(ax, 8.15, 1.0, 1.9, 0.9, "Application server\n10.0.0.10\n:5000 :5001 :5002", AQUA)

    arrow(ax, (7.0, 3.35), (8.0, 3.35), MUTED, text="1 Gbit", dy=0.08)
    arrow(ax, (9.1, 2.9), (9.1, 1.9), MUTED)
    arrow(ax, (9.9, 3.8), (9.9, 4.9), GRAY, "--")
    ax.text(10.0, 4.3, "data path\nto logger", fontsize=7, color=GRAY)
    arrow(ax, (4.6, 3.8), (4.6, 4.9), ORANGE)
    ax.text(4.5, 4.3, "OpenFlow\npacket-in / flow-mod", fontsize=7.5, color=ORANGE, ha="right", va="center")
    arrow(ax, (6.4, 5.4), (8.4, 5.4), RED)
    ax.text(7.4, 5.5, "security events\n(TCP, JSON lines)", fontsize=7.5, color=RED, ha="center", va="bottom")
    ax.text(7.4, 5.3, "mgmt link 192.168.99.1 -> .2", fontsize=6.8, color=RED, ha="center", va="top")

    ax.text(0.2, 4.4, "policy.json (src, dst, proto, port, action)", fontsize=8, color=MUTED)
    ax.text(4.0, 0.35, "red = event path, orange = control path, grey = data path.   Controller and logger are independent:\n"
            "if the logger dies the controller keeps enforcing and queues/spools events.", fontsize=8, color=MUTED)
    fig.savefig(os.path.join(OUT, "architecture.png"), dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def flow():
    fig, ax = plt.subplots(figsize=(11, 6.8))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6.8)
    ax.axis("off")
    ax.text(0.1, 6.55, "Request flow: client -> switch -> controller decision -> rule install -> event to logger",
            fontsize=12, color=INK, weight="bold")
    cols = [("Client\n(h1..h6)", 0.9, GRAY), ("s1 edge\nswitch", 3.1, BLUE), ("Controller\n(engine)", 5.3, ORANGE),
            ("App server\n10.0.0.10", 7.5, AQUA), ("Logger\n10.0.0.100", 9.7, AQUA)]
    for name, x, c in cols:
        box(ax, x - 0.8, 5.55, 1.6, 0.7, name, c, fs=8.5, fill=0.15)
        ax.plot([x, x], [0.25, 5.55], color=c, lw=1, ls=":")
    X = {n: x for n, x, _ in cols}
    C, S, K, A, L = 0.9, 3.1, 5.3, 7.5, 9.7
    steps = [
        (C, S, 5.1, "1  SYN to server:5000", MUTED),
        (S, K, 4.7, "2  table-miss -> packet-in (first packet only)", ORANGE),
        (K, K, 4.35, "3  classify src,dst,port  ->  ALLOW", ORANGE),
        (K, S, 4.0, "4  flow-mod  ALLOW prio 100 (+reverse) ; packet-out", ORANGE),
        (S, A, 3.65, "5  packet forwarded (later packets: switch only)", MUTED),
        (K, L, 3.3, "6  event {RULE_ADDED, src, dst, port, allow, ts}", RED),
        (C, S, 2.85, "7  SYN to server:5001 (forbidden)", MUTED),
        (S, K, 2.5, "8  packet-in", ORANGE),
        (K, S, 2.15, "9  flow-mod DENY prio 200 (drop) + event {deny}", ORANGE),
        (K, K, 1.8, "10  5th deny within 10 s  ->  ESCALATE", ORANGE),
        (K, S, 1.45, "11  flow-mod BLOCK prio 300 (in_port+MAC, hard_timeout) ; barrier", ORANGE),
        (K, L, 1.1, "12  events {block}, {block_active: response_ms}", RED),
        (S, K, 0.7, "13  flow-removed after timeout -> {unblock}, host recovers", ORANGE),
    ]
    for x0, x1, y, text, color in steps:
        if x0 == x1:
            ax.text(x0 + 0.15, y, text, fontsize=7.5, color=color, va="center")
            ax.plot([x0 - 0.1, x0 + 0.1], [y, y], color=color, lw=3)
        else:
            arrow(ax, (x0, y), (x1, y), color)
            ax.text((x0 + x1) / 2, y + 0.08, text, fontsize=7.2, color=color, ha="center")
    fig.savefig(os.path.join(OUT, "flow.png"), dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    flow()
    print("wrote architecture.png flow.png")
