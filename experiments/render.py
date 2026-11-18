"""Turn `ovs-ofctl dump-flows` output into a compact text table / PNG 'screenshot'."""
import re


def condense(line):
    head, _, actions = line.partition(" actions=")
    toks = [t.strip() for t in head.split(", ")]
    kv = dict(t.split("=", 1) for t in toks[:-1] if "=" in t)
    pri, _, match = toks[-1].partition(",")
    prio = int(pri.split("=")[1]) if pri.startswith("priority=") else 0
    return {
        "prio": prio, "match": match or "(any)", "actions": actions or "drop",
        "pkts": kv.get("n_packets", "0"), "idle": kv.get("idle_timeout", "0"),
        "hard": kv.get("hard_timeout", "0"),
    }


def table_lines(flow_lines):
    rows = sorted((condense(l) for l in flow_lines), key=lambda r: -r["prio"])
    out = []
    for r in rows:
        out.append("prio %3d  %-78s -> %-22s pkts=%-5s idle=%-3s hard=%s" % (
            r["prio"], r["match"][:78], r["actions"][:22], r["pkts"], r["idle"], r["hard"]))
    return out or ["(flow table is empty)"]


def save_text(flow_lines, path, title=""):
    with open(path, "w") as fh:
        if title:
            fh.write(title + "\n" + "=" * len(title) + "\n")
        fh.write("\n".join(table_lines(flow_lines)) + "\n")


def save_png(flow_lines, path, title=""):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    lines = table_lines(flow_lines)
    width = max(len(l) for l in lines + [title])
    fig_h = 0.9 + 0.22 * (len(lines) + 1)
    fig = plt.figure(figsize=(max(8, width * 0.082), fig_h), facecolor="#101418")
    fig.text(0.01, 1 - 0.35 / fig_h, title, color="#e6edf3", family="monospace", fontsize=10, weight="bold")
    for i, l in enumerate(lines):
        color = "#ff7b72" if "actions=drop" in l or "-> drop" in l else "#7ee787"
        if re.match(r"prio 300", l):
            color = "#ffa657"
        if l.startswith("prio   0"):
            color = "#8b949e"
        fig.text(0.01, 1 - (0.75 + 0.22 * i) / fig_h, l, color=color, family="monospace", fontsize=8)
    fig.savefig(path, dpi=130, facecolor=fig.get_facecolor())
    plt.close(fig)
