"""Measure every pcap in a folder, diagnose with B1 and FlowLens, compare with the answer files.

Usage (from ~/flowlens):
    python -m flowlens.run data/test
Writes data/test/measurements.csv and prints a table plus scores.
"""
import csv
import glob
import json
import os
import sys

from .measure import measure_pcap, COLUMNS
from .baseline import b1_diagnose
from .evaluate import loss_unobserved
from .scorer import fit_reference, diagnose as fl_diagnose, NO_EVIDENCE

CAUSES = ["healthy", "dns", "delay", "server", "loss"]


def fmt(v, ms=True):
    if v is None or v == "":
        return "   -  "
    if isinstance(v, bool):
        return "yes" if v else "NO "
    return f"{v * 1000:6.0f}" if ms else f"{v:6}"


def scores(pairs):
    """pairs = [(truth, predicted)] -> per-class precision/recall/F1 and accuracy."""
    out = {}
    for c in CAUSES:
        tp = sum(1 for t, p in pairs if t == c and p == c)
        fp = sum(1 for t, p in pairs if t != c and p == c)
        fn = sum(1 for t, p in pairs if t == c and p != c)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out[c] = (tp, fp, fn, prec, rec, f1)
    acc = sum(1 for t, p in pairs if t == p) / len(pairs) if pairs else 0.0
    return out, acc


def print_scores(name, pairs):
    sc, acc = scores(pairs)
    print(f"\n{name} accuracy: {acc:.1%} on {len(pairs)} captures")
    print(f"{'cause':8} {'TP':>3} {'FP':>3} {'FN':>3} {'prec':>5} {'recall':>6} {'F1':>5}")
    for c, (tp, fp, fn, p, r, f1) in sc.items():
        if tp + fp + fn:
            print(f"{c:8} {tp:3} {fp:3} {fn:3} {p:5.2f} {r:6.2f} {f1:5.2f}")
    print(f"\nConfusion (rows = truth, cols = {name}):")
    print(f"{'':8}" + "".join(f"{c:>8}" for c in CAUSES))
    for t in CAUSES:
        print(f"{t:8}" + "".join(f"{sum(1 for a, b in pairs if a == t and b == p):8}"
                                 for p in CAUSES))


def main(folder, z_limit=3.5):
    pcaps = sorted(glob.glob(os.path.join(folder, "*.pcap")))
    if not pcaps:
        print("no .pcap files in", folder)
        return

    # pass 1: measure every capture
    captures = []          # (name, label, truth, curl, rows, main_row)
    for path in pcaps:
        name = os.path.splitext(os.path.basename(path))[0]
        rows = measure_pcap(path)
        truth, curl, label = "?", None, "?"
        jpath = path[:-5] + ".json"
        if os.path.exists(jpath):
            with open(jpath) as f:
                j = json.load(f)
            truth = j["problem"]
            label = f"{j['problem']}/{j['severity']}"
            curl = j.get("curl")
        # the web visit = the transaction that carried the most data
        main_row = max(rows, key=lambda r: r["bytes"] or 0) if rows else None
        captures.append((name, label, truth, curl, rows, main_row))

    # FlowLens reference = main transactions of healthy captures
    ref = fit_reference([m for _, _, t, _, _, m in captures if t == "healthy" and m])

    # pass 2: diagnose and print
    all_rows, b1_pairs, fl_pairs, no_dns, no_loss = [], [], [], [], []
    print(f"{'capture':10} {'truth':14} {'B1':8} {'FlowLens':8} {'dns':>6} {'rtt':>6} "
          f"{'setup':>6} {'ttfb':>6} {'srvwait':>7} {'retx':>4} {'total':>6}   "
          f"curl dns/conn/ttfb (ms)")
    for name, label, truth, curl, rows, main_row in captures:
        for r in rows:
            r["b1"], r["b1_all"] = b1_diagnose(r)
            d = fl_diagnose(r, ref, z_limit)
            r["fl"], r["fl_all"], r["fl_dns"] = d["cause"], d["flagged"], d["dns"]
            r["truth"] = truth
            all_rows.append(r)
        if main_row is None:
            print(f"{name:10} {label:14} no TCP connection found")
            continue
        r = main_row
        c = ""
        if curl:
            c = f"{curl['dns_s']*1000:.0f}/{curl['connect_s']*1000:.0f}/{curl['ttfb_s']*1000:.0f}"
        print(f"{name:10} {label:14} {r['b1']:8} {r['fl']:8} {fmt(r['dns_s'])} "
              f"{fmt(r['rtt_s'])} {fmt(r['setup_s'])} {fmt(r['ttfb_s'])} "
              f"{fmt(r['server_wait_s']):>7} {r['retx_count']:4} {fmt(r['total_s'])}   {c}")
        if r["fl_dns"] == NO_EVIDENCE:
            no_dns.append(name)
        if loss_unobserved(r):
            # loss was switched on but no packet was dropped: nothing to find
            print(f"{'':10} ^ no loss observed (0 retransmissions), left out of scores")
            no_loss.append(name)
        elif truth != "?":
            b1_pairs.append((truth, r["b1"]))
            fl_pairs.append((truth, r["fl"]))
    if no_loss:
        print(f"\nNo loss observed in {len(no_loss)} loss capture(s), not scored: "
              + ", ".join(no_loss))
    if no_dns:
        print(f"\nFlowLens DNS: {NO_EVIDENCE} in " + ", ".join(no_dns))

    out = os.path.join(folder, "measurements.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS + ["truth", "b1", "b1_all",
                                                    "fl", "fl_all", "fl_dns"])
        w.writeheader()
        for r in all_rows:
            w.writerow(dict(r, b1_all="+".join(r["b1_all"]), fl_all="+".join(r["fl_all"])))
    print(f"\nSaved {len(all_rows)} rows to {out}")

    if b1_pairs:
        print_scores("B1", b1_pairs)
        print_scores("FlowLens", fl_pairs)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/test")
