"""Measure every pcap in a folder, diagnose with B1, compare with the answer files.

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


def main(folder):
    pcaps = sorted(glob.glob(os.path.join(folder, "*.pcap")))
    if not pcaps:
        print("no .pcap files in", folder)
        return
    all_rows, pairs = [], []
    print(f"{'capture':10} {'truth':14} {'B1':8} {'dns':>6} {'rtt':>6} {'setup':>6} "
          f"{'ttfb':>6} {'srvwait':>7} {'retx':>4} {'total':>6}   curl dns/conn/ttfb (ms)")
    for path in pcaps:
        name = os.path.splitext(os.path.basename(path))[0]
        rows = measure_pcap(path)
        truth, curl = "?", None
        jpath = path[:-5] + ".json"
        if os.path.exists(jpath):
            with open(jpath) as f:
                j = json.load(f)
            truth = j["problem"]
            label = f"{j['problem']}/{j['severity']}"
            curl = j.get("curl")
        else:
            label = "?"
        # the web visit = the transaction that carried the most data
        main_row = max(rows, key=lambda r: r["bytes"] or 0) if rows else None
        for r in rows:
            r["b1"], r["b1_all"] = b1_diagnose(r)
            r["truth"] = truth
            all_rows.append(r)
        if main_row is None:
            print(f"{name:10} {label:14} no TCP connection found")
            continue
        r = main_row
        c = ""
        if curl:
            c = f"{curl['dns_s']*1000:.0f}/{curl['connect_s']*1000:.0f}/{curl['ttfb_s']*1000:.0f}"
        print(f"{name:10} {label:14} {r['b1']:8} {fmt(r['dns_s'])} {fmt(r['rtt_s'])} "
              f"{fmt(r['setup_s'])} {fmt(r['ttfb_s'])} {fmt(r['server_wait_s']):>7} "
              f"{r['retx_count']:4} {fmt(r['total_s'])}   {c}")
        if truth != "?":
            pairs.append((truth, r["b1"]))

    out = os.path.join(folder, "measurements.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS + ["truth", "b1", "b1_all"])
        w.writeheader()
        for r in all_rows:
            r = dict(r, b1_all="+".join(r["b1_all"]))
            w.writerow(r)
    print(f"\nSaved {len(all_rows)} rows to {out}")

    if pairs:
        sc, acc = scores(pairs)
        print(f"\nB1 accuracy: {acc:.1%} on {len(pairs)} captures")
        print(f"{'cause':8} {'TP':>3} {'FP':>3} {'FN':>3} {'prec':>5} {'recall':>6} {'F1':>5}")
        for c, (tp, fp, fn, p, r, f1) in sc.items():
            if tp + fp + fn:
                print(f"{c:8} {tp:3} {fp:3} {fn:3} {p:5.2f} {r:6.2f} {f1:5.2f}")
        print("\nConfusion (rows = truth, cols = B1):")
        print(f"{'':8}" + "".join(f"{c:>8}" for c in CAUSES))
        for t in CAUSES:
            print(f"{t:8}" + "".join(f"{sum(1 for a, b in pairs if a == t and b == p):8}"
                                     for p in CAUSES))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/test")
