"""python -m flowlens run.pcap [more.pcap ...] [--csv]"""
import argparse
import csv
import os
import sys

from .measure import COLUMNS, measure_pcap


def fmt(v, col):
    if v is None or v == "":
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if col.endswith("_s"):
        return f"{v * 1000:.3f}"
    return str(v)


def main():
    ap = argparse.ArgumentParser(prog="flowlens",
        description="Measure DNS, RTT, setup, TTFB, retransmissions and transfer time in a pcap.")
    ap.add_argument("pcaps", nargs="+", help="one or more .pcap files")
    ap.add_argument("--csv", action="store_true", help="print CSV instead of a table")
    a = ap.parse_args()

    rows = []
    for path in a.pcaps:
        r = measure_pcap(path, os.path.splitext(os.path.basename(path))[0])
        rows += r if isinstance(r, list) else [r]
    if not rows:
        sys.exit("no TCP connections found")

    if a.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
        return

    heads = [c[:-2] + "(ms)" if c.endswith("_s") else c for c in COLUMNS]
    cells = [[fmt(r.get(c), c) for c in COLUMNS] for r in rows]
    widths = [max(len(h), *(len(x[i]) for x in cells)) for i, h in enumerate(heads)]
    print("  ".join(h.rjust(w) for h, w in zip(heads, widths)))
    for x in cells:
        print("  ".join(v.rjust(w) for v, w in zip(x, widths)))


if __name__ == "__main__":
    main()
