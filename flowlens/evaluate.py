"""Compare B1 and FlowLens on a measurements.csv written by flowlens.run.

Usage:
    python -m flowlens.evaluate data/practice/measurements.csv [--out results]

One row per capture is used: the transaction with the most bytes (the web
visit).  Captures with no truth ("?") and loss captures where no loss was
observed (0 retransmissions, 0 SYN resends) are left out, same as run.py.

FlowLens answers are taken from the CSV's fl column by default.  With
--reference, FlowLens is run again on every scored capture, learning what
"healthy" looks like only from the healthy captures in the reference CSV
(never from the captures being scored).

Truth may name two problems joined by "+" (e.g. "dns+loss").  A diagnosis is
correct when its main cause is one of the true problems (top-1 accuracy).

Writes to the output folder (default: results/):
    eval_per_cause.csv   precision, recall, F1 per cause, for each method
    eval_summary.csv     top-1 accuracy, false-alarm rate (95% Wilson CI)
    eval_mcnemar.csv     McNemar's test, B1 vs FlowLens
"""
import argparse
import csv
import math
import os
from collections import defaultdict

from .scorer import fit_reference, load_reference, same_file, diagnose as fl_diagnose

CAUSES = ["healthy", "dns", "delay", "server", "loss"]
METHODS = {"B1": "b1", "FlowLens": "fl"}       # name -> CSV column


def loss_unobserved(row):
    """True for a loss capture where no packet was actually resent."""
    num = lambda v: float(v) if v not in (None, "") else 0.0
    return row["truth"] == "loss" and not (num(row["retx_count"]) or num(row["syn_retx"]))


def main_rows(path):
    """measurements.csv -> (scored rows, one per capture; skipped capture ids)."""
    best = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            b = float(r["bytes"] or 0)
            if r["capture_id"] not in best or b > best[r["capture_id"]][0]:
                best[r["capture_id"]] = (b, r)
    rows, skipped = [], []
    for cid in sorted(best):
        r = best[cid][1]
        if r["truth"] in ("", "?") or loss_unobserved(r):
            skipped.append(cid)
        else:
            rows.append(r)
    return rows, skipped


def truth_set(row):
    return set(row["truth"].split("+"))


def correct(row, col):
    return row[col] in truth_set(row)


def per_cause(rows, col):
    """Precision / recall / F1 per cause.
    TP: said c and c is true.  FP: said c and c is not true.
    FN: c is true and the method's answer was wrong (not one of the true causes)."""
    out = []
    for c in CAUSES:
        tp = sum(1 for r in rows if r[col] == c and c in truth_set(r))
        fp = sum(1 for r in rows if r[col] == c and c not in truth_set(r))
        fn = sum(1 for r in rows if c in truth_set(r) and not correct(r, col))
        support = sum(1 for r in rows if c in truth_set(r))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out.append({"cause": c, "tp": tp, "fp": fp, "fn": fn, "support": support,
                    "precision": prec, "recall": rec, "f1": f1})
    return out


def wilson(k, n, z=1.96):
    """95% Wilson confidence interval for k successes out of n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))


def mcnemar(b, c):
    """McNemar's test on the disagreements.
    b = captures only method A got right, c = captures only method B got right.
    Exact binomial test when b + c < 25, else chi-square with continuity correction.
    Returns (test name, statistic, p-value)."""
    n = b + c
    if n == 0:
        return ("exact", 0.0, 1.0)
    if n < 25:
        k = min(b, c)
        p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
        return ("exact", float(k), min(1.0, p))
    stat = (abs(b - c) - 1) ** 2 / n
    return ("chi2", stat, math.erfc(math.sqrt(stat / 2)))   # chi-square, 1 df


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.3f}" if isinstance(v, float) else v) for k, v in r.items()})


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m flowlens.evaluate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="measurements.csv from flowlens.run")
    ap.add_argument("--out", default="results", help="output folder")
    ap.add_argument("--reference", metavar="CSV",
                    help="measurements CSV whose healthy captures FlowLens learns from; "
                         "FlowLens is re-run instead of using the fl column")
    a = ap.parse_args(argv)
    for path in [a.csv] + ([a.reference] if a.reference else []):
        if not os.path.isfile(path):
            ap.error(f"file not found: {path}")
    if a.reference and same_file(a.reference, a.csv):
        ap.error("--reference must be a different set from the CSV being scored")
    os.makedirs(a.out, exist_ok=True)

    rows, skipped = main_rows(a.csv)
    if not rows:
        print("no labelled captures to score")
        return
    if a.reference:
        ref_rows = load_reference(a.reference)
        ref = fit_reference(ref_rows)
        for r in rows:
            r["fl"] = fl_diagnose(r, ref)["cause"]
        print(f"FlowLens re-run with reference: {len(ref_rows)} healthy captures "
              f"from {a.reference}")
    healthy = [r for r in rows if r["truth"] == "healthy"]
    print(f"{len(rows)} captures scored ({len(healthy)} healthy), "
          f"{len(skipped)} left out: {', '.join(skipped) or '-'}\n")

    # ---- per cause ----
    cause_rows = []
    for name, col in METHODS.items():
        for d in per_cause(rows, col):
            cause_rows.append({"method": name, **d})
    print(f"{'method':9} {'cause':8} {'n':>3} {'TP':>3} {'FP':>3} {'FN':>3} "
          f"{'prec':>5} {'recall':>6} {'F1':>5}")
    for d in cause_rows:
        print(f"{d['method']:9} {d['cause']:8} {d['support']:3} {d['tp']:3} {d['fp']:3} "
              f"{d['fn']:3} {d['precision']:5.2f} {d['recall']:6.2f} {d['f1']:5.2f}")

    # ---- summary: top-1 accuracy, false alarms ----
    summary = []
    for name, col in METHODS.items():
        k = sum(correct(r, col) for r in rows)
        fa = sum(1 for r in healthy if r[col] != "healthy")
        lo, hi = wilson(fa, len(healthy))
        alo, ahi = wilson(k, len(rows))
        summary.append({"method": name, "captures": len(rows), "top1_correct": k,
                        "top1_accuracy": k / len(rows), "top1_ci_low": alo, "top1_ci_high": ahi,
                        "healthy": len(healthy), "false_alarms": fa,
                        "false_alarm_rate": fa / len(healthy) if healthy else 0.0,
                        "fa_ci_low": lo, "fa_ci_high": hi})
    print(f"\n{'method':9} {'top-1 accuracy (95% CI)':28} {'false alarms on healthy (95% CI)'}")
    for s in summary:
        print(f"{s['method']:9} {s['top1_correct']:3}/{s['captures']:<3} = {s['top1_accuracy']:6.1%} "
              f"[{s['top1_ci_low']:.0%}, {s['top1_ci_high']:.0%}]   "
              f"{s['false_alarms']:3}/{s['healthy']:<3} = {s['false_alarm_rate']:6.1%} "
              f"[{s['fa_ci_low']:.0%}, {s['fa_ci_high']:.0%}]")

    # ---- McNemar: same captures, B1 vs FlowLens ----
    table = defaultdict(int)
    for r in rows:
        table[(correct(r, "b1"), correct(r, "fl"))] += 1
    only_b1, only_fl = table[(True, False)], table[(False, True)]
    test, stat, p = mcnemar(only_b1, only_fl)
    mc = [{"both_right": table[(True, True)], "only_b1_right": only_b1,
           "only_flowlens_right": only_fl, "both_wrong": table[(False, False)],
           "test": test, "statistic": stat, "p_value": p}]
    print(f"\nMcNemar B1 vs FlowLens: both right {mc[0]['both_right']}, only B1 right {only_b1}, "
          f"only FlowLens right {only_fl}, both wrong {mc[0]['both_wrong']}")
    print(f"  {test} test, p = {p:.4f}"
          + ("  (difference is significant at 0.05)" if p < 0.05 else "  (not significant at 0.05)"))

    write_csv(os.path.join(a.out, "eval_per_cause.csv"), cause_rows, list(cause_rows[0]))
    write_csv(os.path.join(a.out, "eval_summary.csv"), summary, list(summary[0]))
    write_csv(os.path.join(a.out, "eval_mcnemar.csv"), mc, list(mc[0]))
    print(f"\nSaved to {a.out}/: eval_per_cause.csv, eval_summary.csv, eval_mcnemar.csv")


if __name__ == "__main__":
    main()
