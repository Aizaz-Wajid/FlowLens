"""Make result plots from a measurements.csv.

Usage:
    python -m flowlens.plots data/test/measurements.csv [--out results]

Captures are chosen the same way as flowlens.evaluate: one row per capture
(the flow with the most bytes); no-truth captures and loss captures with no
observed loss are left out.

Writes to the output folder (default: results/):
    delay_breakdown.png  average delay parts per truth problem
    b1_confusion.png     B1 confusion matrix (rows = truth, columns = B1)
    b1_scores.csv        precision, recall, F1 per cause
    fl_confusion.png     FlowLens confusion matrix   (if the CSV has an fl column)
    fl_scores.csv        FlowLens precision, recall, F1 per cause
    f1_compare.png       per-cause F1, B1 next to FlowLens
"""

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # write files only, no window
import matplotlib.pyplot as plt
import matplotlib.ticker
import pandas as pd

from flowlens.evaluate import loss_unobserved

PROBLEMS = ["healthy", "dns", "delay", "server", "loss"]

# Delay parts shown in the bar chart, with readable names.
PARTS = {
    "dns_s": "DNS",
    "rtt_s": "RTT",
    "server_wait_s": "Server wait",
    "retx_time_s": "Retransmission",
}
# Fixed categorical colors (blue, orange, aqua, yellow), one per delay part.
PART_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]

# One fixed color per method, used in every comparison chart.
METHOD_COLORS = {"B1": "#2a78d6", "FlowLens": "#eb6834"}
METHOD_COLS = {"B1": "b1", "FlowLens": "fl"}

TEXT = "#2b2b29"
MUTED = "#6b6a63"
GRID = "#e4e3de"


def main_transactions(df):
    """Keep one row per capture: the flow with the most bytes."""
    idx = df.groupby("capture_id")["bytes"].idxmax()
    main = df.loc[idx].reset_index(drop=True)
    truth = main["truth"].fillna("?").astype(str)
    skip = (truth == "?") | main.apply(lambda r: loss_unobserved(r.to_dict()), axis=1)
    skipped = sorted(main.loc[skip, "capture_id"].astype(str))
    return main[~skip].reset_index(drop=True), skipped


def ordered_labels(*columns):
    """Known problems first (in fixed order), then anything else seen."""
    seen = set()
    for col in columns:
        seen.update(col.dropna().astype(str))
    extra = sorted(seen - set(PROBLEMS))
    return PROBLEMS + extra


def style_axes(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED, labelcolor=TEXT)


def plot_delay_breakdown(main, out_path):
    means = main.groupby("truth")[list(PARTS)].mean().reindex(PROBLEMS)

    fig, ax = plt.subplots(figsize=(9, 5))
    n = len(PARTS)
    width = 0.8 / n
    x = range(len(PROBLEMS))
    for i, (col, name) in enumerate(PARTS.items()):
        xs = [xi - 0.4 + width * (i + 0.5) for xi in x]
        ax.bar(xs, means[col].fillna(0), width=width * 0.9,
               color=PART_COLORS[i], label=name, zorder=2)

    ax.set_xticks(list(x))
    ax.set_xticklabels(PROBLEMS)
    ax.set_xlabel("Truth problem", color=TEXT)
    ax.set_ylabel("Average time (seconds)", color=TEXT)
    ax.set_title("Where the time goes, by problem", color=TEXT, loc="left")
    ax.yaxis.grid(True, color=GRID, zorder=0)
    style_axes(ax)
    ax.legend(frameon=False, ncol=n, loc="upper left", labelcolor=TEXT)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def confusion_matrix(main, col="b1"):
    labels = ordered_labels(main["truth"], main[col])
    cm = pd.crosstab(main["truth"].astype(str), main[col].astype(str))
    return cm.reindex(index=labels, columns=labels, fill_value=0)


def plot_confusion(cm, out_path, method="B1"):
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    vmax = max(int(cm.values.max()), 1)
    img = ax.imshow(cm.values, cmap="Blues", vmin=0, vmax=vmax)

    for r in range(cm.shape[0]):
        for c in range(cm.shape[1]):
            v = int(cm.iat[r, c])
            # dark text on light cells, white text on dark cells
            color = "white" if v > vmax / 2 else TEXT
            ax.text(c, r, str(v), ha="center", va="center", color=color)

    ax.set_xticks(range(cm.shape[1]))
    ax.set_xticklabels(cm.columns)
    ax.set_yticks(range(cm.shape[0]))
    ax.set_yticklabels(cm.index)
    ax.set_xlabel(f"{method} says", color=TEXT)
    ax.set_ylabel("Truth", color=TEXT)
    ax.set_title(f"{method} confusion matrix ({int(cm.values.sum())} captures)",
                 color=TEXT, loc="left")
    ax.tick_params(colors=MUTED, labelcolor=TEXT, length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    cbar = fig.colorbar(img, ax=ax, fraction=0.046, pad=0.04)
    cbar.locator = matplotlib.ticker.MaxNLocator(integer=True)  # counts are whole numbers
    cbar.update_ticks()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def scores(cm):
    """Precision, recall, F1 for each truth cause, from the confusion matrix."""
    rows = []
    for cause in cm.index:
        if cause not in PROBLEMS:
            continue
        tp = cm.at[cause, cause]
        predicted = cm[cause].sum()       # column: method said this cause
        actual = cm.loc[cause].sum()      # row: truth is this cause
        precision = tp / predicted if predicted else 0.0
        recall = tp / actual if actual else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        rows.append({"cause": cause, "precision": precision, "recall": recall,
                     "f1": f1, "support": int(actual)})
    return pd.DataFrame(rows)


def plot_f1_compare(score_tables, out_path):
    """Grouped bars: per-cause F1 for each method."""
    fig, ax = plt.subplots(figsize=(9, 4.8))
    n = len(score_tables)
    width = 0.8 / n
    x = range(len(PROBLEMS))
    for i, (method, sc) in enumerate(score_tables.items()):
        f1 = sc.set_index("cause")["f1"].reindex(PROBLEMS).fillna(0)
        xs = [xi - 0.4 + width * (i + 0.5) for xi in x]
        bars = ax.bar(xs, f1, width=width * 0.9, color=METHOD_COLORS[method],
                      label=method, zorder=2)
        for b, v in zip(bars, f1):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}",
                    ha="center", va="bottom", fontsize=8, color=MUTED)

    ax.set_xticks(list(x))
    ax.set_xticklabels(PROBLEMS)
    ax.set_ylim(0, 1.25)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])  # F1 never goes above 1
    ax.set_xlabel("Cause", color=TEXT)
    ax.set_ylabel("F1 score", color=TEXT)
    ax.set_title("Per-cause F1: " + " vs ".join(score_tables), color=TEXT, loc="left")
    ax.yaxis.grid(True, color=GRID, zorder=0)
    style_axes(ax)
    ax.legend(frameon=False, ncol=n, loc="upper left", labelcolor=TEXT,
              bbox_to_anchor=(0, 1.0))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv", help="path to measurements.csv")
    p.add_argument("--out", default="results", help="output folder")
    args = p.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.csv)
    main_df, skipped = main_transactions(df)

    plot_delay_breakdown(main_df, out / "delay_breakdown.png")
    saved = ["delay_breakdown.png"]
    print(f"{len(main_df)} captures (main transaction each), "
          f"{len(skipped)} left out: {', '.join(skipped) or '-'}\n")

    score_tables = {}
    for method, col in METHOD_COLS.items():
        if col not in main_df.columns:
            continue
        cm = confusion_matrix(main_df, col)
        plot_confusion(cm, out / f"{col}_confusion.png", method)
        sc = scores(cm)
        sc.to_csv(out / f"{col}_scores.csv", index=False, float_format="%.3f")
        score_tables[method] = sc
        saved += [f"{col}_confusion.png", f"{col}_scores.csv"]
        print(f"Confusion matrix (rows = truth, columns = {method}):")
        print(cm.to_string(), "\n")
        print(sc.to_string(index=False, float_format="%.3f"), "\n")

    if len(score_tables) > 1:
        plot_f1_compare(score_tables, out / "f1_compare.png")
        saved.append("f1_compare.png")

    print(f"Saved to {out}/: {', '.join(saved)}")


if __name__ == "__main__":
    main()
