"""Make result plots from a measurements.csv.

Usage:
    python -m flowlens.plots data/test/measurements.csv [--out results]

Writes to the output folder (default: results/):
    delay_breakdown.png  average delay parts per truth problem
    b1_confusion.png     B1 confusion matrix (rows = truth, columns = B1)
    b1_scores.csv        precision, recall, F1 per cause
"""

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # write files only, no window
import matplotlib.pyplot as plt
import matplotlib.ticker
import pandas as pd

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

TEXT = "#2b2b29"
MUTED = "#6b6a63"
GRID = "#e4e3de"


def main_transactions(df):
    """Keep one row per capture: the flow with the most bytes."""
    idx = df.groupby("capture_id")["bytes"].idxmax()
    return df.loc[idx].reset_index(drop=True)


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


def confusion_matrix(main):
    labels = ordered_labels(main["truth"], main["b1"])
    cm = pd.crosstab(main["truth"].astype(str), main["b1"].astype(str))
    return cm.reindex(index=labels, columns=labels, fill_value=0)


def plot_confusion(cm, out_path):
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
    ax.set_xlabel("B1 says", color=TEXT)
    ax.set_ylabel("Truth", color=TEXT)
    ax.set_title("B1 confusion matrix (captures)", color=TEXT, loc="left")
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
        predicted = cm[cause].sum()       # column: B1 said this cause
        actual = cm.loc[cause].sum()      # row: truth is this cause
        precision = tp / predicted if predicted else 0.0
        recall = tp / actual if actual else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        rows.append({"cause": cause, "precision": precision, "recall": recall,
                     "f1": f1, "support": int(actual)})
    return pd.DataFrame(rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv", help="path to measurements.csv")
    p.add_argument("--out", default="results", help="output folder")
    args = p.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.csv)
    main_df = main_transactions(df)

    plot_delay_breakdown(main_df, out / "delay_breakdown.png")
    cm = confusion_matrix(main_df)
    plot_confusion(cm, out / "b1_confusion.png")
    sc = scores(cm)
    sc.to_csv(out / "b1_scores.csv", index=False, float_format="%.3f")

    print(f"{len(main_df)} captures (main transaction each)\n")
    print("Confusion matrix (rows = truth, columns = B1):")
    print(cm.to_string(), "\n")
    print(sc.to_string(index=False, float_format="%.3f"), "\n")
    print(f"Saved to {out}/: delay_breakdown.png, b1_confusion.png, b1_scores.csv")


if __name__ == "__main__":
    main()
