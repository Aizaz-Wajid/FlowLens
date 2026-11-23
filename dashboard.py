"""FlowLens dashboard: look at one capture, see where the time went and why.

Run from the repo folder (with the venv active):
    streamlit run dashboard.py
then open http://localhost:8501 in a browser.

The file list comes from data/ (or the folder in the FLOWLENS_DATA environment
variable).  FlowLens learns what "healthy" looks like from the reference
chosen in the sidebar (default: the pilot set's healthy captures).
"""
import glob
import hashlib
import json
import os
import tempfile

import altair as alt
import pandas as pd
import streamlit as st

from flowlens.baseline import b1_diagnose
from flowlens.measure import measure_pcap
from flowlens.scorer import (DEFAULT_REFERENCE, MIN_HEALTHY, NO_EVIDENCE,
                             diagnose as fl_diagnose, fit_reference, load_reference,
                             same_file)

DATA_DIR = os.environ.get("FLOWLENS_DATA", "data")
DEFAULT_REF = "results/pilot_measurements.csv"
BUILTIN = "Built-in healthy values"

# Delay parts of one transaction, in time order.  Together they add up to the
# transaction's total time (DNS query -> last byte of the response).
# Fixed colors, one per part.
PARTS = {
    "DNS lookup":         "#2a78d6",
    "TCP setup":          "#eb6834",
    "Request round trip": "#1baf7a",
    "Server wait":        "#eda100",
    "Transfer":           "#e87ba4",
    "Loss recovery":      "#6250d6",
    "Other":              "#a3a29b",
}
CAUSE_NAMES = {"dns": "DNS", "delay": "Network delay", "server": "Slow server",
               "loss": "Packet loss", "healthy": "Healthy"}

MS_COLUMNS = {"dns_s": "DNS (ms)", "rtt_s": "RTT (ms)", "setup_s": "Setup (ms)",
              "ttfb_s": "TTFB (ms)", "server_wait_s": "Server wait (ms)",
              "retx_time_s": "Retx time (ms)", "transfer_s": "Transfer (ms)",
              "total_s": "Total (ms)"}


# ---------------------------------------------------------------- helpers

def num(v):
    return 0.0 if v is None or v == "" else float(v)


def dns_seen(row):
    v = row.get("dns_observable")
    return v is True or str(v).lower() == "true"


def breakdown(row):
    """Split the transaction's total time into non-overlapping parts (seconds)."""
    transfer = num(row.get("transfer_s"))
    wait = max(0.0, num(row.get("server_wait_s")))
    loss = min(num(row.get("retx_time_s")), transfer)    # resend waits happen during transfer
    parts = {
        "DNS lookup":         num(row.get("dns_s")) if dns_seen(row) else 0.0,
        "TCP setup":          num(row.get("setup_s")),     # includes resent SYNs
        "Request round trip": max(0.0, num(row.get("ttfb_s")) - wait),
        "Server wait":        wait,
        "Transfer":           transfer - loss,
        "Loss recovery":      loss,
    }
    parts["Other"] = max(0.0, num(row.get("total_s")) - sum(parts.values()))
    return parts


def main_index(rows):
    """The web visit = the transaction that carried the most data."""
    return max(range(len(rows)), key=lambda i: rows[i].get("bytes") or 0)


@st.cache_data(show_spinner="Reading capture...")
def measure_file(path, mtime):            # mtime: re-read when the file changes
    return measure_pcap(path)


@st.cache_data(show_spinner="Reading capture...")
def measure_upload(name, data, digest):
    suffix = os.path.splitext(name)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        return measure_pcap(tmp, os.path.splitext(name)[0])
    finally:
        os.unlink(tmp)


@st.cache_data
def reference_for(choice, mtime):
    """-> (reference dict, number of healthy captures or None for built-in)."""
    if choice == BUILTIN:
        return dict(DEFAULT_REFERENCE), None
    rows = load_reference(choice)
    return fit_reference(rows), len(rows)


def reference_options():
    opts = []
    if os.path.isfile(DEFAULT_REF):
        opts.append(DEFAULT_REF)
    for path in sorted(glob.glob(os.path.join(DATA_DIR, "*", "measurements.csv"))):
        if path not in opts:
            opts.append(path)
    return opts + [BUILTIN]


def truth_label(pcap_path):
    jpath = os.path.splitext(pcap_path)[0] + ".json"
    if not os.path.isfile(jpath):
        return None
    with open(jpath) as f:
        j = json.load(f)
    return f"{j.get('problem')} / {j.get('severity')}"


def ms(v):
    return None if v is None or v == "" else round(float(v) * 1000, 2)


# ---------------------------------------------------------------- page

st.set_page_config(page_title="FlowLens", layout="wide")
st.title("FlowLens")
st.caption("Why was this web visit slow? Measurements from one packet capture, "
           "diagnosed by FlowLens and by the fixed-limit baseline B1.")

# ---- sidebar: choose a capture and a reference ----
with st.sidebar:
    st.header("Capture")
    source = st.radio("Source", ["Pick from data/", "Upload a pcap"], key="source")
    rows, pcap_path, name = None, None, None
    if source == "Pick from data/":
        pcaps = sorted(glob.glob(os.path.join(DATA_DIR, "**", "*.pcap*"), recursive=True))
        if not pcaps:
            st.info(f"No .pcap files under {DATA_DIR}/")
        else:
            pcap_path = st.selectbox("File", pcaps, key="pcap",
                                     format_func=lambda p: os.path.relpath(p, DATA_DIR))
            name = os.path.basename(pcap_path)
            rows = measure_file(pcap_path, os.path.getmtime(pcap_path))
    else:
        up = st.file_uploader("pcap or pcapng file", type=["pcap", "pcapng", "cap"])
        if up is not None:
            data = up.getvalue()
            name = up.name
            rows = measure_upload(up.name, data, hashlib.sha1(data).hexdigest())

    st.header("FlowLens reference")
    ref_choice = st.selectbox(
        "Learn 'healthy' from", reference_options(), key="reference",
        help="FlowLens flags a measurement when it is far outside the healthy "
             "range learned from these captures.")
    ref_mtime = os.path.getmtime(ref_choice) if ref_choice != BUILTIN else 0
    ref, n_healthy = reference_for(ref_choice, ref_mtime)
    if n_healthy is not None:
        st.caption(f"{n_healthy} healthy captures")
        if n_healthy < MIN_HEALTHY:
            st.warning(f"Fewer than {MIN_HEALTHY} healthy captures: "
                       "FlowLens uses its built-in healthy values instead.")
    if pcap_path and ref_choice != BUILTIN and same_file(
            ref_choice, os.path.join(os.path.dirname(pcap_path), "measurements.csv")):
        st.warning("This reference is the capture's own set, so FlowLens may have "
                   "learned from this capture. Pick another set for a fair test.")

if rows is None:
    st.info("Pick a capture from data/ or upload one in the sidebar.")
    st.stop()
if not rows:
    st.error(f"No TCP connections found in {name}.")
    st.stop()

# ---- choose the transaction (default: the main one) ----
main_i = main_index(rows)
labels = [f"#{r['flow_id']}  {r['server']}  ({r.get('bytes') or 0:,} bytes)"
          + ("  - main" if i == main_i else "") for i, r in enumerate(rows)]
sel = st.selectbox("Transaction", range(len(rows)), index=main_i, key="tx",
                   format_func=lambda i: labels[i])
row = rows[sel]

head = f"**{name}**, {len(rows)} transaction(s)"
truth = truth_label(pcap_path) if pcap_path else None
if truth:
    head += f" · ground truth from answer file: **{truth}**"
st.markdown(head)

fl = fl_diagnose(row, ref)
b1_main, b1_all = b1_diagnose(row)

# ---- DNS evidence ----
if fl["dns"] == NO_EVIDENCE:
    st.warning("**DNS: not enough evidence.** No DNS lookup for this connection was "
               "seen in the capture (cached, or not captured). This is *not* the same "
               "as a fast lookup: FlowLens neither blames nor clears DNS, and DNS is "
               "left out of the chart below.", icon="⚠️")

# ---- diagnoses side by side ----
c1, c2 = st.columns(2)
with c1:
    st.subheader("FlowLens")
    st.metric("Main cause", CAUSE_NAMES.get(fl["cause"], fl["cause"]))
    if fl["flagged"]:
        costs = {c: fl["share"][c] * num(row.get("total_s")) for c in fl["flagged"]}
        st.dataframe(pd.DataFrame({
            "Rank": range(1, len(fl["flagged"]) + 1),
            "Cause": [CAUSE_NAMES.get(c, c) for c in fl["flagged"]],
            "Share of total time": [fl["share"][c] for c in fl["flagged"]],
            "Time (ms)": [round(costs[c] * 1000, 1) for c in fl["flagged"]],
        }), hide_index=True, width="stretch", column_config={
            "Share of total time": st.column_config.ProgressColumn(
                format="percent", min_value=0.0, max_value=1.0)})
    else:
        st.caption("No measurement is outside the healthy range.")
    dns_text = {"ok": "observed, normal", "flagged": "observed, slow",
                NO_EVIDENCE: "not enough evidence"}[fl["dns"]]
    st.caption(f"DNS: {dns_text}")
with c2:
    st.subheader("B1 (fixed limits)")
    st.metric("Main cause", CAUSE_NAMES.get(b1_main, b1_main))
    if b1_all:
        st.caption("Limits crossed (largest factor first): "
                   + ", ".join(CAUSE_NAMES.get(c, c) for c in b1_all))
    else:
        st.caption("No fixed limit crossed (DNS > 200 ms, RTT > 100 ms, "
                   "server wait > 300 ms, any retransmission).")
    if b1_main != fl["cause"]:
        st.info("B1 and FlowLens disagree on this transaction.")

with st.expander("FlowLens z-scores (how far each measurement is from healthy)"):
    st.dataframe(pd.DataFrame({
        "Measurement": list(fl["z"]),
        "Value": [row.get(c) for c in fl["z"]],
        "z-score": [None if z is None else round(z, 1) for z in fl["z"].values()],
    }), hide_index=True)
    st.caption("A z-score above 3.5 is flagged. Empty = not measured "
               "(e.g. DNS not observable). A resent SYN always counts as loss.")

# ---- delay breakdown ----
st.subheader("Where the time went")
parts = breakdown(row)
total = sum(parts.values())
bars = pd.DataFrame([{"Transaction": f"#{row['flow_id']}", "Part": p, "ms": v * 1000,
                      "Share": v / total if total else 0.0, "order": i}
                     for i, (p, v) in enumerate(parts.items()) if v > 0])
chart = (alt.Chart(bars).mark_bar(height=36)
         .encode(x=alt.X("ms:Q", stack="zero", title="Time (ms)"),
                 y=alt.Y("Transaction:N", title=None),
                 color=alt.Color("Part:N", sort=list(PARTS),
                                 scale=alt.Scale(domain=list(PARTS), range=list(PARTS.values())),
                                 legend=alt.Legend(orient="bottom", title=None, columns=4)),
                 order=alt.Order("order:Q"),
                 tooltip=["Part", alt.Tooltip("ms:Q", title="Time (ms)", format=".1f"),
                          alt.Tooltip("Share:Q", format=".0%")])
         .properties(height=130))
st.altair_chart(chart, width="stretch")
st.caption(f"Total {total * 1000:.1f} ms"
           + ("" if dns_seen(row) else " (from the SYN; DNS not observed)")
           + ". Loss recovery = time spent waiting for resent data during the transfer.")
with st.expander("Breakdown as a table"):
    st.dataframe(pd.DataFrame({"Part": list(parts),
                               "Time (ms)": [round(v * 1000, 2) for v in parts.values()]}),
                 hide_index=True)

# ---- all transactions ----
st.subheader("Transactions")
table = pd.DataFrame([{
    "Main": "★" if i == main_i else "",
    "Flow": r["flow_id"],
    "Server": r["server"],
    "DNS (ms)": ms(r.get("dns_s")) if dns_seen(r) else None,
    "DNS seen": "yes" if dns_seen(r) else "not enough evidence",
    **{label: ms(r.get(col)) for col, label in MS_COLUMNS.items() if col != "dns_s"},
    "Retransmissions": r.get("retx_count"),
    "SYN resends": r.get("syn_retx"),
    "Bytes": r.get("bytes"),
} for i, r in enumerate(rows)])
st.dataframe(table, hide_index=True, width="stretch")
