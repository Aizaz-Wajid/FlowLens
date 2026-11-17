"""FlowLens: robust z-score diagnosis (the method from the proposal).

1. Learn what "healthy" looks like: the median and MAD of each measurement
   over healthy reference captures.
2. For a new transaction, compute a robust z-score per measurement:
       z = (x - median) / spread,   spread = max(1.4826 * MAD, MIN_SPREAD)
3. A measurement is flagged when z > z_limit (default 3.5).
   A retransmitted SYN is always loss evidence (healthy setups never resend it).
4. Each flagged cause gets the share of the total time it is responsible
   for; the biggest share is the main cause.
5. If DNS was not seen in the capture, DNS is "not enough evidence",
   never "fast".
"""
import statistics
import sys

# measurement column -> cause it points to
CAUSE_OF = {
    "dns_s":         "dns",
    "rtt_s":         "delay",
    "server_wait_s": "server",
    "retx_time_s":   "loss",
    "retx_count":    "loss",
}

MIN_SPREAD = 0.005      # 5 ms: smallest spread allowed, so z is always defined
# smallest spread per column (times in seconds, counts in packets)
MIN_SPREAD_OF = {col: MIN_SPREAD for col in CAUSE_OF}
MIN_SPREAD_OF["retx_count"] = 1
MIN_HEALTHY = 5         # fewer healthy values than this -> use built-in defaults
NO_EVIDENCE = "not enough evidence"

# Built-in healthy values (seconds), from the lab's healthy captures.
# MAD 0 means "use MIN_SPREAD".
DEFAULT_REFERENCE = {
    "dns_s":         (0.003, 0.0),
    "rtt_s":         (0.001, 0.0),
    "server_wait_s": (0.003, 0.0),
    "retx_time_s":   (0.0,   0.0),
    "retx_count":    (0.0,   0.0),
}


def _num(v):
    """CSV text or number -> float, or None if missing."""
    if v is None or v == "":
        return None
    return float(v)


def _dns_seen(row):
    v = row.get("dns_observable")
    return v is True or str(v).lower() == "true"


def fit_reference(healthy_rows, min_count=MIN_HEALTHY):
    """Median and MAD of each measurement over healthy rows.
    Returns {column: (median, mad)}.  Falls back to DEFAULT_REFERENCE (with a
    warning) for any measurement with fewer than min_count healthy values."""
    ref = {}
    for col in CAUSE_OF:
        rows = healthy_rows
        if col == "dns_s":
            rows = [r for r in rows if _dns_seen(r)]   # unseen DNS is not 0 ms
        vals = [v for v in (_num(r.get(col)) for r in rows) if v is not None]
        if len(vals) < min_count:
            print(f"warning: only {len(vals)} healthy value(s) for {col} "
                  f"(need {min_count}); using built-in defaults", file=sys.stderr)
            ref[col] = DEFAULT_REFERENCE[col]
            continue
        med = statistics.median(vals)
        mad = statistics.median(abs(v - med) for v in vals)
        ref[col] = (med, mad)
    return ref


def robust_z(x, median, mad, min_spread=MIN_SPREAD):
    spread = max(1.4826 * mad, min_spread)
    return (x - median) / spread


def time_cost(cause, row):
    """How much of the total time this cause is responsible for.
    delay: RTT counts twice (one round trip for the handshake, one for the
           request).
    loss:  time spent resending data, plus the extra setup time when the
           SYN had to be resent (setup_s minus one RTT)."""
    val = lambda col: _num(row.get(col)) or 0.0
    if cause == "delay":
        return 2 * val("rtt_s")
    if cause == "loss":
        extra_setup = max(0.0, val("setup_s") - val("rtt_s")) if val("syn_retx") else 0.0
        return val("retx_time_s") + extra_setup
    return val({"dns": "dns_s", "server": "server_wait_s"}[cause])


def diagnose(row, ref, z_limit=3.5):
    """Return a dict:
        cause    main cause ('healthy', 'dns', 'delay', 'server', 'loss')
        flagged  all flagged causes, biggest share first
        z        {column: z-score or None}
        share    {cause: share of total time} for flagged causes
        dns      'ok', 'flagged' or 'not enough evidence'
    """
    z, flagged = {}, set()
    for col, cause in CAUSE_OF.items():
        x = _num(row.get(col))
        if x is None or (col == "dns_s" and not _dns_seen(row)):
            z[col] = None
            continue
        z[col] = robust_z(x, *ref[col], min_spread=MIN_SPREAD_OF[col])
        if z[col] > z_limit:
            flagged.add(cause)
    if (_num(row.get("syn_retx")) or 0) > 0:
        flagged.add("loss")                      # a resent SYN is loss evidence

    if not _dns_seen(row):
        dns_status = NO_EVIDENCE
    else:
        dns_status = "flagged" if "dns" in flagged else "ok"

    if not flagged:
        return {"cause": "healthy", "flagged": [], "z": z, "share": {}, "dns": dns_status}

    costs = {cause: time_cost(cause, row) for cause in flagged}
    total = _num(row.get("total_s")) or sum(costs.values())
    share = {cause: (c / total if total else 0.0) for cause, c in costs.items()}
    order = sorted(share, key=share.get, reverse=True)
    return {"cause": order[0], "flagged": order, "z": z, "share": share, "dns": dns_status}
