"""B1: fixed-limit rule diagnosis (the baseline FlowLens is compared against).

Each measurement has one fixed limit.  Every limit that is crossed names a
cause; the main cause is the one that crossed its limit by the largest factor.
"""

# cause -> (measurement column, fixed limit)
LIMITS = {
    "dns":    ("dns_s",         0.200),   # DNS above 200 ms is slow
    "delay":  ("rtt_s",         0.100),   # RTT above 100 ms is a long link
    "server": ("server_wait_s", 0.300),   # server wait above 300 ms is slow
    "loss":   ("retx_count",    1),       # any retransmission means loss
}


def b1_diagnose(row):
    """Return (main_cause, [all flagged causes]).  main_cause is 'healthy' if none."""
    flagged = []
    for cause, (col, limit) in LIMITS.items():
        v = row.get(col)
        if v is None or v == "":
            continue
        v = float(v)
        if v >= limit if cause == "loss" else v > limit:
            flagged.append((v / limit, cause))
    if not flagged:
        return "healthy", []
    flagged.sort(reverse=True)
    return flagged[0][1], [c for _, c in flagged]
