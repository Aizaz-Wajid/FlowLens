"""Steps 1b + 2: group packets into transactions and measure each delay part.

One transaction = one TCP connection (HTTP/1.0: one request, one response)
plus the DNS lookup that came just before it.  Output: one dict per
transaction with the columns agreed in the README (Table 1 of the proposal).
"""
from .pcapread import read_pcap, SYN, ACK, RST

COLUMNS = ["capture_id", "flow_id", "server", "dns_s", "dns_observable",
           "rtt_s", "setup_s", "ttfb_s", "server_wait_s", "retx_count",
           "retx_time_s", "syn_retx", "transfer_s", "total_s", "bytes"]

M32 = 2 ** 32


def _merge_len(intervals):
    """Total length of a union of [start, end] intervals (no double counting)."""
    total, cur_s, cur_e = 0.0, None, None
    for s, e in sorted(intervals):
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                total += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        total += cur_e - cur_s
    return total


def _dns_lookups(pkts):
    """Pair DNS queries with responses.  Returns a list of
    (name, first_query_t, response_t, answered) ordered by response time."""
    queries = {}          # (client ip, client port, id, name) -> first query time
    by_name_first = {}    # name -> first query time not yet answered (retries counted once)
    out = []
    for p in pkts:
        if p.dns_id is None or p.dns_qname is None:
            continue
        if p.dns_qtype not in (1, None):        # only A lookups (IPv4)
            continue
        if p.dns_qr == 0:
            queries.setdefault((p.src, p.sport, p.dns_id, p.dns_qname), p.t)
            by_name_first.setdefault(p.dns_qname, p.t)
        else:
            key = (p.dst, p.dport, p.dns_id, p.dns_qname)
            if key in queries:
                start = by_name_first.pop(p.dns_qname, queries[key])
                out.append((p.dns_qname, start, p.t, (p.dns_ancount or 0) > 0))
                del queries[key]
    return out


def _tcp_flows(pkts):
    flows = {}
    for p in pkts:
        if p.proto != "tcp":
            continue
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (a, b) if a < b else (b, a)
        flows.setdefault(key, []).append(p)
    return flows


def measure_flow(fp, lookups, capture_id, flow_id):
    syns = [p for p in fp if p.flags & SYN and not p.flags & ACK]
    if not syns:
        return None                       # connection started before the capture
    syn = syns[0]
    cli, srv = (syn.src, syn.sport), (syn.dst, syn.dport)
    is_c2s = lambda p: (p.src, p.sport) == cli

    synack = next((p for p in fp if not is_c2s(p) and p.flags & SYN and p.flags & ACK), None)
    row = dict.fromkeys(COLUMNS)
    row.update(capture_id=capture_id, flow_id=flow_id, server=f"{srv[0]}:{srv[1]}",
               syn_retx=len(syns) - 1, retx_count=0, retx_time_s=0.0, bytes=0)
    if synack is None:
        return row                        # handshake never finished

    # first SYN -> SYN-ACK = RTT (fresh connection); SYN -> client ACK = setup
    syn_last = syns[-1]                   # the SYN that was actually answered
    row["rtt_s"] = synack.t - syn_last.t
    hs_ack = next((p for p in fp if is_c2s(p) and p.t >= synack.t and p.flags & ACK
                   and not p.flags & SYN), None)
    if hs_ack is not None:
        row["setup_s"] = hs_ack.t - syn.t

    c_isn, s_isn = syn.seq, synack.seq
    c_data = [p for p in fp if is_c2s(p) and p.plen > 0]
    s_data = [p for p in fp if not is_c2s(p) and p.plen > 0]

    # ---- retransmissions (both directions) ----
    gaps = []
    for seg_list, isn in ((c_data, c_isn), (s_data, s_isn)):
        max_end, first_sent = 0, {}
        for p in seg_list:
            rel = (p.seq - isn) % M32
            end = rel + p.plen
            if end <= max_end:            # this range was already sent before
                row["retx_count"] += 1
                t0 = first_sent.get(rel)
                if t0 is None:            # partial overlap: earliest earlier segment covering it
                    t0 = min((t for s, t in first_sent.items() if s > rel), default=p.t)   # when the hole first appeared
                gaps.append((t0, p.t))
            else:
                first_sent.setdefault(rel, p.t)
                max_end = end
    row["retx_time_s"] = _merge_len(gaps)

    # ---- request / response timing ----
    if s_data:
        first_srv = s_data[0]
        req = [p for p in c_data if p.t <= first_srv.t]
        if req:
            row["ttfb_s"] = first_srv.t - req[-1].t
            row["server_wait_s"] = row["ttfb_s"] - row["rtt_s"]
        row["transfer_s"] = s_data[-1].t - first_srv.t
        row["bytes"] = _unique_bytes(s_data, s_isn)

    # ---- DNS lookup that led to this connection ----
    before = [l for l in lookups if l[2] <= syn.t and l[3]]
    if before:
        name, q_t, r_t, _ = before[-1]
        row["dns_s"] = r_t - q_t
        row["dns_observable"] = True
        start = q_t
    else:
        row["dns_observable"] = False     # cached / not captured: NOT zero delay
        start = syn.t
    if s_data:
        row["total_s"] = s_data[-1].t - start
    return row


def _unique_bytes(seg_list, isn):
    """Payload bytes seen at least once, each byte counted once.
    A byte that only arrived in a retransmission still counts (the original
    was lost before the capture point, so the resend is the only copy)."""
    ranges = sorted(((p.seq - isn) % M32, (p.seq - isn) % M32 + p.plen) for p in seg_list)
    total, cur_s, cur_e = 0, None, None
    for s, e in ranges:
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                total += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        total += cur_e - cur_s
    return total


def _retx_bytes(seg_list, isn):
    max_end, dup = 0, 0
    for p in seg_list:
        rel = (p.seq - isn) % M32
        end = rel + p.plen
        if end <= max_end:
            dup += p.plen
        else:
            dup += max(0, max_end - rel)
            max_end = end
    return dup


def measure_pcap(path, capture_id=None):
    """pcap file -> list of row dicts (one per TCP transaction)."""
    import os
    capture_id = capture_id or os.path.splitext(os.path.basename(path))[0]
    pkts = read_pcap(path)
    lookups = _dns_lookups(pkts)
    rows = []
    flows = sorted(_tcp_flows(pkts).values(), key=lambda fp: fp[0].t)
    for i, fp in enumerate(flows, 1):
        r = measure_flow(fp, lookups, capture_id, i)
        if r is not None:
            rows.append(r)
    return rows
