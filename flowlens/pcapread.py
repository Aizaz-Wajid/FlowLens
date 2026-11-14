"""Step 1a: read a pcap file into simple packet records.

A small pure-Python reader (struct only). It is much faster than Scapy for this
job and understands everything FlowLens needs: Ethernet / Linux-cooked /
raw IPv4, TCP, UDP and DNS headers.
"""
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class Pkt:
    t: float              # capture time (seconds)
    src: str
    dst: str
    proto: str            # "tcp" | "udp"
    sport: int
    dport: int
    # TCP
    seq: int = 0
    ack: int = 0
    flags: int = 0        # TCP flag bits
    plen: int = 0         # TCP/UDP payload length
    # DNS (only for UDP port 53)
    dns_id: Optional[int] = None
    dns_qr: Optional[int] = None     # 0 = query, 1 = response
    dns_qname: Optional[str] = None
    dns_qtype: Optional[int] = None
    dns_ancount: Optional[int] = None


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _ip(b):
    return ".".join(str(x) for x in b)


def _dns_name(data, off):
    labels = []
    for _ in range(64):
        if off >= len(data):
            break
        n = data[off]
        if n == 0:
            break
        if n & 0xC0:          # compression pointer (not used in questions normally)
            break
        labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels).lower(), off + 1


def _parse_dns(p, data):
    if len(data) < 12:
        return
    did, flags, qd, an = struct.unpack("!HHHH", data[:8])
    p.dns_id, p.dns_qr, p.dns_ancount = did, (flags >> 15) & 1, an
    if qd >= 1:
        name, off = _dns_name(data, 12)
        p.dns_qname = name
        if off + 2 <= len(data):
            p.dns_qtype = struct.unpack("!H", data[off:off + 2])[0]


def read_pcap(path):
    """Return a list of Pkt (IPv4 TCP/UDP only), in capture order."""
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < 24:
        return []
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError(f"{path}: not a classic pcap file (pcapng is not supported; "
                         "save it as 'Wireshark/tcpdump - pcap' or use tcpdump -w)")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(e + "I", raw[20:24])[0]
    div = 1e9 if nano else 1e6

    pkts, off = [], 24
    while off + 16 <= len(raw):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", raw[off:off + 16])
        off += 16
        frame = raw[off:off + incl]
        off += incl
        t = sec + frac / div

        # ---- link layer ----
        if linktype == 1:                       # Ethernet
            if len(frame) < 14:
                continue
            etype = struct.unpack("!H", frame[12:14])[0]
            l3 = 14
            if etype == 0x8100 and len(frame) >= 18:   # VLAN tag
                etype = struct.unpack("!H", frame[16:18])[0]
                l3 = 18
            if etype != 0x0800:
                continue
        elif linktype == 113:                   # Linux cooked (SLL)
            if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
                continue
            l3 = 16
        elif linktype == 276:                   # Linux cooked v2
            if len(frame) < 20 or struct.unpack("!H", frame[0:2])[0] != 0x0800:
                continue
            l3 = 20
        elif linktype in (101, 228):            # raw IPv4
            l3 = 0
        else:
            raise ValueError(f"unsupported link type {linktype}")

        ip = frame[l3:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total_len = struct.unpack("!H", ip[2:4])[0]
        proto = ip[9]
        src, dst = _ip(ip[12:16]), _ip(ip[16:20])
        l4 = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]

        if proto == 6 and len(l4) >= 20:
            sport, dport, seq, ack = struct.unpack("!HHII", l4[:12])
            doff = (l4[12] >> 4) * 4
            flags = l4[13]
            plen = max(0, (total_len - ihl - doff) if total_len else len(l4) - doff)
            pkts.append(Pkt(t, src, dst, "tcp", sport, dport, seq, ack, flags, plen))
        elif proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack("!HH", l4[:4])
            p = Pkt(t, src, dst, "udp", sport, dport, plen=len(l4) - 8)
            if sport == 53 or dport == 53:
                _parse_dns(p, l4[8:])
            pkts.append(p)
    return pkts
