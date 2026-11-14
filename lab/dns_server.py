"""FlowLens lab DNS server.

Answers every name ending in .lab with the server IP, after an optional delay.
Each query is handled in its own thread, so parallel queries are each delayed
once (not queued behind each other).

Run inside the server namespace:
    sudo ip netns exec srv ~/flenv/bin/python dns_server.py --delay 300
"""
import argparse
import socket
import threading
import time

from dnslib import DNSRecord, RR, A, QTYPE, RCODE

parser = argparse.ArgumentParser()
parser.add_argument("--ip", default="10.0.0.2", help="address to listen on and to answer with")
parser.add_argument("--port", type=int, default=53)
parser.add_argument("--delay", type=float, default=0, help="reply delay in ms")
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((args.ip, args.port))
print(f"DNS server on {args.ip}:{args.port}, delay {args.delay} ms", flush=True)


def handle(data, addr):
    try:
        query = DNSRecord.parse(data)
    except Exception:
        return
    if args.delay > 0:
        time.sleep(args.delay / 1000.0)
    reply = query.reply()
    name = str(query.q.qname).rstrip(".")
    if name.endswith(".lab"):
        if query.q.qtype == QTYPE.A:
            reply.add_answer(RR(query.q.qname, QTYPE.A, rdata=A(args.ip), ttl=0))
        # other types (e.g. AAAA): empty NOERROR answer
    else:
        reply.header.rcode = RCODE.NXDOMAIN
    sock.sendto(reply.pack(), addr)


while True:
    data, addr = sock.recvfrom(4096)
    threading.Thread(target=handle, args=(data, addr), daemon=True).start()
