"""FlowLens lab web server.

  /small  -> about 10 KB page
  /large  -> about 5 MB file
Waits --delay ms before sending each response (simulates a slow server).
Uses HTTP/1.0, so every request is a fresh TCP connection.

Run inside the server namespace:
    sudo ip netns exec srv ~/flenv/bin/python slow_http.py --delay 500
"""
import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--ip", default="10.0.0.2")
parser.add_argument("--port", type=int, default=80)
parser.add_argument("--delay", type=float, default=0, help="server wait in ms")
args = parser.parse_args()

BODIES = {
    "/small": b"A" * (10 * 1024),
    "/large": b"B" * (5 * 1024 * 1024),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = BODIES.get(self.path)
        if args.delay > 0:
            time.sleep(args.delay / 1000.0)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep the terminal quiet
        pass


print(f"HTTP server on {args.ip}:{args.port}, delay {args.delay} ms", flush=True)
ThreadingHTTPServer((args.ip, args.port), Handler).serve_forever()
