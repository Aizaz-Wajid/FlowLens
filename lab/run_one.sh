#!/bin/bash
# Record ONE labelled capture with ONE known problem.
#
# Usage:  sudo ./run_one.sh <set> <name> <problem> <severity> <size>
#   set       folder under ~/flowlens/data  (e.g. test, pilot, exp1)
#   name      capture name                  (e.g. run001)
#   problem   healthy | loss | delay | dns | server
#   severity  none | low | med | high
#   size      small (10 KB) | large (5 MB)
#
# Example: sudo ./run_one.sh test run001 dns high small
# Output:  ~/flowlens/data/test/run001.pcap  and  run001.json (the answer file)

set -u
SET=$1; NAME=$2; PROBLEM=$3; SEV=$4; SIZE=$5

LAB="$(cd "$(dirname "$0")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
USER_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
PY="$USER_HOME/flenv/bin/python"
OUT="$USER_HOME/flowlens/data/$SET"
mkdir -p "$OUT"; chown "$REAL_USER": "$USER_HOME/flowlens/data" "$OUT"

# ---- severity table (Table 3 of the proposal) ----
declare -A LOSS=([low]=1 [med]=5 [high]=10)          # %
declare -A DELAY=([low]=50 [med]=150 [high]=300)     # ms
declare -A DNS=([low]=100 [med]=300 [high]=800)      # ms
declare -A SRV=([low]=200 [med]=500 [high]=1000)     # ms

NETEM=""; DNS_MS=0; SRV_MS=0; VALUE=0; UNIT=""
case "$PROBLEM" in
  healthy) ;;
  loss)    VALUE=${LOSS[$SEV]};  UNIT="%";  NETEM="loss ${VALUE}%" ;;
  delay)   VALUE=${DELAY[$SEV]}; UNIT="ms"; NETEM="delay ${VALUE}ms" ;;
  dns)     VALUE=${DNS[$SEV]};   UNIT="ms"; DNS_MS=$VALUE ;;
  server)  VALUE=${SRV[$SEV]};   UNIT="ms"; SRV_MS=$VALUE ;;
  *) echo "unknown problem: $PROBLEM"; exit 1 ;;
esac

# ---- 1. clean start ----
ip netns exec srv tc qdisc del dev veth-srv root 2>/dev/null
pkill -f dns_server.py 2>/dev/null; pkill -f slow_http.py 2>/dev/null
sleep 0.3

# ---- 2. start servers in the server namespace ----
ip netns exec srv "$PY" "$LAB/dns_server.py" --delay "$DNS_MS" >/dev/null 2>&1 &
DNS_PID=$!
ip netns exec srv "$PY" "$LAB/slow_http.py" --delay "$SRV_MS" >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

# ---- 3. inject the network fault (server -> client direction) ----
if [ -n "$NETEM" ]; then
  ip netns exec srv tc qdisc add dev veth-srv root netem $NETEM
fi

# ---- 4. capture on the client ----
ip netns exec cli tcpdump -i veth-cli -U -Z root -w "$OUT/$NAME.pcap" \
    'udp port 53 or tcp port 80' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# ---- 5. the web visit (curl's own timings saved as a cross-check) ----
CURL=$(ip netns exec cli curl -4 -s -o /dev/null --max-time 60 -w \
  '{"dns_s":%{time_namelookup},"connect_s":%{time_connect},"ttfb_s":%{time_starttransfer},"total_s":%{time_total},"http_code":%{http_code},"bytes":%{size_download}}' \
  "http://site.lab/$SIZE")
[ -z "$CURL" ] && CURL='null'
sleep 1

# ---- 6. stop and clean up ----
kill -INT $TCPDUMP_PID 2>/dev/null; wait $TCPDUMP_PID 2>/dev/null
ip netns exec srv tc qdisc del dev veth-srv root 2>/dev/null
kill $DNS_PID $HTTP_PID 2>/dev/null; wait $DNS_PID $HTTP_PID 2>/dev/null

# ---- 7. answer file ----
cat > "$OUT/$NAME.json" <<EOF
{
  "name": "$NAME",
  "problem": "$PROBLEM",
  "severity": "$SEV",
  "value": $VALUE,
  "unit": "$UNIT",
  "size": "$SIZE",
  "netem": "$NETEM",
  "dns_delay_ms": $DNS_MS,
  "server_delay_ms": $SRV_MS,
  "time": "$(date -Iseconds)",
  "curl": $CURL
}
EOF
chown "$REAL_USER": "$OUT/$NAME.pcap" "$OUT/$NAME.json"
echo "$NAME  $PROBLEM/$SEV/$SIZE  curl: $CURL"
