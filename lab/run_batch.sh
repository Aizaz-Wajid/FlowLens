#!/bin/bash
# Record many labelled captures.
#
# Usage:  sudo ./run_batch.sh <set> <repeats> [size]
#   Records <repeats> healthy runs, then <repeats> runs for every
#   problem x severity (4 x 3), in shuffled order.
#
# Pilot set (5 repeats -> 5 healthy + 60 faulty):
#   sudo ./run_batch.sh pilot 5 small
# Experiment 2 (20 repeats -> 20 healthy + 240 faulty):
#   sudo ./run_batch.sh exp2 20 small
#
# Loss runs always use the large (5 MB) download, whatever [size] says:
# a 10 KB download is only a few packets, so with low loss often no packet
# is dropped and the capture looks healthy.

SET=$1; N=$2; SIZE=${3:-small}
LAB="$(cd "$(dirname "$0")" && pwd)"

JOBS=()
for i in $(seq 1 "$N"); do
  JOBS+=("healthy none")
  for p in loss delay dns server; do
    for s in low med high; do JOBS+=("$p $s"); done
  done
done

i=0
printf '%s\n' "${JOBS[@]}" | shuf | while read -r PROB SEV; do
  i=$((i+1))
  NAME=$(printf "run%04d" "$i")
  RUN_SIZE=$SIZE
  [ "$PROB" = loss ] && RUN_SIZE=large
  "$LAB/run_one.sh" "$SET" "$NAME" "$PROB" "$SEV" "$RUN_SIZE"
done
echo "Batch '$SET' done."
