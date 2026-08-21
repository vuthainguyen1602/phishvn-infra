#!/usr/bin/env bash
# Append a timestamped row count for every live feed.
# Exists because ct_benign back-dates first_detected (run_time - age_days), so
# per-day accrual cannot be recovered from the date column -- only from deltas.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
OUT=data/raw/_rowcounts.csv
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[ -f "$OUT" ] || echo "ts_utc,source,rows" > "$OUT"
for f in data/raw/*/detections.csv data/raw/host_infra/host_infra.csv; do
  [ -f "$f" ] || continue
  src=$(basename "$(dirname "$f")")
  n=$(( $(wc -l < "$f") - 1 ))
  echo "$TS,$src,$n" >> "$OUT"
done
