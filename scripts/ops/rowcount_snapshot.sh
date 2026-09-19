#!/usr/bin/env bash
# Append a timestamped row count for every live feed.
# Exists because ct_benign back-dates first_detected (run_time - age_days), so
# per-day accrual cannot be recovered from the date column -- only from deltas.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
OUT=data/raw/_rowcounts.csv
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[ -f "$OUT" ] || echo "ts_utc,source,rows" > "$OUT"
files=(data/raw/*/detections.csv data/raw/host_infra/host_infra.csv)
# Optional host-specific extra files, one path per line: ledgers of collectors the deposit's
# protocol does not describe, held beside this script and not in it (same split, and the same
# reason, as jetson_health.rows.local).
extra="$(dirname "$0")/rowcount_snapshot.paths.local"
if [ -f "$extra" ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    files+=("$line")
  done < "$extra"
fi
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  src=$(basename "$(dirname "$f")")
  n=$(( $(wc -l < "$f") - 1 ))
  echo "$TS,$src,$n" >> "$OUT"
done
