#!/usr/bin/env bash
# Refresh labels for this live collection only; replaces discontinued paper monitoring.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
mkdir -p data/processed/live_labels
LOG=data/processed/live_labels/rebuild.log
rc=0
flock -n -E 200 /tmp/phishvn-live-labels.lock \
  python3 -u scripts/rebuild_live_labels.py >> "$LOG" 2>&1 || rc=$?
if [ "$rc" -eq 200 ]; then exit 0; fi
if [ "$rc" -eq 0 ]; then
  date -u +%Y-%m-%dT%H:%M:%SZ > data/processed/live_labels/last_success.txt
fi
exit "$rc"
