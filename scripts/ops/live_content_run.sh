#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
mkdir -p data/processed/live_content
exec 9>/tmp/phishvn-live-content.lock
flock -n 9 || exit 0
# 75 a tick, raised from 50 on 2026-10-15. At 50, every phishing-source host detected 1-12/10 was
# captured inside 48 h (median 1.1 h) but only 63% of the CT benign hosts were, so the benign arm
# had detection-time HTML for about a third of its hosts. A 50-host run took a median 20 min and
# at most 33, so 75 fits the hour; an overrun only defers the next tick through the flock above.
python3 -u scripts/inspect_live_content.py --sudo-docker --limit "${CONTENT_LIMIT:-75}" >> data/processed/live_content/run.log 2>&1
bash scripts/ops/live_labels_run.sh
date -u +%Y-%m-%dT%H:%M:%SZ > data/processed/live_content/last_success.txt
