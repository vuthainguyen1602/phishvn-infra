#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
mkdir -p data/processed/live_content
exec 9>/tmp/phishvn-live-content.lock
flock -n 9 || exit 0
python3 -u scripts/inspect_live_content.py --sudo-docker --limit "${CONTENT_LIMIT:-50}" >> data/processed/live_content/run.log 2>&1
bash scripts/ops/live_labels_run.sh
date -u +%Y-%m-%dT%H:%M:%SZ > data/processed/live_content/last_success.txt
