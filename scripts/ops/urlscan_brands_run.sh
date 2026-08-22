#!/usr/bin/env bash
# Live Vietnamese brand-impersonation feed (urlscan search). Runs alongside cldwatch_run.sh, which
# is draining a frozen 2024 snapshot; this one is the source that still produces new material.
#
# RECOVERED INTO THE REPO 2026-07-26: this wrapper had only ever existed on the Jetson, so the
# cron entry driving the project's freshest feed was one SD-card failure from being unrecoverable.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
# Guarded with -f, not `|| true`: bash treats sourcing a MISSING file as fatal even with `||`,
# so a deploy without .env would abort before the log redirect below and leave no output at all
# — indistinguishable from cron never firing. Verified 2026-07-26.
if [ -f scripts/.env ]; then set -a; . scripts/.env; set +a; fi
mkdir -p data/raw/urlscan_brands
# --days 2 with a 6-hourly cron overlaps deliberately: urlscan indexes with a lag, and seen_domains
# makes re-seeing a domain free. python3 -u so a stalled run shows progress instead of a mute log.
# flock -E 200 makes a held lock distinguishable from a failing collector.
rc=0; { flock -n -E 200 /tmp/phishvn-urlscan-brands.lock python3 -u scripts/watch_urlscan_brands.py --days 2 --max-captures 60 >> data/raw/urlscan_brands/watch.log 2>&1; } || rc=$?
case "$rc" in
  0) ;;
  200) echo "[!] $(date -Is) tick skipped (previous run still holding the lock)" >> data/raw/urlscan_brands/watch.log ;;
  *) echo "[!] $(date -Is) collector exited $rc (see the traceback above)" >> data/raw/urlscan_brands/watch.log ;;
esac
