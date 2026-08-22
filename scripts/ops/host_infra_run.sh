#!/usr/bin/env bash
# Infrastructure watcher (WHOIS/DNS/TLS at detection time) — run by cron on the Jetson.
# Tails every detections.csv and enriches domains it has not observed yet; phishing
# infrastructure is perishable, so this must tick on the same host, on the same cadence,
# as the collectors that produce the detections. See watch_host_infra.py for the rationale.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
# Guarded with -f, not `|| true` — same trap as ct_brands_run.sh: sourcing a MISSING file is
# fatal under set -e even with `||`, and would abort before the log redirect leaves any trace.
if [ -f scripts/.env ]; then set -a; . scripts/.env; set +a; fi
mkdir -p data/raw/host_infra
LOG=data/raw/host_infra/watch.log
# flock: a run that stalls on slow WHOIS servers must defer the next tick, not overlap it.
# python3 -u: an unflushed stall leaves a zero-byte log and looks dead rather than slow.
# flock -E 200 makes a held lock distinguishable from a failing collector.
rc=0; { flock -n -E 200 /tmp/phishvn-host-infra.lock python3 -u scripts/watch_host_infra.py >> "$LOG" 2>&1; } || rc=$?
case "$rc" in
  0) ;;
  200) echo "[!] $(date -Is) tick skipped (previous run still holding the lock)" >> "$LOG" ;;
  *) echo "[!] $(date -Is) collector exited $rc (see the traceback above)" >> "$LOG" ;;
esac
