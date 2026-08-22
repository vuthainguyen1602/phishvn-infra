#!/bin/bash
# Wrapper for the CT-sampled benign arm (run by cron on the Jetson).
# No API key: CT logs are public, so unlike the other collectors this one needs no scripts/.env.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
mkdir -p data/raw/ct_benign
# The age is ROTATED, not fixed. A constant --age-days would hand the benign arm a constant
# certificate age and P4 would then be comparing "3 days old" against whatever ages the phishing
# arm happens to carry — a result decided by this wrapper rather than by the data. Cycling the
# target across the hour of the day gives the arm an age spread the protocol can match against.
#
# THIS REQUIRES AN HOURLY CRON LINE. The rotation reads the hour mod 4, so it only visits all four
# strata if every hour occurs. On the `*/2` cadence the other collectors use, the hour is always
# even and `% 4` only ever yields 0 or 2 — the arm would silently collect nothing but 1- and
# 7-day-old certificates, which is the constant-age artefact this rotation exists to prevent,
# reintroduced by the schedule instead of by the flag. Schedule it `N * * * *`, not `N */2 * * *`.
# (Deployed on a `*/4` line until 2026-08-16, which pinned AGE=1 for every run — 62/63 ticks — and
# hours 08/09 crashed outright because `date +%H` emits a leading zero that bash arithmetic reads
# as octal. Hence the `10#` base prefix below; keep it.)
case "$(( 10#$(date +%H) % 4 ))" in
  0) AGE=1  ;;
  1) AGE=3  ;;
  2) AGE=7  ;;
  *) AGE=14 ;;
esac
# flock -E 200 makes a held lock distinguishable from a failing collector.
rc=0; { flock -n -E 200 /tmp/phishvn-ctbenign.lock python3 scripts/watch_ct_benign.py --age-days "$AGE" --batches 4 >> data/raw/ct_benign/watch.log 2>&1; } || rc=$?
case "$rc" in
  0) ;;
  200) echo "[!] $(date -Is) tick skipped (previous run still holding the lock)" >> data/raw/ct_benign/watch.log ;;
  *) echo "[!] $(date -Is) collector exited $rc (see the traceback above)" >> data/raw/ct_benign/watch.log ;;
esac
