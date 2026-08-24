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
# THIS REQUIRES AN HOURLY CRON LINE. The rotation reads the hour mod 6, so it only visits all six
# strata if every hour occurs. On the `*/2` cadence the other collectors use, the hour is always
# even and half the targets would never be reached — the constant-age artefact this rotation
# exists to prevent, reintroduced by the schedule instead of by the flag. Schedule it
# `N * * * *`, not `N */2 * * *`. 24 is divisible by 6, so each target gets four ticks a day.
# (Deployed on a `*/4` line until 2026-08-16, which pinned AGE=1 for every run — 62/63 ticks — and
# hours 08/09 crashed outright because `date +%H` emits a leading zero that bash arithmetic reads
# as octal. Hence the `10#` base prefix below; keep it.)
#
# WIDENED 2026-08-24 (PREREG amendment of that date), from 1/3/7/14. The spread above is not the
# quantity that matters: the matching cells are (suffix x QUARTILE of the PHISHING arm's
# certificate age), and all four old targets fell inside one quartile of those. Measured that day
# against the 2026-08-24 edges [0.96, 15.28, 37.74] days, this arm was short 129 of its 435
# wanted cells, 47 of them in the youngest quartile alone, while the quartile the old rotation
# oversupplied had rows to spare. Collecting faster could not fix that; only collecting elsewhere
# on the age axis can. The edges are quantiles and move as the phishing arm grows — re-measure
# before treating these targets as fixed.
# 0.4 and 0.8 rather than 0: `--age-days 0` reads the log HEAD, which the sampler's own docstring
# warns manufactures "benign has newer certs". Twelve hours is inside the first quartile without
# being the head.
case "$(( 10#$(date +%H) % 6 ))" in
  0) AGE=0.4 ;;
  1) AGE=5   ;;
  2) AGE=0.8 ;;
  3) AGE=25  ;;
  4) AGE=45  ;;
  *) AGE=75  ;;
esac
# flock -E 200 makes a held lock distinguishable from a failing collector.
rc=0; { flock -n -E 200 /tmp/phishvn-ctbenign.lock python3 scripts/watch_ct_benign.py --age-days "$AGE" --batches 4 >> data/raw/ct_benign/watch.log 2>&1; } || rc=$?
case "$rc" in
  0) ;;
  200) echo "[!] $(date -Is) tick skipped (previous run still holding the lock)" >> data/raw/ct_benign/watch.log ;;
  *) echo "[!] $(date -Is) collector exited $rc (see the traceback above)" >> data/raw/ct_benign/watch.log ;;
esac
