#!/bin/bash
# Wrapper for the CT-sampled benign arm (run by cron on the Jetson).
# No API key: CT logs are public, so unlike the other collectors this one needs no scripts/.env.
set -euo pipefail
if [ -d "$(dirname "$0")/../../data" ]; then
  REPO="$(cd "$(dirname "$0")/../.." && pwd)"
else
  REPO="$(cd "$(dirname "$0")/../.." && pwd)"
fi
cd "$REPO"
mkdir -p data/raw/ct_benign
# Age is ROTATED across `hour % 6`, not fixed: a constant --age-days would let this wrapper, not
# the data, decide the benign arm's certificate age. TWO TRAPS, both hit in production already:
#   * REQUIRES AN HOURLY CRON LINE (`N * * * *`). On `*/2` the hour is always even, half the
#     strata are never visited, and the constant-age artefact comes back via the schedule.
#     Deployed on a `*/4` line until 2026-08-16, which pinned AGE=1 for 62/63 ticks. That
#     clause is PARSED, not prose: check_paper_claims.py reads `*/N` + the date out of this
#     comment and matches it against P4b's "four-hourly". Keep them on one line.
#   * `10#` keeps bash from reading hours 08/09 as octal. Keep it.
# The targets, the 2026-08-24 prereg widening with its cell measurements, and why 0.4/0.8 rather
# than 0: docs/decisions/ct-benign-age-rotation.md
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
