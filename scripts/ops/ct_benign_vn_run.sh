#!/bin/bash
# Wrapper for the .vn BENIGN SUPPLEMENT of P4's matched arm (run by cron on the Jetson).
# Registered by the 2026-08-21 amendment in papers/P4_infra/PREREG_trigger_analysis.md: the
# matched arm's collector bars .vn by its TLD allow-list and suffix test, so the .vn registry
# group had no benign support. This is the same sampler with `--stratum vn`, writing to its own
# directory (data/raw/ct_benign_vn/) so it is its own source and fills .vn matching cells only.
# No API key: CT logs are public.
# Crontab line (installed on the Jetson 2026-08-21): `45 * * * *`, i.e. hourly at :45, twenty
# minutes after the matched arm's :25 tick so the two samplers never overlap. The log directory
# must exist BEFORE cron opens its redirect (the first tick, 13:45, died on a missing directory).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
mkdir -p data/raw/ct_benign_vn
# Age rotation for the .vn arm, widened 2026-08-24 (PREREG amendment of that date). Same two
# traps as ct_benign_run.sh: HOURLY cron line only (`% 6` needs every hour to occur), and `10#`
# against octal 08/09. The .vn cell measurements behind these targets, and the quartile edges
# they straddle (which move as the phishing arm grows): docs/decisions/ct-benign-age-rotation.md
case "$(( 10#$(date +%H) % 6 ))" in
  0) AGE=0.4 ;;
  1) AGE=5   ;;
  2) AGE=0.8 ;;
  3) AGE=25  ;;
  4) AGE=45  ;;
  *) AGE=75  ;;
esac
# .vn is ~1 apex name in 2,000 CT entries, so a tick walks the log tail until 10 names are kept
# or 20,000 entries are read. The 20,000 is the binding limit, not the target: a manual tick at
# age 7 on 2026-08-24 read 11,538 entries over 21,785 names in ~45 min and kept 2. The "~8 min"
# recorded here on 2026-08-21 was a lucky tick, not the rate. Ticks are hourly, so a slow one
# holds the lock into the next one, which then logs "tick skipped" -- expected, not a fault.
# flock -E 200 makes a held lock distinguishable from a failing collector.
rc=0; { flock -n -E 200 /tmp/phishvn-ctbenign-vn.lock python3 scripts/watch_ct_benign.py --stratum vn --age-days "$AGE" --target 10 --max-entries 20000 >> data/raw/ct_benign_vn/watch.log 2>&1; } || rc=$?
case "$rc" in
  0) ;;
  200) echo "[!] $(date -Is) tick skipped (previous run still holding the lock)" >> data/raw/ct_benign_vn/watch.log ;;
  *) echo "[!] $(date -Is) collector exited $rc (see the traceback above)" >> data/raw/ct_benign_vn/watch.log ;;
esac
