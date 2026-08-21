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
# Same age rotation as ct_benign_run.sh, for the same reason (a constant target age would make
# certificate age a label marker in the one registry group the endpoint is read on), and the same
# HOURLY requirement: `% 4` visits all four strata only if every hour occurs. `10#` keeps bash from
# reading 08/09 as octal.
case "$(( 10#$(date +%H) % 4 ))" in
  0) AGE=1  ;;
  1) AGE=3  ;;
  2) AGE=7  ;;
  *) AGE=14 ;;
esac
# .vn is ~1 apex name in 2,000 CT entries, so a tick walks the log tail until 10 names are kept
# or 20,000 entries are read (~8 min measured 2026-08-21); the lock stops ticks from overlapping.
exec flock -n /tmp/phishvn-ctbenign-vn.lock \
  python3 scripts/watch_ct_benign.py --stratum vn --age-days "$AGE" \
    --target 10 --max-entries 20000 \
  >> data/raw/ct_benign_vn/watch.log 2>&1
