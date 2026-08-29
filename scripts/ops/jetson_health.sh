#!/usr/bin/env bash
# jetson_health.sh — one-screen health report for the collectors running on the Jetson.
#
# WHY: every collector here can fail without looking like it failed. Today the CT feed ran on
# schedule for six hours, logged tidily, and produced nothing, because crt.sh was answering "200,
# no rows" under load. A glance at the data directory would have said "no new files" — which is
# also what a perfectly healthy quiet day looks like.
#
# So this reports two DIFFERENT things per collector and never conflates them:
#   RAN     — is the log fresh relative to the collector's own cron period? (process health)
#   FOUND   — has the data file grown, and when? (yield)
# A collector that RAN but has not FOUND anything for a long time is the interesting case: it is
# either a genuinely dry source (the legacy feeds are, by now) or a silent breakage. The script
# will not guess which; it prints both columns and lets you see it.
#
# USAGE:  ./scripts/ops/jetson_health.sh [user@host]      (default: $JETSON_HOST)
set -euo pipefail
HOST="${1:-${JETSON_HOST:-bvdung@192.168.1.50}}"

ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" 'bash -s' <<'REMOTE'
set -u
cd ~/PhishVN/data/raw 2>/dev/null || { echo "no ~/PhishVN/data/raw on this host"; exit 1; }
now=$(date +%s)

# collector | log path | data path | cron period in hours
rows=(
  "vn_phishing_live|vn_phishing_live/cron.log|vn_phishing_live/detections.csv|1"
  "chongluadao_live|chongluadao_live/watch.log|chongluadao_live/detections.csv|4"
  "urlscan_brands|urlscan_brands/watch.log|urlscan_brands/detections.csv|6"
  "ct_brands|ct_brands/watch.log|ct_brands/detections.csv|2"
  "tinnhiem_benign|tinnhiem_benign/crawl.log|tinnhiem_benign/detections.csv|12"
  # Added 2026-08-24. The infrastructure arms were the ones missing: host_infra died at every
  # tick for 28 h on 21-22/8 and this table had no row that could have shown it. The
  # `_vn` supplement needs its own row because it is a separate cron line and a separate seen-set,
  # so it can die while `ct_benign` beside it stays healthy.
  "host_infra|host_infra/watch.log|host_infra/host_infra.csv|2"
  "ct_benign|ct_benign/watch.log|ct_benign/detections.csv|1"
  "ct_benign_vn|ct_benign_vn/watch.log|ct_benign_vn/detections.csv|1"
)

printf "%-18s %-22s %-24s %s\n" "COLLECTOR" "RAN (log age)" "FOUND (data age)" "ROWS"
printf "%-18s %-22s %-24s %s\n" "------------------" "----------------------" "------------------------" "------"
for r in "${rows[@]}"; do
  IFS='|' read -r name log data period <<< "$r"
  if [ -f "$log" ]; then
    age=$(( (now - $(stat -c %Y "$log")) / 60 ))
    # stale if the log has not been touched in more than twice its cron period
    if [ "$age" -gt $(( period * 120 )) ]; then ran="STALE ${age}m (every ${period}h)"; else ran="ok ${age}m ago"; fi
  else
    ran="NO LOG"
  fi
  if [ -f "$data" ]; then
    dage=$(( (now - $(stat -c %Y "$data")) / 3600 ))
    n=$(( $(wc -l < "$data") - 1 ))
    # Mark, do not diagnose. A collector can RAN=ok for days and yield nothing because its
    # upstream is down -- ct_brands on 2026-08-24 ran every 2 h, exited clean, and produced zero
    # for twelve days because crt.sh was serving 502 to everyone. The table said "ok 29m ago" and
    # the only trace was a bare "298h ago" here, which reads like ordinary staleness. Twenty-four
    # missed periods is not ordinary, so say so; whether it is a dry source (chongluadao is, by
    # design) or a breakage is still the reader's call, exactly as the header promises.
    if [ "$dage" -gt $(( period * 24 )) ]; then found="DRY ${dage}h (every ${period}h)"
    else found="${dage}h ago"; fi
  else
    found="never"; n=0
  fi
  printf "%-18s %-22s %-24s %6s\n" "$name" "$ran" "$found" "$n"
done

echo
# the ChongLuaDao watcher is draining a frozen 2024 snapshot, so its remaining backlog is a
# countdown to the day it legitimately goes quiet — worth seeing before mistaking that for a fault
left=$(grep -oE 'processed [0-9]+/[0-9]+ new VN' chongluadao_live/watch.log 2>/dev/null | tail -1 || true)
[ -n "$left" ] && echo "chongluadao backlog: $left (drains ~1,800/day, then it stops finding by design)"

echo "disk: $(df -h /home | tail -1 | awk '{print $3" used of "$2" ("$5")"}')   data/raw: $(du -sh . | cut -f1)"

echo
# WINDOWED since 2026-08-24. This used to grep each log whole, so a fault that was fixed weeks
# ago kept being reported as a current complaint: the `psl` ModuleNotFoundError from the 21-22/8
# incident showed for days after the fix, and on 24/8 it cost a round of SSH to work out whether
# 2,548 crt.sh errors were history or happening now. The logs have no reliable per-line
# timestamp, so the window is the last N lines of each log -- roughly the last day or two of
# ticks. Anything older is history and belongs in the incident notes, not in a health report.
TAIL_LINES=400
echo "recent complaints (last ${TAIL_LINES} log lines per collector):"
for l in */watch.log */crawl.log */cron.log; do
  [ -f "$l" ] && tail -n "$TAIL_LINES" "$l"
done 2>/dev/null | grep -hoE '\[!\][^|]{0,90}' | sort | uniq -c | sort -rn | head -6 || echo "  (none)"
for l in */watch.log */cron.log; do
  [ -f "$l" ] && tail -n "$TAIL_LINES" "$l"
done 2>/dev/null | grep -hoE 'ModuleNotFoundError[^|]{0,60}' | sort | uniq -c | sort -rn | head -3 || true

echo
# The device is a manual copy, not a clone, so a new module can be left behind and a collector
# then dies on import while its row count looks like a quiet day (21/8). Check imports statically.
echo "collector imports present on the device:"
cd "$HOME/PhishVN"
missing=0
# Only what cron runs: scripts named in the ops wrappers plus their first-party imports.
files=$(grep -hoE 'scripts/[a-z_/]+\.py' scripts/ops/*.sh | sort -u)
for _ in 1 2; do
  for f in $files; do
    for m in $(grep -hoE '^(from [A-Za-z_][A-Za-z0-9_]* import|import [A-Za-z_][A-Za-z0-9_]*( |$))' "$f" | awk '{print $2}' | sort -u); do
      for c in "scripts/$m.py" "scripts/$m.py" "scripts/$m.py" "scripts/$m.py"; do
        [ -f "$c" ] && files="$files $c"
      done
    done
  done
  files=$(echo $files | tr ' ' '\n' | sort -u)
done
for f in $files; do
  for m in $(grep -hoE '^(from [A-Za-z_][A-Za-z0-9_]* import|import [A-Za-z_][A-Za-z0-9_]*( |$))' "$f" | awk '{print $2}' | sort -u); do
    python3 -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('$m') else 1)" 2>/dev/null && continue
    found=0
    for c in "scripts/$m.py" "scripts/$m.py" "scripts/$m.py" "scripts/$m.py" "scripts/$m/__init__.py"; do
      [ -f "$c" ] && found=1 && break
    done
    [ "$found" = 1 ] && continue
    echo "  MISSING: $m  (imported by $f)"; missing=1
  done
  # The module resolving is not enough. A first-party module deployed WITHOUT the symbol its
  # caller wants dies exactly like a missing file, and reads as a quiet day in the row counts --
  # the failure of 21/8, one level down. `from psl import apex` against a psl.py that predates
  # apex() is the live example: deploy the caller without the library and this loop is the only
  # thing between that and another silent stop.
  while read -r mod names; do
    [ -n "$mod" ] && [ -n "$names" ] || continue
    src=""
    for c in "scripts/$mod.py" "scripts/$mod.py" "scripts/$mod.py" "scripts/$mod.py"; do
      [ -f "$c" ] && src="$c" && break
    done
    [ -n "$src" ] || continue          # third-party: pip owns its contents, not this check
    for n in $names; do
      grep -qE "^(def|class) $n([ (:]|\$)|^$n *=" "$src" && continue
      echo "  MISSING SYMBOL: $mod.$n  (imported by $f; $src is stale)"; missing=1
    done
  done <<EOSYM
$(grep -hoE '^from [A-Za-z_][A-Za-z0-9_]* import [A-Za-z_][A-Za-z0-9_, ]*' "$f" \
  | tr ',' ' ' | awk '{ printf "%s", $2; for (i = 4; i <= NF; i++) printf " %s", $i; print "" }')
EOSYM
done
[ "$missing" = 0 ] && echo "  all present"
REMOTE
