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
    found="${dage}h ago"
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
echo "recent complaints in the logs:"
grep -hoE '\[!\][^|]{0,90}' */watch.log */crawl.log */cron.log 2>/dev/null | sort | uniq -c | sort -rn | head -6 || echo "  (none)"
grep -hoE 'ModuleNotFoundError[^|]{0,60}' */watch.log */cron.log 2>/dev/null | sort | uniq -c | sort -rn | head -3 || true

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
done
[ "$missing" = 0 ] && echo "  all present"
REMOTE
