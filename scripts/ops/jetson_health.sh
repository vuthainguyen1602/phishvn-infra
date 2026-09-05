#!/usr/bin/env bash
# jetson_health.sh — One-screen health report for collectors running on the Jetson.
#
# Reports process health (RAN: log freshness) and yield (FOUND: data growth).
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
  "host_infra|host_infra/watch.log|host_infra/host_infra.csv|2"
  "ct_benign|ct_benign/watch.log|ct_benign/detections.csv|1"
  "ct_benign_vn|ct_benign_vn/watch.log|ct_benign_vn/detections.csv|1"
)

# Optional host-specific extra collectors
extra_rows="$HOME/PhishVN/scripts/ops/jetson_health.rows.local"
[ -f "$extra_rows" ] || extra_rows="$HOME/PhishVN/scripts/ops/jetson_health.rows.local"
if [ -f "$extra_rows" ]; then
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    rows+=("$line")
  done < "$extra_rows"
fi

# Filter collectors present on this host
present=()
for r in "${rows[@]}"; do

  IFS='|' read -r _n _l _d _p <<< "$r"
  if [ -e "$_l" ] || [ -e "$_d" ]; then present+=("$r"); fi
done
if [ "${#present[@]}" -gt 0 ]; then rows=("${present[@]}"); fi

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
    # Check if collector exhausted static list or is dry
    if tail -40 "$log" 2>/dev/null | grep -qE '0 not yet captured'; then
      found="DONE ${dage}h (list exhausted)"
    elif [ "$dage" -gt $(( period * 24 )) ]; then found="DRY ${dage}h (every ${period}h)"
    else found="${dage}h ago"; fi
  else
    found="never"; n=0
  fi
  printf "%-18s %-22s %-24s %6s\n" "$name" "$ran" "$found" "$n"
done

echo
# ChongLuaDao snapshot backlog countdown
left=$(grep -oE 'processed [0-9]+/[0-9]+ new VN' chongluadao_live/watch.log 2>/dev/null | tail -1 || true)
[ -n "$left" ] && echo "chongluadao backlog: $left"

echo "disk: $(df -h /home | tail -1 | awk '{print $3" used of "$2" ("$5")"}')   data/raw: $(du -sh . | cut -f1)"

echo
# Show recent complaints in last N lines
TAIL_LINES=400
echo "recent complaints (last ${TAIL_LINES} log lines per collector):"
for l in */watch.log */crawl.log */cron.log; do
  [ -f "$l" ] && tail -n "$TAIL_LINES" "$l"
done 2>/dev/null | grep -hoE '\[!\][^|]{0,90}' | sort | uniq -c | sort -rn | head -6 || echo "  (none)"
for l in */watch.log */cron.log; do
  [ -f "$l" ] && tail -n "$TAIL_LINES" "$l"
done 2>/dev/null | grep -hoE 'ModuleNotFoundError[^|]{0,60}' | sort | uniq -c | sort -rn | head -3 || true

echo
# Statically check collector module dependencies on device
echo "collector imports present on the device:"
cd "$HOME/PhishVN"
missing=0
files=$(cat scripts/ops/*.sh scripts/ops/*.sh scripts/*/run_*.sh 2>/dev/null |
        grep -hoE 'scripts/[a-z_/]+\.py' | sort -u)
[ -z "$files" ] && echo "  (no wrapper scripts on this host — nothing to check)"
for _ in 1 2; do
  for f in $files; do
    for m in $(grep -hoE '^(from [A-Za-z_][A-Za-z0-9_]* import|import [A-Za-z_][A-Za-z0-9_]*( |$))' "$f" | awk '{print $2}' | sort -u); do
      for c in "scripts/$m.py" "scripts/$m.py" scripts/*/"$m.py" scripts/*/"$m.py" scripts/*/"$m.py" scripts/*/"$m.py" "scripts/$m.py"; do
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
    for c in "scripts/$m.py" "scripts/$m.py" "scripts/$m.py" scripts/*/"$m.py" scripts/*/"$m.py" scripts/*/"$m.py" scripts/*/"$m.py" "scripts/$m/__init__.py"; do
      [ -f "$c" ] && found=1 && break
    done
    [ "$found" = 1 ] && continue
    echo "  MISSING: $m  (imported by $f)"; missing=1
  done
  # Check first-party imported symbols

  while read -r mod names; do
    [ -n "$mod" ] && [ -n "$names" ] || continue
    src=""
    for c in "scripts/$mod.py" "scripts/$mod.py" scripts/*/"$mod.py" scripts/*/"$mod.py"; do
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
