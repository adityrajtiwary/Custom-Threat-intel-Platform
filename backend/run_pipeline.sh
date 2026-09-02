#!/bin/bash
# Threat Intel Pipeline -- cron isko chalata hai
# Har run ka log banta hai taaki fail hone pe pata chale (DevSecOps: observability)

set -u  # undefined variable pe error

cd "$HOME/threat-intel" || exit 1
source venv/bin/activate

LOG_DIR="$HOME/threat-intel/logs"
mkdir -p "$LOG_DIR"
STAMP=$(date +%Y%m%d_%H%M%S)
LOG="$LOG_DIR/pipeline_$STAMP.log"

# jo connector arg me diya wahi chalao, warna sabhi
CONNECTORS=("$@")
if [ ${#CONNECTORS[@]} -eq 0 ]; then
  CONNECTORS=(connector_threatfox connector_rl_iocs connector_cisa_kev connector_hackernews)
fi

echo "=== Pipeline run: $STAMP ===" | tee -a "$LOG"

for c in "${CONNECTORS[@]}"; do
  echo "--- Running $c ---" | tee -a "$LOG"
  if python "$c.py" >> "$LOG" 2>&1; then
    echo "    OK: $c" | tee -a "$LOG"
  else
    echo "    FAIL: $c (see log)" | tee -a "$LOG"
  fi
done

# processors -- raw se clean
echo "--- Running processor_structured ---" | tee -a "$LOG"
python processor_structured.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"

echo "--- Running enrich_abuseipdb ---" | tee -a "$LOG"
python enrich_abuseipdb.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"

echo "--- Running enrich_shodan ---" | tee -a "$LOG"
python enrich_shodan.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"

echo "--- Running compute_risk ---" | tee -a "$LOG"
python compute_risk.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"

echo "=== Done: $(date +%H:%M:%S) ===" | tee -a "$LOG"

# purane log 14 din se zyada hataao (disk bloat na ho)
find "$LOG_DIR" -name "pipeline_*.log" -mtime +14 -delete
