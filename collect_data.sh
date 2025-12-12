#!/bin/bash

DASHBOARD_DIR="/home/$(whoami)/cyber-dashboard"
DATA_DIR="$DASHBOARD_DIR/data"
MITM_LOG="/home/$(whoami)/mitm/logs/mitmproxy.log"
LABELS="/home/$(whoami)/mitm/labels/attack_window.csv"

mkdir -p "$DATA_DIR"

echo "[+] Collecting MITM attack data..."

if [ -f "$MITM_LOG" ]; then
    echo "  - Parsing mitmproxy logs..."
    python3 "$DASHBOARD_DIR/scripts/parse_mitm_logs.py" "$MITM_LOG" > "$DATA_DIR/mitm_events.json"
else
    echo "  - WARNING: MITM log not found at $MITM_LOG"
    echo "[]" > "$DATA_DIR/mitm_events.json"
fi

if [ -f "$LABELS" ]; then
    echo "  - Copying attack timeline..."
    cp "$LABELS" "$DATA_DIR/attack_timeline.csv"
else
    echo "  - WARNING: Attack labels not found at $LABELS"
    echo "timestamp,event" > "$DATA_DIR/attack_timeline.csv"
fi

echo "[]" > "$DATA_DIR/suricata_events.json"

echo "  - Generating summary..."
python3 -c "
import json

try:
    with open('$DATA_DIR/mitm_events.json', 'r') as f:
        mitm = json.load(f)
except:
    mitm = []

try:
    with open('$DATA_DIR/suricata_events.json', 'r') as f:
        suricata = json.load(f)
except:
    suricata = []

summary = {
    'total_http_requests': len([e for e in mitm if e.get('type') == 'http_request']),
    'total_connections': len([e for e in mitm if e.get('type') == 'client_connect']),
    'total_suricata_events': len(suricata),
    'unique_urls': len(set(e.get('url', '') for e in mitm if e.get('type') == 'http_request')),
    'data_collected_at': '$(date -Iseconds)'
}

with open('$DATA_DIR/summary.json', 'w') as f:
    json.dump(summary, f, indent=2)
print('Summary created')
"

echo "[+] Data collection complete!"
echo "    - MITM events: $DATA_DIR/mitm_events.json"
echo "    - Suricata events: $DATA_DIR/suricata_events.json"
echo "    - Timeline: $DATA_DIR/attack_timeline.csv"
echo "    - Summary: $DATA_DIR/summary.json"