#!/usr/bin/env bash
# collectors/pcap_stop.sh — Stop the background tcpdump started by pcap_collector.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config/lab.conf"

SESSION_ID="${SESSION_ID:-session_unknown}"
PID_FILE="$PCAP_DIR/${SESSION_ID}_tcpdump.pid"

if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" && echo "[pcap_stop] Stopped tcpdump PID $PID"
    fi
    rm -f "$PID_FILE"
else
    echo "[pcap_stop] No tcpdump PID file found — nothing to stop"
fi
