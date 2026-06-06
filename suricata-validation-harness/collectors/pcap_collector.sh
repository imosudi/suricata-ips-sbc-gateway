#!/usr/bin/env bash
# collectors/pcap_collector.sh
# Two-track PCAP strategy (Kali-deployed, remote-model):
#   Track A — Local capture: tcpdump on Kali's outbound interface.
#             Captures the attack traffic as it leaves Kali.
#   Track B — Remote fetch: SCP any pcap-log files written by Suricata
#             on the gateway (requires pcap-log enabled in suricata.yaml).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config/lab.conf"

SESSION_ID="${SESSION_ID:-session_unknown}"
LOCAL_PCAP="$PCAP_DIR/${SESSION_ID}_kali.pcap"
mkdir -p "$PCAP_DIR"

# ── Track A: local capture ────────────────────────────────────────────────────
if [[ "${PCAP_ENABLED:-true}" == "true" ]] && command -v tcpdump >/dev/null 2>&1; then
    echo "[pcap_collector] Starting local capture on ${KALI_IFACE} → $LOCAL_PCAP"
    # Run in background; harness kills by PID after attack window
    tcpdump -i "${KALI_IFACE}" \
            -w "$LOCAL_PCAP" \
            -s "${PCAP_SNAPLEN:-65535}" \
            ${PCAP_FILTER:+"$PCAP_FILTER"} \
            2>/dev/null &
    echo $! > "$PCAP_DIR/${SESSION_ID}_tcpdump.pid"
    echo "[pcap_collector] tcpdump PID $(cat "$PCAP_DIR/${SESSION_ID}_tcpdump.pid")"
else
    echo "[pcap_collector] Local PCAP disabled or tcpdump not found — skipping Track A"
fi

# ── Track B: fetch Suricata pcap-log from gateway ────────────────────────────
SSH="ssh $GW_SSH_OPTS -i $GW_SSH_KEY -p $GW_SSH_PORT ${GW_USER}@${GW_HOST}"
REMOTE_PCAPS=$($SSH "ls -t '${GW_PCAP_DIR}'/*.pcap 2>/dev/null | head -5" 2>/dev/null || echo "")

if [[ -n "$REMOTE_PCAPS" ]]; then
    echo "[pcap_collector] Fetching remote Suricata pcap-log files..."
    while IFS= read -r rfile; do
        fname=$(basename "$rfile")
        scp $GW_SSH_OPTS -i "$GW_SSH_KEY" -P "$GW_SSH_PORT" \
            "${GW_USER}@${GW_HOST}:${rfile}" \
            "$PCAP_DIR/${SESSION_ID}_gw_${fname}" 2>/dev/null && \
            echo "[pcap_collector]   Fetched: $fname" || \
            echo "[pcap_collector]   Failed to fetch: $fname"
    done <<< "$REMOTE_PCAPS"
else
    echo "[pcap_collector] No remote Suricata pcap-log files found (pcap-log may be disabled)"
fi
