#!/usr/bin/env bash
# attacks/30_http_scanners.sh
# Sends requests with sqlmap and Nikto User-Agent strings → SIDs 9000312, 9000313
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_30_http_scanners.pcap"

echo "[30_http_scanners] Starting capture"
tcpdump -i "${KALI_IFACE}" tcp port "${HTTP_PORT}" -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

# sqlmap User-Agent — SID 9000312
echo "[30_http_scanners] sqlmap UA → http://${TARGET_IP}/"
curl -s -o /dev/null \
     --max-time "${HTTP_TIMEOUT}" \
     --http1.1 \
     -A "sqlmap/1.7.8#stable (https://sqlmap.org)" \
     "http://${TARGET_IP}/" \
|| true
sleep 1

# Nikto User-Agent — SID 9000313
echo "[30_http_scanners] Nikto UA → http://${TARGET_IP}/"
curl -s -o /dev/null \
     --max-time "${HTTP_TIMEOUT}" \
     --http1.1 \
     -A "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)" \
     "http://${TARGET_IP}/" \
|| true

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[30_http_scanners] Done — PCAP: ${PCAP}"
