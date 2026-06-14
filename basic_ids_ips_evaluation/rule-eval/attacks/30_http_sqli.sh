#!/usr/bin/env bash
# attacks/30_http_sqli.sh
# SQL injection in URI → SID 9000310
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_30_http_sqli.pcap"

echo "[30_http_sqli] Starting capture"
tcpdump -i "${KALI_IFACE}" tcp port "${HTTP_PORT}" -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

# Classic OR-based SQLi payloads — should match the pcre in SID 9000310
PAYLOADS=(
    "/login.php?user=admin'%20OR%20'1'='1"
    "/index.php?id=1%27%20OR%201=1--"
    "/search?q=1%27%20AND%20%271%27=%271"
)

for payload in "${PAYLOADS[@]}"; do
    echo "[30_http_sqli] Sending: http://${TARGET_IP}${payload}"
    curl -s -o /dev/null \
         --max-time "${HTTP_TIMEOUT}" \
         --http1.1 \
         "http://${TARGET_IP}${payload}" \
    || true
    sleep 1
done

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[30_http_sqli] Done — PCAP: ${PCAP}"
