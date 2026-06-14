#!/usr/bin/env bash
# attacks/30_http_example_host.sh
# Sends HTTP requests with Host: example.com/net/org headers through the gateway
# Triggers SIDs: 9000300, 9000301, 9000302
# Note: traffic must exit via GATEWAY_IP (wlan0) to be inspected.
#       Requests are made to the real external IP of example.com so they
#       traverse the gateway's WAN interface.
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_30_http_example_host.pcap"

echo "[30_http_example_host] Starting capture"
tcpdump -i "${KALI_IFACE}" tcp port "${HTTP_PORT}" -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

for domain in example.com example.net example.org; do
    echo "[30_http_example_host] GET http://${domain}/ (Host: ${domain})"
    curl -s -o /dev/null \
         --max-time "${HTTP_TIMEOUT}" \
         --http1.1 \
         "http://${domain}/" \
    || true
    sleep 1
done

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[30_http_example_host] Done — PCAP: ${PCAP}"
