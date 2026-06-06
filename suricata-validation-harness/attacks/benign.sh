#!/usr/bin/env bash
# attacks/benign.sh — Baseline legitimate traffic module
# Goal: generate traffic that should NOT trigger any Suricata alerts.
set -euo pipefail

TARGET="${TARGET:-10.10.10.1}"
BASE_HTTP="${HTTP_TARGET:-http://${TARGET}}"
DURATION="${DURATION:-30}"

echo "[benign] Generating baseline legitimate traffic (${DURATION}s)..."

END=$(( SECONDS + DURATION ))
while [[ $SECONDS -lt $END ]]; do
    # Normal HTTP GET
    curl -sk -A "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
        "${BASE_HTTP}/" -o /dev/null 2>/dev/null || true

    # ICMP echo (normal)
    ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1 || true

    # DNS A query (normal)
    dig @"$TARGET" google.com A +short +time=1 +tries=1 >/dev/null 2>&1 || true

    sleep 1
done

# iperf3 bandwidth test (if both client and server available)
if command -v iperf3 >/dev/null 2>&1; then
    echo "[benign] iperf3 throughput baseline (5s)..."
    iperf3 -c "$TARGET" -t 5 -J >/dev/null 2>&1 || true
fi

echo "[benign] Module complete."
