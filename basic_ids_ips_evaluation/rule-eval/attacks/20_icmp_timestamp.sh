#!/usr/bin/env bash
# attacks/20_icmp_timestamp.sh
# Sends ICMP Type 13 (Timestamp Request) to TARGET_IP
# Triggers SIDs: 9000201 (request), 9000202 (reply)
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_20_icmp_timestamp.pcap"

echo "[20_icmp_timestamp] Starting capture on ${KALI_IFACE}"
tcpdump -i "${KALI_IFACE}" icmp -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

echo "[20_icmp_timestamp] Sending ICMP Type 13 (Timestamp Request) → ${TARGET_IP}"
# hping3 --icmptype 13 sends ICMP timestamp requests
hping3 --icmp --icmptype 13 -c 5 "${TARGET_IP}" 2>/dev/null || true

echo "[20_icmp_timestamp] Sending ICMP Type 14 (Timestamp Reply spoofed) → ${TARGET_IP}"
# Craft a timestamp reply — some IDS rulesets also alert on type 14 inbound
hping3 --icmp --icmptype 14 -c 5 "${TARGET_IP}" 2>/dev/null || true

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true

echo "[20_icmp_timestamp] Done — PCAP: ${PCAP}"
