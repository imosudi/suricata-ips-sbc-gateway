#!/usr/bin/env bash
# attacks/50_telnet_bigbang.sh
# Sends "Big Bang Theory" string over a Telnet session (TCP/23)
# Rule is bidirectional (<>) so both client→server and server→client are tested
# Triggers SID 9000500
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_50_telnet_bigbang.pcap"

echo "[50_telnet_bigbang] Starting capture (TCP/23)"
tcpdump -i "${KALI_IFACE}" tcp port 23 -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

# ── Client → Server: type "Big Bang Theory" as a command ──────────────────
echo "[50_telnet_bigbang] Client→Server: Big Bang Theory string via ncat"
echo -e "Big Bang Theory\r\nquit\r\n" | \
    timeout "${TELNET_TIMEOUT}" ncat "${TARGET_IP}" 23 2>/dev/null || true
sleep 1

# ── Serve "Big Bang Theory" back from Kali as a fake Telnet server ────────
# This tests the server→client direction of the bidirectional rule
echo "[50_telnet_bigbang] Server→Client: fake Telnet server replying with Big Bang Theory"
{
    echo -e "Welcome to the Big Bang Theory test server\r"
    echo -e "Login: \r"
    sleep 3
} | timeout 6 ncat -l "${TELNET_PORT}" --keep-open --max-conns 1 &
SRV_PID=$!
sleep 1

# Connect to our fake server (loopback — adjust if gateway-visible test needed)
echo -e "testuser\r\n" | \
    timeout 4 ncat "127.0.0.1" "${TELNET_PORT}" 2>/dev/null || true

kill "${SRV_PID}" 2>/dev/null || true

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[50_telnet_bigbang] Done — PCAP: ${PCAP}"
