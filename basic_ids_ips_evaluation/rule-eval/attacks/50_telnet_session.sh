#!/usr/bin/env bash
# attacks/50_telnet_session.sh
# Establishes a Telnet session with login/password prompts visible in stream
# Triggers SIDs: 9000501 (session), 9000502 (login prompt), 9000503 (password)
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_50_telnet_session.pcap"

echo "[50_telnet_session] Starting capture (TCP/23)"
tcpdump -i "${KALI_IFACE}" tcp port 23 -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

# Spin up a fake Telnet server on Kali that sends login+password prompts
# This simulates what the rule sees on the wire going to $HOME_NET port 23
echo "[50_telnet_session] Starting mock Telnet server on port 23 (requires root or cap_net_bind)"
{
    echo -e "Trying ${TARGET_IP}...\r"
    echo -e "Connected to ${TARGET_IP}.\r"
    echo -e "\r"
    echo -e "Ubuntu 24.04 LTS\r"
    echo -e "login: \r"
    sleep 2
    echo -e "Password: \r"
    sleep 2
    echo -e "Login incorrect\r"
} | sudo timeout 8 ncat -l 23 --keep-open --max-conns 2 &
SRV_PID=$!
sleep 1

# Kali connects to itself — traffic goes via loopback but Suricata on gateway
# sees the same pattern when clients connect to TARGET_IP:23
echo "[50_telnet_session] Connecting to mock Telnet server"
{
    echo -e "admin\r"
    sleep 1
    echo -e "admin123\r"
    sleep 1
    echo -e "exit\r"
} | timeout 7 ncat "127.0.0.1" 23 2>/dev/null || true

# Also attempt real connection to TARGET_IP to ensure gateway sees it
echo "[50_telnet_session] Attempting real Telnet → ${TARGET_IP}:23"
{
    echo -e "admin\r"
    sleep 1
    echo -e "password\r"
    sleep 1
} | timeout "${TELNET_TIMEOUT}" ncat "${TARGET_IP}" "${TELNET_PORT}" 2>/dev/null || true

kill "${SRV_PID}" 2>/dev/null || true

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[50_telnet_session] Done — PCAP: ${PCAP}"
