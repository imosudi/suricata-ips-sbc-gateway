#!/usr/bin/env bash

# ids_ips_evaluation.sh
# 
#
# PURPOSE
# ---------------------------------------------------------------------
# Kali Linux IDS/IPS Evaluation Client for a Remote Suricata Gateway
#
# This script:
#
#   ✓ Verifies and installs required testing tools
#   ✓ Generates evaluation traffic
#   ✓ Captures packets locally
#   ✓ Retrieves Suricata alerts remotely
#   ✓ Extracts IPS drop events
#   ✓ Generates throughput benchmarks
#   ✓ Produces consolidated evaluation reports
#
# TOOLS USED
# ---------------------------------------------------------------------
#   - Nmap
#   - Hping3
#   - Scapy
#   - Hydra
#   - Sqlmap
#   - Tcpdump
#   - Tcpreplay
#   - Iperf3
#   - jq
#
# ARCHITECTURE
# ---------------------------------------------------------------------
#
#   [ Kali Evaluation Client ]
#              |
#              |
#       [ Suricata Gateway ]
#              |
#              |
#         [ Target Host ]
#
# NOTES
# ---------------------------------------------------------------------
# - Suricata is NOT required on this Kali client.
# - Suricata runs on a REMOTE gateway.
# - SSH access to the gateway is required.
#
# USAGE
# ---------------------------------------------------------------------
#
# chmod +x ids_ips_evaluation.sh
#
# sudo ./ids_ips_evaluation.sh \
#   <TARGET_IP> \
#   <INTERFACE> \
#   <WEB_URL> \
#   <SURICATA_GATEWAY_IP> \
#   <SURICATA_USER>
#
# EXAMPLE
# ---------------------------------------------------------------------
#
# sudo ./ids_ips_evaluation.sh \
#   192.168.1.50 \
#   eth0 \
#   http://192.168.1.50/login.php?id=1 \
#   192.168.1.1 \
#   suricata
#
# 

set -euo pipefail

# INPUT PARAMETERS
# 

read -p "Target IP address: " targetIP
read -p "Network interface: " interface
read -p "Web URL: (e.g. http://192.168.1.50/login.php?id=1 ) " webURL
read -p "IDS/IPS Gateway IP: " suricataGatewayIP
read -p "IDS/IPS User: " suricataUser


#TARGET="${1:-192.168.1.50}"
#INTERFACE="${2:-eth0}"
#WEB_URL="${3:-http://192.168.1.50/login.php?id=1}"
#SURICATA_GATEWAY_IP="${4:-192.168.1.1}"
#SURICATA_USER="${5:-suricata}"

TARGET=$targetIP #"${1:-192.168.1.50}"
INTERFACE=$interface #"${2:-eth0}"
#WEB_URL=$webURL #"${3:-http://192.168.1.50/login.php?id=1}"
WEB_URL="3:${WEB_URL#http://}" # Strip http:// if present

SURICATA_GATEWAY_IP=$suricataGatewayIP #"${4:-192.168.1.1}"
SURICATA_USER=$suricataUser #"${5:-suricata}"

REMOTE_EVE="/var/log/suricata/eve.json"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BASE_LOG_DIR="./ids_ips_eval_${TIMESTAMP}"

mkdir -p "$BASE_LOG_DIR"

# TERMINAL COLOURS
# 

GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
BLUE="\e[34m"
RESET="\e[0m"

log() {
    echo -e "${GREEN}[+]${RESET} $1"
}

warn() {
    echo -e "${YELLOW}[!]${RESET} $1"
}

err() {
    echo -e "${RED}[-]${RESET} $1"
}

info() {
    echo -e "${BLUE}[*]${RESET} $1"
}

# ROOT CHECK
# 

if [[ $EUID -ne 0 ]]; then
    err "Please run this script as root"
    exit 1
fi

# PACKAGE INSTALLATION FUNCTION
# 

install_package() {

    TOOL_NAME="$1"
    PACKAGE_NAME="$2"

    if command -v "$TOOL_NAME" &>/dev/null; then
        log "$TOOL_NAME already installed"
    else
        warn "$TOOL_NAME not found"
        info "Installing $PACKAGE_NAME..."

        apt-get install -y "$PACKAGE_NAME"

        if command -v "$TOOL_NAME" &>/dev/null; then
            log "$TOOL_NAME installation successful"
        else
            err "$TOOL_NAME installation failed"
            exit 1
        fi
    fi
}

# UPDATE REPOSITORIES
# 

log "Updating package repositories..."

apt-get update -y

# INSTALL REQUIRED TOOLS
# 

log "Checking required packages..."

install_package nmap nmap
install_package hping3 hping3
install_package python3 python3
install_package hydra hydra
install_package sqlmap sqlmap
install_package tcpdump tcpdump
install_package tcpreplay tcpreplay
install_package iperf3 iperf3
install_package jq jq
install_package ssh ssh

# INSTALL SCAPY
# 

if python3 -c "import scapy" 2>/dev/null; then
    log "Scapy already installed"
else
    warn "Scapy not installed"
    info "Installing python3-scapy..."

    apt-get install -y python3-scapy

    if python3 -c "import scapy" 2>/dev/null; then
        log "Scapy installation successful"
    else
        err "Scapy installation failed"
        exit 1
    fi
fi

# DISPLAY CONFIGURATION
# 

echo ""
echo "========================================================"
echo " IDS/IPS EVALUATION CONFIGURATION"
echo "========================================================"
echo " Target Host        : $TARGET"
echo " Interface          : $INTERFACE"
echo " Web URL            : $WEB_URL"
echo " Suricata Gateway   : $SURICATA_GATEWAY_IP"
echo " SSH User           : $SURICATA_USER"
echo " Remote eve.json    : $REMOTE_EVE"
echo " Log Directory      : $BASE_LOG_DIR"
echo "========================================================"
echo ""

# VERIFY SSH CONNECTIVITY
# 

log "Checking SSH connectivity to Suricata gateway..."

if ssh \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    "${SURICATA_USER}@${SURICATA_GATEWAY_IP}" \
    "echo connected" &>/dev/null; then

    log "Remote Suricata gateway reachable"

else
    err "Unable to connect to remote Suricata gateway"
    err "Ensure:"
    err "  - SSH server is enabled"
    err "  - Firewall allows SSH"
    err "  - SSH keys/password authentication works"

    exit 1
fi

# VERIFY REMOTE EVE.JSON
# 

log "Checking remote Suricata eve.json..."

if ssh "${SURICATA_USER}@${SURICATA_GATEWAY_IP}" \
    "[ -f $REMOTE_EVE ]"; then

    log "Remote eve.json located"

else
    err "Remote eve.json not found"
    exit 1
fi

# START PACKET CAPTURE
# 

log "Starting tcpdump capture..."

tcpdump \
    -i "$INTERFACE" \
    -nn \
    -w "$BASE_LOG_DIR/traffic_capture.pcap" \
    > /dev/null 2>&1 &

TCPDUMP_PID=$!

sleep 3

# NMAP RECONNAISSANCE
# 

log "Running Nmap reconnaissance scan..."

nmap \
    -sS \
    -sV \
    -O \
    -T4 \
    -Pn \
    "$TARGET" \
    -oA "$BASE_LOG_DIR/nmap_scan"

# HPING3 SYN FLOOD
# 

log "Running Hping3 SYN flood simulation..."

timeout 15 hping3 \
    -S \
    -p 80 \
    --flood \
    --rand-source \
    "$TARGET" \
    > "$BASE_LOG_DIR/hping3.log" 2>&1 || true

# SCAPY MALFORMED PACKETS
# 

log "Generating malformed packets using Scapy..."

cat <<EOF > "$BASE_LOG_DIR/scapy_test.py"
from scapy.all import *

target = "$TARGET"

pkt = IP(dst=target)/TCP(dport=80, flags="SF")/"SURICATA_TEST"

send(pkt, count=20)

print("Malformed packets transmitted")
EOF

python3 "$BASE_LOG_DIR/scapy_test.py" \
    > "$BASE_LOG_DIR/scapy.log" 2>&1

# HYDRA BRUTE FORCE TEST
# 

log "Running Hydra SSH brute-force simulation..."

if [ -f /usr/share/wordlists/rockyou.txt ]; then

    timeout 30 hydra \
        -l admin \
        -P /usr/share/wordlists/rockyou.txt \
        ssh://"$TARGET" \
        -o "$BASE_LOG_DIR/hydra.log" \
        > /dev/null 2>&1 || true

else
    warn "rockyou.txt not found — skipping Hydra test"
fi

# SQLMAP TEST
# 

log "Running SQLMap injection simulation..."

sqlmap \
    -u "$WEB_URL" \
    --batch \
    --random-agent \
    --level=3 \
    --risk=2 \
    --output-dir="$BASE_LOG_DIR/sqlmap_output" \
    > "$BASE_LOG_DIR/sqlmap.log" 2>&1 || true

# IPERF3 THROUGHPUT TEST
# 

log "Running iPerf3 throughput benchmark..."

iperf3 \
    -c "$TARGET" \
    -t 20 \
    -P 5 \
    --json \
    > "$BASE_LOG_DIR/iperf3.json" 2>/dev/null || true

# STOP PACKET CAPTURE
# 

log "Stopping tcpdump capture..."

kill "$TCPDUMP_PID" || true

sleep 2

# TCPREPLAY TEST
# 

if [ -f "$BASE_LOG_DIR/traffic_capture.pcap" ]; then

    log "Replaying captured traffic..."

    tcpreplay \
        -i "$INTERFACE" \
        "$BASE_LOG_DIR/traffic_capture.pcap" \
        > "$BASE_LOG_DIR/tcpreplay.log" 2>&1 || true
fi

# RETRIEVE SURICATA ALERTS
# 

log "Retrieving Suricata alerts from gateway..."

ssh "${SURICATA_USER}@${SURICATA_GATEWAY_IP}" \
"sudo jq 'select(.event_type==\"alert\")' $REMOTE_EVE" \
> "$BASE_LOG_DIR/suricata_alerts.json"

# ALERT SUMMARY
# 

log "Generating alert summary..."

ssh "${SURICATA_USER}@${SURICATA_GATEWAY_IP}" \
"sudo jq -r '
select(.event_type==\"alert\")
| .alert.signature
' $REMOTE_EVE" \
| sort \
| uniq -c \
| sort -nr \
> "$BASE_LOG_DIR/alert_summary.txt"

# IPS DROP EVENTS
# 

log "Extracting IPS drop events..."

ssh "${SURICATA_USER}@${SURICATA_GATEWAY_IP}" \
"sudo jq '
select(.event_type==\"drop\")
' $REMOTE_EVE" \
> "$BASE_LOG_DIR/drop_events.json"

# THROUGHPUT EXTRACTION
# 

if [ -f "$BASE_LOG_DIR/iperf3.json" ]; then

    log "Extracting throughput metrics..."

    jq '
.end.sum_received.bits_per_second
' "$BASE_LOG_DIR/iperf3.json" \
    > "$BASE_LOG_DIR/throughput_bps.txt" || true
fi

# FINAL REPORT
# 

REPORT="$BASE_LOG_DIR/final_report.txt"

log "Generating final report..."

{
echo "=========================================================="
echo " IDS/IPS EVALUATION REPORT"
echo "=========================================================="
echo ""
echo "Timestamp           : $(date)"
echo "Target Host         : $TARGET"
echo "Network Interface   : $INTERFACE"
echo "Web URL             : $WEB_URL"
echo "Suricata Gateway    : $SURICATA_GATEWAY_IP"
echo "SSH User            : $SURICATA_USER"
echo ""
echo "=========================================================="
echo " TESTS EXECUTED"
echo "=========================================================="
echo "✓ Nmap Reconnaissance"
echo "✓ Hping3 SYN Flood"
echo "✓ Scapy Malformed Packets"
echo "✓ Hydra Brute Force"
echo "✓ SQLMap Injection"
echo "✓ iPerf3 Throughput"
echo "✓ Tcpreplay Replay"
echo ""
echo "=========================================================="
echo " TOP SURICATA ALERTS"
echo "=========================================================="

cat "$BASE_LOG_DIR/alert_summary.txt" 2>/dev/null || true

echo ""
echo "=========================================================="
echo " GENERATED FILES"
echo "=========================================================="

find "$BASE_LOG_DIR" -type f

echo ""
echo "=========================================================="
echo " EVALUATION COMPLETE"
echo "=========================================================="

} > "$REPORT"

# DISPLAY COMPLETION
# 

echo ""
log "IDS/IPS evaluation completed successfully"
log "Logs stored at: $BASE_LOG_DIR"
log "Final report: $REPORT"

echo ""
echo "Useful Commands"
echo "----------------------------------------------------------"
echo ""
echo "View remote Suricata alerts:"
echo "ssh ${SURICATA_USER}@${SURICATA_GATEWAY_IP}"
echo ""
echo "Monitor eve.json live:"
echo "sudo tail -f $REMOTE_EVE | jq"
echo ""
echo "Open packet capture:"
echo "wireshark $BASE_LOG_DIR/traffic_capture.pcap"
echo ""
echo "View alert summary:"
echo "cat $BASE_LOG_DIR/alert_summary.txt"
echo ""
