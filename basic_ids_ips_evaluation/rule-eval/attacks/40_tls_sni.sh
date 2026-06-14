#!/usr/bin/env bash
# attacks/40_tls_sni.sh
# Initiates TLS connections to example.com/net/org — Suricata reads the SNI
# in the ClientHello to trigger SIDs 9000401, 9000402, 9000403
# Certificate CN rules (9000404-9000406) fire when TLS 1.2 handshake completes
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_40_tls_sni.pcap"

echo "[40_tls_sni] Starting capture (port 443)"
tcpdump -i "${KALI_IFACE}" tcp port 443 -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

for domain in example.com example.net example.org; do
    echo "[40_tls_sni] TLS connection → https://${domain}/"
    # --tls-max 1.2 forces TLS 1.2 so cert_subject rules also fire
    curl -s -o /dev/null \
         --max-time "${HTTP_TIMEOUT}" \
         --tls-max 1.2 \
         "https://${domain}/" \
    || true
    sleep 2

    # Also attempt with default TLS (1.3) for SNI-only rules
    echo "[40_tls_sni] TLS connection (TLS 1.3) → https://${domain}/"
    curl -s -o /dev/null \
         --max-time "${HTTP_TIMEOUT}" \
         "https://${domain}/" \
    || true
    sleep 1
done

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[40_tls_sni] Done — PCAP: ${PCAP}"
