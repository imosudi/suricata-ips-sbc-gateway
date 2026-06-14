#!/usr/bin/env bash
# attacks/40_tls_deprecated.sh
# Forces TLS 1.0 connection → SID 9000410 (deprecated version)
# Also attempts TLS on non-standard port → SID 9000411
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_40_tls_deprecated.pcap"

echo "[40_tls_deprecated] Starting capture"
tcpdump -i "${KALI_IFACE}" tcp -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

# ── SID 9000410: TLS 1.0 ─────────────────────────────────────────────────
echo "[40_tls_deprecated] Attempting TLS 1.0 connection to ${EXTERNAL_IP}"
# openssl s_client gives fine-grained TLS version control
echo | timeout 6 openssl s_client \
    -connect "${EXTERNAL_IP}:443" \
    -tls1 \
    -servername "example.com" \
    2>/dev/null || true
sleep 2

# ── SID 9000411: TLS on non-standard port ─────────────────────────────────
# Spin up a self-signed TLS listener on the Kali machine itself on port 8443
# then have the gateway-transiting traffic hit it
echo "[40_tls_deprecated] TLS on non-standard port (8443) → SID 9000411"

# Generate a throwaway self-signed cert if not already present
if [[ ! -f /tmp/eval_tls.key ]]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout /tmp/eval_tls.key \
        -out /tmp/eval_tls.crt \
        -days 1 -nodes \
        -subj "/CN=eval.lab" 2>/dev/null
fi

# Launch listener
openssl s_server \
    -key /tmp/eval_tls.key \
    -cert /tmp/eval_tls.crt \
    -accept 8443 \
    -quiet &
SRV_PID=$!
sleep 1

# Connect to it (traffic goes via lo, but tshark will still see the TLS handshake)
echo | timeout 5 openssl s_client \
    -connect "127.0.0.1:8443" \
    -tls1_2 2>/dev/null || true

# For gateway visibility: attempt against TARGET_IP:8443 (if target has a listener)
echo | timeout 5 openssl s_client \
    -connect "${TARGET_IP}:8443" 2>/dev/null || true

kill "${SRV_PID}" 2>/dev/null || true

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[40_tls_deprecated] Done — PCAP: ${PCAP}"
