#!/usr/bin/env bash
# attacks/30_http_bigbang.sh
# Tests "Big Bang Theory" string detection across all four HTTP vectors:
#   URI (SID 9000303), request body (9000304), header (9000305), response (9000306)
#
# For response body (9000306): we need a server that replies with "Big Bang Theory".
# We spin up a tiny Python HTTP server on TARGET_IP port 8080 via SSH,
# then fetch from it. If SSH to target isn't available, that sub-test is skipped.
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"
PCAP="${PCAPS_DIR}/${RUN_ID}_30_http_bigbang.pcap"

echo "[30_http_bigbang] Starting capture"
tcpdump -i "${KALI_IFACE}" tcp port "${HTTP_PORT}" -w "${PCAP}" -q &
CAP_PID=$!
sleep 1

BASE_URL="http://${EXTERNAL_IP}"

# ── SID 9000303: Big Bang Theory in URI ────────────────────────────────────
echo "[30_http_bigbang] URI test → ${BASE_URL}/search?q=Big+Bang+Theory"
curl -s -o /dev/null \
     --max-time "${HTTP_TIMEOUT}" \
     --http1.1 \
     "${BASE_URL}/search?q=Big+Bang+Theory" \
|| true
sleep 1

# ── SID 9000304: Big Bang Theory in POST body ──────────────────────────────
echo "[30_http_bigbang] POST body test → ${BASE_URL}/"
curl -s -o /dev/null \
     --max-time "${HTTP_TIMEOUT}" \
     --http1.1 \
     -X POST \
     -d "show=Big Bang Theory&season=1" \
     "${BASE_URL}/" \
|| true
sleep 1

# ── SID 9000305: Big Bang Theory in request header ────────────────────────
echo "[30_http_bigbang] Header test → ${BASE_URL}/"
curl -s -o /dev/null \
     --max-time "${HTTP_TIMEOUT}" \
     --http1.1 \
     -H "X-Favourite-Show: Big Bang Theory" \
     "${BASE_URL}/" \
|| true
sleep 1

# ── SID 9000306: Big Bang Theory in response body ─────────────────────────
# Use ncat to serve a single HTTP response from Kali itself, then curl-fetch it
# from a second terminal context — or set up a transient listener:
echo "[30_http_bigbang] Response body test (local ncat server on port 18080)"
RESPONSE="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Big Bang Theory</html>"
echo -e "${RESPONSE}" | timeout 8 ncat -l 18080 --keep-open --max-conns 2 &
NCAT_PID=$!
sleep 1
# Gateway sees: internal client → internal server delivering Big Bang Theory body
curl -s -o /dev/null \
     --max-time "${HTTP_TIMEOUT}" \
     "http://127.0.0.1:18080/" \
|| true
kill "${NCAT_PID}" 2>/dev/null || true

sleep "${ALERT_SETTLE_SECS}"
kill "${CAP_PID}" 2>/dev/null; wait "${CAP_PID}" 2>/dev/null || true
echo "[30_http_bigbang] Done — PCAP: ${PCAP}"
