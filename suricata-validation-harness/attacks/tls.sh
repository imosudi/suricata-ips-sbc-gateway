#!/usr/bin/env bash
# attacks/tls.sh — TLS/SSL anomaly module
set -euo pipefail

TARGET="${TLS_TARGET:-${TARGET:-10.10.10.1}}"
PORT="${TLS_PORT:-443}"

echo "[tls] Starting TLS module → $TARGET:$PORT"

# 1. Enumerate supported cipher suites
echo "[tls] Cipher enumeration (legacy suites)..."
for cipher in RC4-SHA DES-CBC-SHA NULL-MD5 EXPORT-RC4-MD5; do
    openssl s_client -connect "${TARGET}:${PORT}" -cipher "$cipher" \
        </dev/null 2>/dev/null | grep -E "(Cipher|CONNECTED|error)" || true
done

# 2. Check for SSLv3 / TLS 1.0
echo "[tls] Protocol version probes..."
for ver in -ssl3 -tls1 -tls1_1; do
    openssl s_client $ver -connect "${TARGET}:${PORT}" \
        </dev/null 2>/dev/null | head -3 || true
done

# 3. Certificate inspection
echo "[tls] Certificate check..."
echo | openssl s_client -connect "${TARGET}:${PORT}" 2>/dev/null \
    | openssl x509 -noout -dates -subject 2>/dev/null || true

# 4. Heartbleed probe (if testssl.sh available)
if command -v testssl.sh >/dev/null 2>&1; then
    echo "[tls] testssl.sh heartbleed check..."
    testssl.sh --heartbleed "${TARGET}:${PORT}" 2>/dev/null || true
fi

echo "[tls] Module complete."
