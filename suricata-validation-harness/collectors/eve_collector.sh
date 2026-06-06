#!/usr/bin/env bash
# collectors/eve_collector.sh
# Pull EVE JSON from the remote Suricata gateway via SSH.
# Runs ON KALI — no local Suricata files are accessed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config/lab.conf"

SESSION_ID="${SESSION_ID:-session_unknown}"
OUT="$LOG_DIR/${SESSION_ID}_eve.json"
mkdir -p "$LOG_DIR"

SSH="ssh $GW_SSH_OPTS -i $GW_SSH_KEY -p $GW_SSH_PORT ${GW_USER}@${GW_HOST}"

echo "[eve_collector] Pulling remote EVE log from ${GW_USER}@${GW_HOST}:${GW_EVE_LOG}"

# Verify gateway is reachable
if ! $SSH "test -f '$GW_EVE_LOG'" 2>/dev/null; then
    echo "[eve_collector] ERROR: Remote EVE log not found or SSH failed: $GW_EVE_LOG"
    echo "[eve_collector] Check GW_HOST, GW_USER, GW_SSH_KEY in lab.conf"
    exit 1
fi

# Record a pre-session marker timestamp on the gateway so we only pull
# events generated after attacks began (if SESSION_START_EPOCH is set)
if [[ -n "${SESSION_START_EPOCH:-}" ]]; then
    # Pull only lines with timestamp >= session start (ISO8601 prefix match)
    SESSION_DATE=$(date -u -d "@$SESSION_START_EPOCH" +"%Y-%m-%dT%H" 2>/dev/null \
               || date -u -r "$SESSION_START_EPOCH" +"%Y-%m-%dT%H" 2>/dev/null \
               || echo "")
    if [[ -n "$SESSION_DATE" ]]; then
        $SSH "grep -a '${SESSION_DATE}' '$GW_EVE_LOG' | tail -n $EVE_TAIL_LINES" > "$OUT" 2>/dev/null || true
    fi
fi

# Fallback: pull last N lines
if [[ ! -s "$OUT" ]]; then
    $SSH "tail -n $EVE_TAIL_LINES '$GW_EVE_LOG'" > "$OUT"
fi

LINES=$(wc -l < "$OUT")
echo "[eve_collector] Collected $LINES EVE lines → $OUT"
