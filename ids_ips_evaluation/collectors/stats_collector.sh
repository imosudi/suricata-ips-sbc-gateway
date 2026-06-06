#!/usr/bin/env bash
# collectors/stats_collector.sh
# Query Suricata stats from remote gateway via SSH.
# Uses suricatasc over the Unix socket (if the SSH user has access),
# with a fallback to tailing the remote stats.log.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config/lab.conf"

SESSION_ID="${SESSION_ID:-session_unknown}"
OUT="$LOG_DIR/${SESSION_ID}_stats.json"
mkdir -p "$LOG_DIR"

SSH="ssh $GW_SSH_OPTS -i $GW_SSH_KEY -p $GW_SSH_PORT ${GW_USER}@${GW_HOST}"

echo "[stats_collector] Querying Suricata stats on ${GW_HOST}..."

# Attempt 1: suricatasc dump-counters (JSON output)
if $SSH "command -v suricatasc >/dev/null 2>&1 && \
         test -S '$GW_SURICATA_SOCKET'" 2>/dev/null; then
    $SSH "suricatasc -c dump-counters 2>/dev/null" > "$OUT" && {
        echo "[stats_collector] Got stats via suricatasc → $OUT"
        exit 0
    }
fi

# Attempt 2: tail remote stats.log, wrap in minimal JSON
echo "[stats_collector] Falling back to remote stats.log tail..."
RAW=$($SSH "tail -n 80 '$GW_STATS_LOG' 2>/dev/null" || echo "")
if [[ -n "$RAW" ]]; then
    printf '{"source":"stats.log","session":"%s","raw":%s}\n' \
        "$SESSION_ID" "$(echo "$RAW" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))")" \
        > "$OUT"
    echo "[stats_collector] Stats saved → $OUT"
else
    echo "[stats_collector] WARNING: Could not retrieve stats from gateway"
    echo '{"source":"none","error":"unreachable or no log"}' > "$OUT"
fi
