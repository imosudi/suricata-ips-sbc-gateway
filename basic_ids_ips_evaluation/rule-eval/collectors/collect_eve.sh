#!/usr/bin/env bash
# collectors/collect_eve.sh
# Pulls Suricata eve.json entries from the gateway via SSH,
# filters by SID range 9000001–9009999 (custom lab rules),
# and saves structured JSON per run.
# Usage: collect_eve.sh <run_id> <tag>
# =============================================================================
source "$(dirname "$0")/../config/eval.conf"

RUN_ID="${1:?RUN_ID required}"
TAG="${2:-generic}"
OUT_DIR="$(dirname "$0")/../results"
OUT_FILE="${OUT_DIR}/${RUN_ID}_eve_${TAG}.json"

echo "[collector] Fetching eve.json from ${GW_USER}@${GATEWAY_IP} …"

ssh -i "${GW_SSH_KEY}" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    "${GW_USER}@${GATEWAY_IP}" \
    "sudo cat ${GW_EVE_LOG} 2>/dev/null | \
     python3 -c \"
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            sid = e.get('alert', {}).get('signature_id', 0)
            if 9000001 <= sid <= 9009999:
                print(json.dumps(e))
    except Exception:
        pass
\" " > "${OUT_FILE}" 2>/dev/null

COUNT=$(wc -l < "${OUT_FILE}" 2>/dev/null || echo 0)
echo "[collector] ${COUNT} custom-rule alert(s) saved → ${OUT_FILE}"

# Also save fast.log snippet for quick reading
FAST_OUT="${OUT_DIR}/${RUN_ID}_fast_${TAG}.txt"
ssh -i "${GW_SSH_KEY}" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    "${GW_USER}@${GATEWAY_IP}" \
    "sudo grep -E '\[9[0-9]{6}\]' ${GW_FAST_LOG} 2>/dev/null | tail -100" \
    > "${FAST_OUT}" 2>/dev/null

echo "[collector] fast.log snippet → ${FAST_OUT}"
