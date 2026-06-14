#!/usr/bin/env bash
# archive/archive_run.sh
# Bundles all artefacts from a completed run into a timestamped .tar.gz
# Usage: archive_run.sh <run_id>
# =============================================================================
RUN_ID="${1:?RUN_ID required}"
EVAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCHIVE_DIR="${EVAL_ROOT}/archive"

mkdir -p "${ARCHIVE_DIR}"

BUNDLE="${ARCHIVE_DIR}/run_${RUN_ID}.tar.gz"

echo "[archive] Bundling run ${RUN_ID} …"

tar -czf "${BUNDLE}" \
    -C "${EVAL_ROOT}" \
    --transform "s|^|run_${RUN_ID}/|" \
    $(find logs pcaps results reports -maxdepth 1 \
        -name "*${RUN_ID}*" 2>/dev/null | sort)

SIZE=$(du -sh "${BUNDLE}" | cut -f1)
echo "[archive] Bundle created: ${BUNDLE} (${SIZE})"

# Prune bundles older than 30 days
find "${ARCHIVE_DIR}" -name "run_*.tar.gz" -mtime +30 -delete
echo "[archive] Old bundles pruned (>30 days)"
