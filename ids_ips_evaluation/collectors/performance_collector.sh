#!/usr/bin/env bash
# collectors/performance_collector.sh
# Collects two snapshots:
#   1. Kali-side: CPU/RAM/NIC stats (local) — reflects attack tool load
#   2. Gateway-side: CPU/RAM stats via SSH — reflects Suricata inspection load
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config/lab.conf"

SESSION_ID="${SESSION_ID:-session_unknown}"
OUT="$LOG_DIR/${SESSION_ID}_perf.json"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── Kali-side metrics ─────────────────────────────────────────────────────────
KALI_CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | tr -d '%us,' || echo 0)
KALI_MEM_TOTAL=$(free -m | awk '/Mem:/{print $2}')
KALI_MEM_USED=$(free -m  | awk '/Mem:/{print $3}')
KALI_RX=$(cat "/sys/class/net/${KALI_IFACE}/statistics/rx_bytes" 2>/dev/null || echo 0)
KALI_TX=$(cat "/sys/class/net/${KALI_IFACE}/statistics/tx_bytes" 2>/dev/null || echo 0)

# ── Gateway-side metrics via SSH ──────────────────────────────────────────────
SSH="ssh $GW_SSH_OPTS -i $GW_SSH_KEY -p $GW_SSH_PORT ${GW_USER}@${GW_HOST}"
GW_CPU=0; GW_MEM_TOTAL=0; GW_MEM_USED=0

if $SSH "true" 2>/dev/null; then
    GW_CPU=$($SSH "top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | tr -d '%us,'" 2>/dev/null || echo 0)
    GW_MEM_TOTAL=$($SSH "free -m | awk '/Mem:/{print \$2}'" 2>/dev/null || echo 0)
    GW_MEM_USED=$($SSH  "free -m | awk '/Mem:/{print \$3}'" 2>/dev/null || echo 0)
    echo "[perf_collector] Gateway metrics collected via SSH"
else
    echo "[perf_collector] WARNING: Cannot SSH to gateway — gateway metrics unavailable"
fi

cat > "$OUT" << JSON
{
  "session":   "$SESSION_ID",
  "timestamp": "$TIMESTAMP",
  "kali": {
    "cpu_usage_pct": $KALI_CPU,
    "mem_total_mb":  $KALI_MEM_TOTAL,
    "mem_used_mb":   $KALI_MEM_USED,
    "iface":         "$KALI_IFACE",
    "rx_bytes":      $KALI_RX,
    "tx_bytes":      $KALI_TX
  },
  "gateway": {
    "host":          "$GW_HOST",
    "cpu_usage_pct": $GW_CPU,
    "mem_total_mb":  $GW_MEM_TOTAL,
    "mem_used_mb":   $GW_MEM_USED
  }
}
JSON
echo "[perf_collector] Performance snapshot → $OUT"
