#!/usr/bin/env bash
# collectors/environment_collector.sh
# Records the lab environment from BOTH sides:
#   Kali: tool versions, kernel, Kali release
#   Gateway: Suricata version, rules count, kernel — all via SSH
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config/lab.conf"

SESSION_ID="${SESSION_ID:-session_unknown}"
OUT="$LOG_DIR/${SESSION_ID}_environment.json"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ── Kali side ─────────────────────────────────────────────────────────────────
KALI_HOSTNAME=$(hostname)
KALI_KERNEL=$(uname -r)
KALI_RELEASE=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
NMAP_VER=$(nmap --version 2>/dev/null | head -1 | awk '{print $3}' || echo "not found")
HPING_VER=$(hping3 --version 2>/dev/null | head -1 || echo "not found")
HYDRA_VER=$(hydra -h 2>&1 | head -1 | awk '{print $2}' || echo "not found")
METASPLOIT_VER=$(msfconsole --version 2>/dev/null | head -1 || echo "not found")

# ── Gateway side via SSH ──────────────────────────────────────────────────────
SSH="ssh $GW_SSH_OPTS -i $GW_SSH_KEY -p $GW_SSH_PORT ${GW_USER}@${GW_HOST}"

GW_SURICATA_VER="unknown"; GW_KERNEL="unknown"; GW_HOSTNAME="unknown"
GW_RULES_COUNT=0; GW_IDS_MODE="unknown"

if $SSH "true" 2>/dev/null; then
    GW_SURICATA_VER=$($SSH "suricata --build-info 2>/dev/null | grep 'Suricata version' | awk '{print \$3}'" || echo "unknown")
    GW_KERNEL=$($SSH "uname -r" 2>/dev/null || echo "unknown")
    GW_HOSTNAME=$($SSH "hostname" 2>/dev/null || echo "unknown")
    GW_RULES_COUNT=$($SSH "find '${GW_SURICATA_RULES_DIR}' -name '*.rules' \
        -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print \$1}'" || echo 0)
    GW_IDS_MODE=$($SSH "grep -E '^#?[[:space:]]*(runmode|detect-engine)' \
        /etc/suricata/suricata.yaml 2>/dev/null | head -2 | tr '\n' ';'" || echo "unknown")
    echo "[env_collector] Gateway info collected via SSH"
else
    echo "[env_collector] WARNING: Cannot SSH to gateway — gateway info unavailable"
fi

cat > "$OUT" << JSON
{
  "session":   "$SESSION_ID",
  "timestamp": "$TIMESTAMP",
  "kali": {
    "hostname":       "$KALI_HOSTNAME",
    "kernel":         "$KALI_KERNEL",
    "os_release":     "$KALI_RELEASE",
    "tools": {
      "nmap":         "$NMAP_VER",
      "hping3":       "$HPING_VER",
      "hydra":        "$HYDRA_VER",
      "metasploit":   "$METASPLOIT_VER"
    }
  },
  "gateway": {
    "host":             "$GW_HOST",
    "hostname":         "$GW_HOSTNAME",
    "kernel":           "$GW_KERNEL",
    "suricata_version": "$GW_SURICATA_VER",
    "rules_count":      $GW_RULES_COUNT,
    "mode_config":      "$GW_IDS_MODE",
    "suricata_mode":    "$SURICATA_MODE"
  }
}
JSON
echo "[env_collector] Environment snapshot → $OUT"
