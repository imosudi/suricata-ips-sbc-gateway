#!/usr/bin/env bash
# =============================================================================
# run_eval.sh — Suricata Rule Evaluation Harness (Kali LAN Client)
# =============================================================================
# Topology:
#   Gateway (Orange Pi)  : 10.10.10.1  — Suricata IDS/IPS inline (NFQUEUE)
#   Kali attacker (this) : 10.10.10.x  — runs all attack scenarios
#   Target LAN host      : 10.10.10.150
#   External target      : 93.184.216.34 (example.com) / DNS resolved
#
# Rule modules under test:
#   20_icmp.rules  — ICMP flood, timestamp request/reply
#   30_http.rules  — HTTP Big Bang Theory, example.com, SQLi, traversal, scanners
#   40_tls.rules   — TLS SNI + cert CN for example.{com,net,org}
#   50_telnet.rules — Telnet Big Bang Theory, session, login, password
#
# Directory layout (all relative to EVAL_ROOT):
#   attacks/    — individual attack scripts (sourced/called by this orchestrator)
#   analysers/  — pcap analysis helpers (tshark/tcpdump post-processors)
#   collectors/ — SSH-based evidence retrieval from gateway
#   config/     — gateway SSH credentials, IP config
#   logs/       — timestamped run logs
#   pcaps/      — libpcap captures per test
#   reports/    — human-readable markdown/HTML summary
#   results/    — per-test JSON pass/fail records
#   archive/    — compressed run bundles (auto-created after each run)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Paths ────────────────────────────────────────────────────────────────────
EVAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="${EVAL_ROOT}/attacks"
ANALYSERS_DIR="${EVAL_ROOT}/analysers"
COLLECTORS_DIR="${EVAL_ROOT}/collectors"
CONFIG_DIR="${EVAL_ROOT}/config"
LOGS_DIR="${EVAL_ROOT}/logs"
PCAPS_DIR="${EVAL_ROOT}/pcaps"
REPORTS_DIR="${EVAL_ROOT}/reports"
RESULTS_DIR="${EVAL_ROOT}/results"
ARCHIVE_DIR="${EVAL_ROOT}/archive"

# ── Run identity ─────────────────────────────────────────────────────────────
RUN_ID="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOGS_DIR}/run_${RUN_ID}.log"
RESULT_FILE="${RESULTS_DIR}/run_${RUN_ID}.json"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Source config ─────────────────────────────────────────────────────────────
# shellcheck source=config/eval.conf
source "${CONFIG_DIR}/eval.conf"

find_env_file() {
    local dir="${EVAL_ROOT}"
    while [[ "${dir}" != "/" ]]; do
        if [[ -f "${dir}/.env" ]]; then
            printf '%s' "${dir}/.env"
            return 0
        fi
        dir="$(dirname "${dir}")"
    done
    return 1
}

load_env_vars() {
    local env_file
    if env_file="$(find_env_file)" && [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
        if [[ -n "${ANSIBLE_USER:-}" ]]; then
            GW_USER="${ANSIBLE_USER}"
        else
            warn "ANSIBLE_USER not set in ${env_file}; using GW_USER from config"
        fi
    else
        warn ".env not found; using config defaults"
    fi
}

detect_iface_for_gateway() {
    local gw="$1" iface
    iface=$(ip route get "$gw" 2>/dev/null | awk '/dev/ {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')
    if [[ -n "${iface}" ]]; then
        echo "${iface}"
        return 0
    fi

    while IFS= read -r line; do
        local ifname ipaddr
        ifname=$(awk '{print $2}' <<< "${line}")
        ipaddr=$(awk '{print $4}' <<< "${line}")
        if python3 - <<'PYTHON'
import ipaddress,sys
print(ipaddress.IPv4Address(sys.argv[1]) in ipaddress.IPv4Network(sys.argv[2], strict=False))
PYTHON
            "${gw}" "${ipaddr}" 2>/dev/null | grep -qx 'True'; then
            echo "${ifname}"
            return 0
        fi
    done < <(ip -o -4 addr show | grep -Ev ' lo')
    return 1
}

initialise_runtime() {
    load_env_vars

    if [[ -z "${KALI_IFACE:-}" ]]; then
        KALI_IFACE="$(detect_iface_for_gateway "${GATEWAY_IP}" || true)"
        if [[ -n "${KALI_IFACE}" ]]; then
            log "Detected Kali interface: ${KALI_IFACE}"
        else
            warn "Could not auto-detect KALI_IFACE; falling back to eth0"
            KALI_IFACE="eth0"
        fi
    fi
}

# ── Logging ───────────────────────────────────────────────────────────────────
exec > >(tee -a "${LOG_FILE}") 2>&1

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} $*"; }
pass() { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
section() { echo -e "\n${BOLD}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}  $*${RESET}"; \
            echo -e "${BOLD}══════════════════════════════════════════${RESET}"; }

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    section "Dependency Check"
    local deps=(nmap hping3 curl wget ncat tshark tcpdump ssh jq python3)
    local missing=()
    for dep in "${deps[@]}"; do
        if command -v "$dep" &>/dev/null; then
            log "  ✓ $dep"
        else
            warn "  ✗ $dep — not found"
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing: ${missing[*]}"
        warn "Install with: apt-get install -y ${missing[*]}"
    fi
}

# ── JSON result helpers ────────────────────────────────────────────────────────
RESULTS_ARRAY="[]"

record_result() {
    # Usage: record_result <rule_module> <test_name> <pass|fail> <detail>
    local module="$1" test="$2" status="$3" detail="$4"
    local ts; ts="$(date -Iseconds)"
    local entry
    entry=$(jq -n \
        --arg ts     "$ts"     \
        --arg mod    "$module" \
        --arg test   "$test"   \
        --arg status "$status" \
        --arg detail "$detail" \
        '{timestamp:$ts, module:$mod, test:$test, status:$status, detail:$detail}')
    RESULTS_ARRAY=$(echo "$RESULTS_ARRAY" | jq --argjson e "$entry" '. + [$e]')
    if [[ "$status" == "pass" ]]; then pass "$module | $test — $detail"
    else                               fail "$module | $test — $detail"; fi
}

flush_results() {
    echo "$RESULTS_ARRAY" | jq '.' > "$RESULT_FILE"
    log "Results saved → ${RESULT_FILE}"
}

# ── PCAP capture helpers ───────────────────────────────────────────────────────
CAPTURE_PID=""

start_capture() {
    local tag="$1" iface="${2:-${KALI_IFACE}}"
    local pcap="${PCAPS_DIR}/${RUN_ID}_${tag}.pcap"
    tcpdump -i "$iface" -w "$pcap" -q &
    CAPTURE_PID=$!
    log "Capture started (PID ${CAPTURE_PID}) → ${pcap}"
    echo "$pcap"
}

stop_capture() {
    if [[ -n "$CAPTURE_PID" ]]; then
        kill "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
        CAPTURE_PID=""
        sleep 1
    fi
}

# ── SSH evidence collector ────────────────────────────────────────────────────
collect_alerts() {
    # Pull Suricata fast.log lines from gateway that appeared in the last $1 seconds
    local since="${1:-30}" tag="${2:-generic}"
    log "Collecting gateway alerts (last ${since}s) …"
    ssh -i "${GW_SSH_KEY}" -o StrictHostKeyChecking=no \
        "${GW_USER}@${GATEWAY_IP}" \
        "sudo tail -n 200 /var/log/suricata/fast.log | grep -F '[**]' | tail -50" \
        > "${RESULTS_DIR}/${RUN_ID}_alerts_${tag}.txt" 2>/dev/null || \
        warn "Could not retrieve alerts for ${tag}"
}

# ── Run sub-scripts ───────────────────────────────────────────────────────────
run_attack() {
    local script="${ATTACKS_DIR}/$1"
    if [[ -x "$script" ]]; then
        log "Running attack: $1"
        # Pass shared context via env
        RUN_ID="$RUN_ID" PCAPS_DIR="$PCAPS_DIR" RESULTS_DIR="$RESULTS_DIR" \
        GATEWAY_IP="$GATEWAY_IP" TARGET_IP="$TARGET_IP" \
        EXTERNAL_IP="$EXTERNAL_IP" KALI_IFACE="$KALI_IFACE" \
        bash "$script"
    else
        warn "Attack script not found or not executable: $script"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    initialise_runtime
    section "Suricata Eval Harness — Run ${RUN_ID}"
    log "Gateway : ${GATEWAY_IP}"
    log "Target  : ${TARGET_IP}"
    log "External: ${EXTERNAL_IP}"

    check_deps

    # ── Module 20: ICMP ───────────────────────────────────────────────────────
    section "Module 20 — ICMP Detection"
    run_attack "20_icmp_timestamp.sh"
    run_attack "20_icmp_flood.sh"
    collect_alerts 30 "20_icmp"

    # ── Module 30: HTTP ───────────────────────────────────────────────────────
    section "Module 30 — HTTP Detection"
    run_attack "30_http_example_host.sh"
    run_attack "30_http_bigbang.sh"
    run_attack "30_http_sqli.sh"
    run_attack "30_http_traversal.sh"
    run_attack "30_http_scanners.sh"
    collect_alerts 30 "30_http"

    # ── Module 40: TLS ────────────────────────────────────────────────────────
    section "Module 40 — TLS/SNI Detection"
    run_attack "40_tls_sni.sh"
    run_attack "40_tls_deprecated.sh"
    collect_alerts 30 "40_tls"

    # ── Module 50: Telnet ─────────────────────────────────────────────────────
    section "Module 50 — Telnet Detection"
    run_attack "50_telnet_bigbang.sh"
    run_attack "50_telnet_session.sh"
    collect_alerts 30 "50_telnet"

    # ── Analyse PCAPs ─────────────────────────────────────────────────────────
    section "PCAP Analysis"
    bash "${ANALYSERS_DIR}/analyse_pcaps.sh" "${PCAPS_DIR}" "${RUN_ID}" "${RESULTS_DIR}"

    # ── Generate report ───────────────────────────────────────────────────────
    section "Report Generation"
    flush_results
    python3 "${REPORTS_DIR}/generate_report.py" \
        --results "${RESULT_FILE}" \
        --alerts-dir "${RESULTS_DIR}" \
        --run-id "${RUN_ID}" \
        --output "${REPORTS_DIR}/report_${RUN_ID}.html"

    # ── Archive ───────────────────────────────────────────────────────────────
    section "Archiving Run"
    bash "${EVAL_ROOT}/archive/archive_run.sh" "${RUN_ID}"

    section "Complete — Run ${RUN_ID}"
    log "Log    : ${LOG_FILE}"
    log "Results: ${RESULT_FILE}"
    log "Report : ${REPORTS_DIR}/report_${RUN_ID}.html"
    log "Archive: ${ARCHIVE_DIR}/run_${RUN_ID}.tar.gz"
}

main "$@"
