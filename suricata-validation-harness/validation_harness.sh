#!/usr/bin/env bash
# =============================================================================
# validation_harness.sh — Suricata Validation Harness (Kali attacker edition)
#
# DEPLOYMENT MODEL:
#   This script runs ON KALI LINUX and attacks a REMOTE target network.
#   The Suricata gateway is a separate host. All EVE/stats/PCAP collection
#   is performed via SSH/SCP from Kali to the gateway after attacks complete.
#
#   Kali (attacker) ──attacks──► victim hosts ──transit──► Suricata gateway
#                   ◄──SSH/SCP── (eve.json, stats, pcap) ◄── gateway
# =============================================================================
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HARNESS_DIR/config"
source "$CONFIG_DIR/lab.conf"       # sets LOG_DIR, RESULTS_DIR, PCAP_DIR, etc.

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SESSION_ID="session_${TIMESTAMP}"
SESSION_LOG="$LOG_DIR/${SESSION_ID}.log"
SESSION_START_EPOCH=$(date +%s)
export SESSION_ID SESSION_START_EPOCH

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} $*" | tee -a "$SESSION_LOG"; }
info() { echo -e "${GREEN}[INFO]${RESET}  $*" | tee -a "$SESSION_LOG"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*" | tee -a "$SESSION_LOG"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$SESSION_LOG" >&2; }
die()  { err "$*"; exit 1; }

# ── usage ─────────────────────────────────────────────────────────────────────
usage() {
    cat <<USAGE
${BOLD}Suricata Validation Harness — Kali Attacker Edition${RESET}

  Runs on Kali Linux. Launches structured attacks toward the victim network
  monitored by a remote Suricata gateway, then collects evidence from the
  gateway via SSH/SCP for scoring and reporting.

Usage: $(basename "$0") [OPTIONS] [ATTACK_MODULES...]

Connection options:
  --gw-host    IP       Gateway IP (overrides lab.conf GW_HOST)
  --gw-user    USER     Gateway SSH user (overrides GW_USER)
  --gw-key     PATH     SSH identity file (overrides GW_SSH_KEY)
  --target     IP       Primary victim IP (overrides targets.conf)

Run options:
  -m, --mode   ids|ips  Suricata mode on gateway (for scoring, default: ids)
  -p, --profile NAME    Attack profile: light|full|aggressive (default: full)
  -r, --report FORMAT   html|csv|both (default: html)
  -d, --duration SECS   Per-attack step duration (default: 5)
  -s, --skip   MOD,...  Comma-separated modules to skip
  -c, --collect-only    Pull evidence from gateway without running attacks
  -a, --archive         Compress session results after run
  -v, --verbose         Verbose output
  -h, --help            This help

Attack modules (default: all):
  icmp  scan  dns  ssh  http  tls  ftp  smtp  policy  benign

Examples:
  # Full suite against default targets
  sudo ./validation_harness.sh

  # Override gateway and target on the command line
  sudo ./validation_harness.sh --gw-host 192.168.56.1 --target 192.168.56.10

  # IPS mode, aggressive profile, archive results
  sudo ./validation_harness.sh -m ips -p aggressive -a

  # Only pull & analyse previous attack evidence (no new attacks)
  ./validation_harness.sh --collect-only
USAGE
}

# ── argument parsing ──────────────────────────────────────────────────────────
MODE="${SURICATA_MODE:-ids}"
PROFILE="full"
REPORT_FORMAT="html"
DURATION="${ATTACK_DURATION:-5}"
SKIP_MODULES=""
COLLECT_ONLY=false
DO_ARCHIVE=false
VERBOSE=false
SELECTED_MODULES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gw-host)      GW_HOST="$2";       shift 2 ;;
        --gw-user)      GW_USER="$2";       shift 2 ;;
        --gw-key)       GW_SSH_KEY="$2";    shift 2 ;;
        --target)       PRIMARY_TARGET="$2"; shift 2 ;;
        -m|--mode)      MODE="$2";          shift 2 ;;
        -p|--profile)   PROFILE="$2";       shift 2 ;;
        -r|--report)    REPORT_FORMAT="$2"; shift 2 ;;
        -d|--duration)  DURATION="$2";      shift 2 ;;
        -s|--skip)      SKIP_MODULES="$2";  shift 2 ;;
        -c|--collect-only) COLLECT_ONLY=true; shift ;;
        -a|--archive)   DO_ARCHIVE=true;    shift ;;
        -v|--verbose)   VERBOSE=true;       shift ;;
        -h|--help)      usage; exit 0 ;;
        icmp|scan|dns|ssh|http|tls|ftp|smtp|policy|benign)
                        SELECTED_MODULES+=("$1"); shift ;;
        *)              die "Unknown option: $1 — run with --help" ;;
    esac
done
[[ ${#SELECTED_MODULES[@]} -eq 0 ]] && \
    SELECTED_MODULES=(icmp scan dns ssh http tls ftp smtp policy benign)

export TARGET="$PRIMARY_TARGET" MODE DURATION VERBOSE
export GW_HOST GW_USER GW_SSH_KEY

# ── SSH helper ────────────────────────────────────────────────────────────────
SSH_CMD="ssh $GW_SSH_OPTS -i $GW_SSH_KEY -p ${GW_SSH_PORT:-22} ${GW_USER}@${GW_HOST}"

gw_ssh() { $SSH_CMD "$@"; }

# ── pre-flight checks ─────────────────────────────────────────────────────────
preflight() {
    log "Running pre-flight checks..."

    # Kali tools
    command -v nmap    >/dev/null 2>&1 || warn "nmap not found — scan module degraded"
    command -v hping3  >/dev/null 2>&1 || warn "hping3 not found — icmp module degraded"
    command -v hydra   >/dev/null 2>&1 || warn "hydra not found — ssh/ftp brute disabled"
    command -v python3 >/dev/null 2>&1 || die  "python3 is required for analyzers"
    command -v tcpdump >/dev/null 2>&1 || warn "tcpdump not found — local PCAP disabled"

    # Exclusion guard
    for excl in $(echo "${EXCLUDED_HOSTS:-}" | tr ',' ' '); do
        [[ "$PRIMARY_TARGET" == "$excl" ]] && \
            die "PRIMARY_TARGET $PRIMARY_TARGET is in EXCLUDED_HOSTS — aborting"
        [[ "${GW_HOST}" == "$excl" ]] && \
            die "GW_HOST $GW_HOST is in EXCLUDED_HOSTS — aborting"
    done

    # SSH connectivity to gateway
    info "Testing SSH connectivity to gateway ${GW_HOST}..."
    if gw_ssh "true" 2>/dev/null; then
        info "Gateway SSH: OK ✓"
    else
        warn "Cannot SSH to ${GW_USER}@${GW_HOST} — collection will fail"
        warn "Check GW_HOST, GW_USER, GW_SSH_KEY in config/lab.conf"
        [[ "${COLLECT_ONLY}" == true ]] && die "Collection mode requires gateway SSH"
    fi

    # Verify remote EVE log exists
    if gw_ssh "test -f '$GW_EVE_LOG'" 2>/dev/null; then
        info "Remote EVE log found: $GW_EVE_LOG ✓"
    else
        warn "Remote EVE log not found at $GW_EVE_LOG — check suricata.yaml on gateway"
    fi

    # Network reachability of victim
    if ! $COLLECT_ONLY; then
        if ping -c 1 -W 2 "$PRIMARY_TARGET" >/dev/null 2>&1; then
            info "Victim $PRIMARY_TARGET is reachable ✓"
        else
            warn "Cannot ping $PRIMARY_TARGET — attacks may still work (ICMP may be blocked)"
        fi
    fi

    info "Session: $SESSION_ID"
    info "Gateway: ${GW_USER}@${GW_HOST}  |  Victim: $PRIMARY_TARGET"
    info "Mode: $MODE  |  Profile: $PROFILE  |  Duration: ${DURATION}s/module"
}

# ── module runner ─────────────────────────────────────────────────────────────
run_module() {
    local module="$1"
    local script="$HARNESS_DIR/attacks/${module}.sh"

    if echo ",$SKIP_MODULES," | grep -q ",${module},"; then
        warn "Skipping module: $module"
        return 0
    fi

    [[ -x "$script" ]] || { warn "Not executable: $script — skipping"; return 1; }

    log "▶  Attack module: ${BOLD}${module}${RESET}  (target: $PRIMARY_TARGET)"
    local t0=$SECONDS

    TARGET="$PRIMARY_TARGET" MODE="$MODE" DURATION="$DURATION" \
    VERBOSE="$VERBOSE" PROFILE="$PROFILE" \
        bash "$script" 2>&1 | tee -a "$SESSION_LOG" || \
        warn "Module $module exited non-zero (partial results expected)"

    info "Module ${module} done in $(( SECONDS - t0 ))s"
}

# ── collector runner ──────────────────────────────────────────────────────────
run_collectors() {
    # Start PCAP before attacks (called early in main), stop it here
    local stop_pcap="${HARNESS_DIR}/collectors/pcap_stop.sh"

    log "Stopping local PCAP capture..."
    [[ -x "$stop_pcap" ]] && \
        SESSION_ID="$SESSION_ID" bash "$stop_pcap" 2>&1 | tee -a "$SESSION_LOG" || true

    # Wait for in-flight packets / Suricata processing
    log "Waiting ${EVE_COLLECTION_DELAY:-3}s for Suricata to process traffic..."
    sleep "${EVE_COLLECTION_DELAY:-3}"

    log "Running remote collectors (SSH → ${GW_HOST})..."
    for col in eve_collector stats_collector performance_collector environment_collector; do
        local cs="$HARNESS_DIR/collectors/${col}.sh"
        [[ -x "$cs" ]] || { warn "Collector not executable: $cs"; continue; }
        SESSION_ID="$SESSION_ID" LOG_DIR="$LOG_DIR" PCAP_DIR="$PCAP_DIR" \
            bash "$cs" 2>&1 | tee -a "$SESSION_LOG" || warn "$col failed"
    done

    # Remote PCAP fetch (separate, as it may be large)
    local pcap_fetch="$HARNESS_DIR/collectors/pcap_collector.sh"
    [[ -x "$pcap_fetch" ]] && \
        SESSION_ID="$SESSION_ID" LOG_DIR="$LOG_DIR" PCAP_DIR="$PCAP_DIR" \
        bash "$pcap_fetch" 2>&1 | tee -a "$SESSION_LOG" || true
}

# ── analyzers ─────────────────────────────────────────────────────────────────
run_analyzers() {
    log "Running analyzers..."
    local ad="$HARNESS_DIR/analyzers"
    local rd="$RESULTS_DIR"

    python3 "$ad/detection_score.py"   --session "$SESSION_ID" --out "$rd"
    python3 "$ad/ips_score.py"         --session "$SESSION_ID" --out "$rd"
    python3 "$ad/latency_score.py"     --session "$SESSION_ID" --out "$rd"
    python3 "$ad/throughput_score.py"  --session "$SESSION_ID" --out "$rd"
    python3 "$ad/false_positive.py"    --session "$SESSION_ID" --out "$rd"
    python3 "$ad/grading.py"           --session "$SESSION_ID" \
            --scoring-conf "$CONFIG_DIR/scoring.conf" --out "$rd"
    python3 "$ad/sid_mapper.py"        --session "$SESSION_ID" \
            --rule-map "$CONFIG_DIR/rule_mapping.yaml"

    info "Analysis complete → $rd/${SESSION_ID}_results.json"
}

# ── reports ───────────────────────────────────────────────────────────────────
generate_reports() {
    log "Generating $REPORT_FORMAT report(s)..."
    local rdir="$HARNESS_DIR/reports"
    local results_json="$RESULTS_DIR/${SESSION_ID}_results.json"

    [[ -f "$results_json" ]] || { warn "No results JSON — skipping reports"; return; }

    case "$REPORT_FORMAT" in
        html) python3 "$rdir/html_report.py" --input "$results_json" --out "$RESULTS_DIR" ;;
        csv)  python3 "$rdir/csv_report.py"  --input "$results_json" --out "$RESULTS_DIR" ;;
        both)
            python3 "$rdir/html_report.py" --input "$results_json" --out "$RESULTS_DIR"
            python3 "$rdir/csv_report.py"  --input "$results_json" --out "$RESULTS_DIR"
            ;;
        *) die "Unknown report format: $REPORT_FORMAT" ;;
    esac
    python3 "$rdir/report_generator.py" --session "$SESSION_ID" --out "$RESULTS_DIR"
}

# ── archive ───────────────────────────────────────────────────────────────────
archive_session() {
    log "Archiving session $SESSION_ID..."
    local arc="$ARCHIVE_DIR/${SESSION_ID}.tar.gz"
    mkdir -p "$ARCHIVE_DIR"
    tar czf "$arc" -C "$HARNESS_DIR" \
        $(find results logs pcaps -maxdepth 1 -name "${SESSION_ID}*" 2>/dev/null) \
        2>/dev/null || true
    info "Archived → $arc"
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    mkdir -p "$LOG_DIR" "$RESULTS_DIR" "$PCAP_DIR" "$ARCHIVE_DIR"

    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   Suricata Validation Harness — Kali Edition  v1.1  ║"
    echo "║   Attacker: $(hostname -s)$(printf '%*s' $((38 - ${#$(hostname -s)})) '')║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    preflight

    if $COLLECT_ONLY; then
        log "Collect-only mode — skipping attacks"
        run_collectors
    else
        # Start local PCAP before first attack
        if [[ "${PCAP_ENABLED:-true}" == "true" ]]; then
            log "Starting local PCAP capture..."
            SESSION_ID="$SESSION_ID" LOG_DIR="$LOG_DIR" PCAP_DIR="$PCAP_DIR" \
                bash "$HARNESS_DIR/collectors/pcap_collector.sh" \
                2>&1 | tee -a "$SESSION_LOG" &
            sleep 1   # give tcpdump a moment to start
        fi

        for module in "${SELECTED_MODULES[@]}"; do
            run_module "$module"
            sleep "${INTER_ATTACK_SLEEP:-2}"
        done

        run_collectors    # stop PCAP, fetch EVE/stats from gateway
    fi

    run_analyzers
    generate_reports
    $DO_ARCHIVE && archive_session

    echo ""
    info "${GREEN}${BOLD}Session complete: $SESSION_ID${RESET}"
    info "Results → $RESULTS_DIR/"
    info "Log     → $SESSION_LOG"
}

main "$@"
