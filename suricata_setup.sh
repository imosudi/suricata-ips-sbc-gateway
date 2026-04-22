#!/usr/bin/env bash
# =============================================================================
# Suricata IPS Setup Script
# Orange Pi 5 / Ubuntu 24.04 LTS - NFQueue Inline Mode
# Mosudi I.O, FH Technikum Wien - IT Security Lab 2026
#
# Prerequisites:
#   - gateway_setup.sh must have been run successfully first
#   - eth0 = LAN (10.10.10.1/24), wlan0 = WAN
#
# Usage:
#   chmod +x suricata_setup.sh
#   sudo ./suricata_setup.sh
# What this script does:
#   1. Installs Suricata with NFQueue (inline IPS) support
#   2. Prepares runtime environment (log directories, permissions)
#   3. Configures suricata.yaml for:
#        - HOME_NET (LAN scope)
#        - NFQUEUE inline mode
#        - Disabling AF_PACKET capture
#        - Enabling local.rules inclusion
#   4. Creates rule directory and initial local.rules file
#   5. Configures iptables to redirect forwarded traffic to NFQUEUE
#   6. Sets up systemd override to run Suricata in NFQueue mode
#   7. Starts and enables Suricata as a system service
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
WAN_IFACE="wlan0"
LAN_IFACE="eth0"
LAN_SUBNET="10.10.10.0/24"
NFQUEUE_NUM=0

SURICATA_YAML="/etc/suricata/suricata.yaml"
SURICATA_YAML_BAK="/etc/suricata/suricata.yaml.bak"
SURICATA_LOG_DIR="/var/log/suricata"
SURICATA_RULES_DIR="/etc/suricata/rules"
LOCAL_RULES="${SURICATA_RULES_DIR}/local.rules"
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/suricata.service.d"
SYSTEMD_OVERRIDE="${SYSTEMD_OVERRIDE_DIR}/override.conf"
SURICATA_LOG="${SURICATA_LOG_DIR}/suricata.log"

# ── COLOUR OUTPUT ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_section() {
    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${BLUE}  $1${RESET}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}"
}
log_step()    { echo -e "${CYAN}  ▶  $1${RESET}"; }
log_ok()      { echo -e "${GREEN}  ✓  $1${RESET}"; }
log_warn()    { echo -e "${YELLOW}  ⚠  $1${RESET}"; }
log_err()     { echo -e "${RED}  ✗  $1${RESET}" >&2; }
log_info()    { echo -e "      $1"; }
log_output()  { echo -e "${YELLOW}      $1${RESET}"; }

# ── PRE-FLIGHT CHECKS ─────────────────────────────────────────────────────────
preflight_checks() {
    log_section "Pre-flight Checks"

    [[ $EUID -ne 0 ]] && { log_err "Run as root: sudo ./suricata_setup.sh"; exit 1; }
    log_ok "Running as root"

    # Require gateway to be configured first
    if ! sysctl -n net.ipv4.ip_forward | grep -q "^1$"; then
        log_err "IP forwarding is not enabled. Run gateway_setup.sh first."
        exit 1
    fi
    log_ok "IP forwarding is enabled (gateway_setup.sh prerequisite met)"

    ip link show "$LAN_IFACE" &>/dev/null \
        || { log_err "LAN interface $LAN_IFACE not found"; exit 1; }
    log_ok "LAN interface $LAN_IFACE present"

    ip link show "$WAN_IFACE" &>/dev/null \
        || log_warn "WAN interface $WAN_IFACE not found - NAT rule will still be applied"
    log_ok "Pre-flight checks passed"
}

# ── STEP 1: INSTALL SURICATA ──────────────────────────────────────────────────
install_suricata() {
    log_section "Step 1 - Suricata Installation"

    log_step "Updating package lists..."
    apt-get update -q
    log_ok "Package lists updated"

    log_step "Installing Suricata..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q suricata
    log_ok "Suricata installed"

    log_step "Verifying installed version..."
    VERSION=$(suricata -V 2>&1 | head -1)
    log_ok "$VERSION"

    log_step "Verifying NFQueue support..."
    NFQ_LINE=$(suricata --build-info 2>&1 | grep -i "NFQueue support")
    log_info "$NFQ_LINE"
    if echo "$NFQ_LINE" | grep -q "yes"; then
        log_ok "NFQueue support confirmed"
    else
        log_err "NFQueue support NOT found in build. Cannot run in inline IPS mode."
        log_err "Install suricata from the OISF PPA for a build with NFQ support:"
        log_err "  add-apt-repository ppa:oisf/suricata-stable && apt install suricata"
        exit 1
    fi
}

# ── STEP 2: LOG DIRECTORY ─────────────────────────────────────────────────────
configure_log_dir() {
    log_section "Step 2 - Runtime Environment"

    log_step "Creating Suricata log directory..."
    mkdir -p "$SURICATA_LOG_DIR"
    # Use root:root - the suricata user does not exist in all package builds
    chown root:root "$SURICATA_LOG_DIR"
    chmod 750 "$SURICATA_LOG_DIR"
    log_ok "Log directory: $SURICATA_LOG_DIR  (750, root:root)"
}

# ── STEP 3: CONFIGURE suricata.yaml ───────────────────────────────────────────
configure_yaml() {
    log_section "Step 3 - suricata.yaml Configuration"

    # ── 3a: Backup ───────────────────────────────────────────────────────────
    log_step "Backing up original configuration..."
    if [[ ! -f "$SURICATA_YAML_BAK" ]]; then
        cp "$SURICATA_YAML" "$SURICATA_YAML_BAK"
        log_ok "Backup saved to $SURICATA_YAML_BAK"
    else
        log_ok "Backup already exists at $SURICATA_YAML_BAK - skipping"
    fi

    # ── 3b: HOME_NET ─────────────────────────────────────────────────────────
    log_step "Setting HOME_NET to [$LAN_SUBNET]..."
    # The default value is typically [192.168.0.0/16,10.0.0.0/8,...] on one line
    # Replace the entire HOME_NET line with a single precise entry
    if grep -q "^\s*HOME_NET:" "$SURICATA_YAML"; then
        sed -i "s|^\s*HOME_NET:.*|HOME_NET: \"[$LAN_SUBNET]\"|" "$SURICATA_YAML"
        log_ok "HOME_NET set to \"[$LAN_SUBNET]\""
    else
        log_err "HOME_NET key not found in $SURICATA_YAML"
        exit 1
    fi

    # ── 3c: NFQ mode ─────────────────────────────────────────────────────────
    log_step "Configuring NFQ mode block..."
    # Strategy: locate the nfq: key and replace the entire block using Python,
    # which handles YAML indentation reliably without a full YAML parser.
    python3 - "$SURICATA_YAML" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    text = f.read()

# Replace the nfq: block - match from "nfq:" up to the next top-level key
nfq_block = (
    "nfq:\n"
    "  mode: accept\n"
    "  repeat-mark: 1\n"
    "  repeat-mask: 1\n"
    "  bypass: yes\n"
)
# Match existing nfq block (key + indented lines that follow)
text = re.sub(
    r'^nfq:.*?(?=^\S)',
    nfq_block,
    text,
    flags=re.MULTILINE | re.DOTALL
)
with open(path, 'w') as f:
    f.write(text)
print("  nfq block updated")
PYEOF
    log_ok "NFQ block: mode=accept, repeat-mark=1, repeat-mask=1, bypass=yes"

    # ── 3d: Disable AF_PACKET default interface ───────────────────────────────
    log_step "Disabling AF_PACKET default interface entry..."
    # Comment out any active "interface: default" or "interface: eth0" line
    # inside the af-packet block so it does not conflict with NFQ mode
    python3 - "$SURICATA_YAML" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

in_afpacket = False
out = []
for line in lines:
    stripped = line.lstrip()
    if re.match(r'^af-packet:', line):
        in_afpacket = True
    elif re.match(r'^\S', line) and not re.match(r'^af-packet:', line):
        in_afpacket = False

    if in_afpacket and re.match(r'\s+-\s+interface:\s+default', line):
        # Comment the line out
        line = line.replace('- interface:', '#- interface:')
    out.append(line)

with open(path, 'w') as f:
    f.writelines(out)
print("  af-packet default interface commented out")
PYEOF
    log_ok "AF_PACKET default interface entry disabled"

    # ── 3e: Add local.rules to rule-files list ────────────────────────────────
    log_step "Ensuring local.rules is in rule-files list..."
    if grep -q "^\s*-\s*local\.rules" "$SURICATA_YAML"; then
        log_ok "local.rules already present in rule-files"
    else
        # Append after the last existing - suricata.rules / - *.rules entry
        python3 - "$SURICATA_YAML" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    text = f.read()

# Find rule-files: block and append local.rules if not present
if 'local.rules' not in text:
    text = re.sub(
        r'(rule-files:.*?)(^\s*#|\Z)',
        lambda m: m.group(1) + '  - local.rules\n' + m.group(2),
        text,
        count=1,
        flags=re.MULTILINE | re.DOTALL
    )
with open(path, 'w') as f:
    f.write(text)
print("  local.rules appended to rule-files")
PYEOF
        log_ok "local.rules added to rule-files"
    fi

    # ── 3f: Validate configuration ────────────────────────────────────────────
    log_step "Validating Suricata configuration (dry run)..."
    VALIDATE_OUT=$(suricata -T -c "$SURICATA_YAML" -v 2>&1)
    if echo "$VALIDATE_OUT" | grep -q "successfully loaded"; then
        log_ok "Configuration validated: successfully loaded"
    else
        log_err "Suricata configuration validation FAILED:"
        echo "$VALIDATE_OUT" | tail -20 >&2
        exit 1
    fi
}

# ── STEP 4: CREATE LOCAL RULES FILE ──────────────────────────────────────────
create_rules_file() {
    log_section "Step 4 - Rule Directory and Local Rules File"

    log_step "Creating rules directory..."
    mkdir -p "$SURICATA_RULES_DIR"
    log_ok "Rules directory: $SURICATA_RULES_DIR"

    log_step "Creating local.rules file..."
    if [[ ! -f "$LOCAL_RULES" ]]; then
        cat > "$LOCAL_RULES" << 'EOF'
# =============================================================================
# local.rules - Custom Suricata Rules
# Mosudi I.O, FH Technikum Wien - IT Security Lab 2026
#
# Reload without restart:
#   sudo kill -USR2 $(cat /run/suricata.pid)
#
# SID range reserved for this lab: 9000001 – 9000099
# =============================================================================

# Add rules below this line:

EOF
        log_ok "local.rules created with header comment"
    else
        log_ok "local.rules already exists - leaving unchanged"
    fi

    chmod 644 "$LOCAL_RULES"
    log_ok "Permissions set: 644"

    log_step "Confirming rule file is referenced in suricata.yaml..."
    grep "local.rules" "$SURICATA_YAML" | while IFS= read -r line; do
        log_info "$line"
    done
}

# ── STEP 5: IPTABLES NFQUEUE RULES ───────────────────────────────────────────
configure_iptables_nfqueue() {
    log_section "Step 5 - iptables NFQUEUE Traffic Routing"

    # ── 5a: Flush ────────────────────────────────────────────────────────────
    log_step "Flushing existing filter and nat tables (clean baseline)..."
    iptables -F
    iptables -t nat -F
    log_ok "Tables flushed"

    # ── 5b: Restore NAT ──────────────────────────────────────────────────────
    log_step "Restoring NAT MASQUERADE rule..."
    iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    log_ok "NAT MASQUERADE: all → $WAN_IFACE"

    # ── 5c: ESTABLISHED/RELATED bypass ───────────────────────────────────────
    log_step "Inserting ESTABLISHED/RELATED bypass at FORWARD position 1..."
    iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
    log_ok "FORWARD rule 1: ACCEPT state ESTABLISHED,RELATED (performance bypass)"

    # ── 5d: NFQUEUE redirect ─────────────────────────────────────────────────
    log_step "Appending NFQUEUE redirect for all other forwarded traffic..."
    iptables -A FORWARD -j NFQUEUE --queue-num "$NFQUEUE_NUM"
    log_ok "FORWARD rule 2: NFQUEUE --queue-num $NFQUEUE_NUM"

    # ── 5e: Verify ───────────────────────────────────────────────────────────
    log_step "Verifying FORWARD chain:"
    iptables -L FORWARD -n -v --line-numbers | while IFS= read -r line; do
        log_info "$line"
    done

    # Check the two required rules are in place
    RULE1=$(iptables -L FORWARD -n --line-numbers | awk 'NR==3' | awk '{print $4}')
    RULE2=$(iptables -L FORWARD -n --line-numbers | awk 'NR==4' | awk '{print $3}')

    if [[ "$RULE1" == "ACCEPT" ]]; then
        log_ok "Rule 1 confirmed: ACCEPT (ESTABLISHED,RELATED)"
    else
        log_warn "Rule 1 may not be in expected position - verify output above"
    fi

    if [[ "$RULE2" == "NFQUEUE" ]]; then
        log_ok "Rule 2 confirmed: NFQUEUE"
    else
        log_warn "Rule 2 may not be in expected position - verify output above"
    fi

    # ── 5f: Persist ──────────────────────────────────────────────────────────
    log_step "Saving iptables rules for persistence..."
    netfilter-persistent save
    log_ok "Rules saved to /etc/iptables/rules.v4"
}

# ── STEP 6: SYSTEMD OVERRIDE ─────────────────────────────────────────────────
configure_systemd() {
    log_section "Step 6 - Systemd Service Override (NFQueue Mode)"

    log_step "Creating override directory..."
    mkdir -p "$SYSTEMD_OVERRIDE_DIR"
    log_ok "Directory: $SYSTEMD_OVERRIDE_DIR"

    log_step "Writing override.conf..."
    # The blank ExecStart= clears the inherited AF_PACKET command from the base unit.
    # The second ExecStart sets the NFQueue command with -q 0.
    tee "$SYSTEMD_OVERRIDE" > /dev/null << EOF
# Generated by suricata_setup.sh - $(date '+%Y-%m-%d %H:%M:%S')
# Overrides the default AF_PACKET launch to use NFQueue inline mode.
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q ${NFQUEUE_NUM} \\
    -c ${SURICATA_YAML} \\
    --pidfile /run/suricata.pid
EOF
    log_ok "Override written to $SYSTEMD_OVERRIDE"

    log_step "Reloading systemd daemon..."
    systemctl daemon-reload
    log_ok "systemd daemon reloaded"

    log_step "Verifying override is active (ExecStart lines from merged unit):"
    systemctl cat suricata.service | grep "ExecStart" | while IFS= read -r line; do
        log_output "$line"
    done

    # Confirm the final ExecStart contains -q
    EXEC_LINE=$(systemctl cat suricata.service | grep "ExecStart=/usr" | tail -1)
    if echo "$EXEC_LINE" | grep -q "\-q ${NFQUEUE_NUM}"; then
        log_ok "Override confirmed: Suricata will start with -q $NFQUEUE_NUM (NFQueue mode)"
    else
        log_err "Override may not have applied correctly. Check $SYSTEMD_OVERRIDE"
        exit 1
    fi
}

# ── STEP 7: START AND VERIFY SURICATA ────────────────────────────────────────
start_suricata() {
    log_section "Step 7 - Start and Verify Suricata"

    log_step "Starting Suricata service..."
    systemctl start suricata
    log_ok "systemctl start issued"

    # Allow Suricata time to initialise and bind to the queue
    log_step "Waiting 8 seconds for Suricata to initialise..."
    sleep 8

    # ── Service status ────────────────────────────────────────────────────────
    log_step "Service status:"
    systemctl status suricata --no-pager -l | while IFS= read -r line; do
        log_info "$line"
    done

    if systemctl is-active --quiet suricata; then
        log_ok "Suricata service is active"
    else
        log_err "Suricata failed to start. Showing last 30 journal lines:"
        journalctl -u suricata -n 30 --no-pager >&2
        exit 1
    fi

    # ── NFQ binding check ─────────────────────────────────────────────────────
    log_step "Checking suricata.log for NFQ queue binding..."
    # The log file may take a few extra seconds to be written
    for i in 1 2 3 4 5; do
        if [[ -f "$SURICATA_LOG" ]] && \
           grep -qi "nfq\|queue" "$SURICATA_LOG" 2>/dev/null; then
            break
        fi
        sleep 2
    done

    if [[ -f "$SURICATA_LOG" ]]; then
        NFQ_LINES=$(grep -i "nfq\|queue" "$SURICATA_LOG" 2>/dev/null || true)
        if [[ -n "$NFQ_LINES" ]]; then
            log_ok "NFQ log entries found:"
            echo "$NFQ_LINES" | while IFS= read -r line; do log_output "$line"; done
        else
            log_warn "No NFQ entries found in suricata.log yet (may still be initialising)"
            log_warn "Check later with: sudo grep -i 'nfq' $SURICATA_LOG"
        fi
    else
        log_warn "$SURICATA_LOG not found yet - Suricata may still be writing it"
    fi
}



# ── NEXT STEPS ────────────────────────────────────────────────────────────────
print_next_steps() {
    log_section "Setup Complete - Next Steps"
    echo -e "
  ${BOLD}Suricata is running in inline NFQueue IPS mode.${RESET}

  ${BOLD}Verify packet counter from a LAN client:${RESET}
    From Kali (10.10.10.10):
      ${CYAN}ping -c 10 8.8.8.8${RESET}
    On Orange Pi:
      ${CYAN}sudo iptables -L FORWARD -n -v${RESET}
      ${YELLOW}→ NFQUEUE rule packet counter must increase${RESET}

  ${BOLD}Monitor Suricata alerts in real time:${RESET}
    ${CYAN}sudo tail -f ${SURICATA_LOG_DIR}/fast.log${RESET}
    ${CYAN}sudo tail -f ${SURICATA_LOG_DIR}/eve.json | python3 -m json.tool${RESET}

  ${BOLD}Add detection rules:${RESET}
    Edit:  ${CYAN}sudo vi $LOCAL_RULES${RESET}
    Then reload without restart:
      ${CYAN}sudo kill -USR2 \$(cat /run/suricata.pid)${RESET}

  ${BOLD}Useful diagnostics:${RESET}
    ${CYAN}sudo systemctl status suricata${RESET}
    ${CYAN}sudo journalctl -u suricata -f${RESET}
    ${CYAN}sudo grep -i 'nfq\\|queue\\|error' $SURICATA_LOG${RESET}
    ${CYAN}sudo suricata -T -c $SURICATA_YAML -v${RESET}   # config check
    ${CYAN}sudo iptables -L FORWARD -n -v --line-numbers${RESET}

  ${BOLD}Emergency: restore connectivity if Suricata locks you out:${RESET}
    ${RED}sudo iptables -F && sudo iptables -t nat -F${RESET}
    ${RED}sudo iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE${RESET}
    ${RED}sudo iptables -A FORWARD -i $LAN_IFACE -o $WAN_IFACE -j ACCEPT${RESET}
    ${RED}sudo iptables -A FORWARD -i $WAN_IFACE -o $LAN_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT${RESET}
"
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "\n${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║   Suricata IPS Setup Script                              ║"
    echo "  ║   NFQueue Inline Mode                                    ║"
    echo "  ║   Orange Pi 5 / Ubuntu 24.04                             ║"
    echo "  ║   Mosudi I.O, FH Technikum Wien - IT Security Lab 2026   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  LAN:     ${BOLD}${LAN_IFACE}${RESET}  ($LAN_SUBNET)"
    echo -e "  WAN:     ${BOLD}${WAN_IFACE}${RESET}"
    echo -e "  NFQueue: ${BOLD}queue ${NFQUEUE_NUM}${RESET}"
    echo ""

    preflight_checks
    install_suricata
    configure_log_dir
    configure_yaml
    create_rules_file
    configure_iptables_nfqueue
    configure_systemd
    start_suricata
    #verify_traffic_counters
    #verify_all
    print_next_steps
}

main "$@"
