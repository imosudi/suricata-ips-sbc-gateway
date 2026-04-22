#!/bin/sh
# =============================================================================
# Suricata IPS Setup Script (POSIX-compliant)
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
# =============================================================================

set -u  # Only use -u (no -e or -o pipefail for POSIX compliance)
IFS='
    '

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
    echo ""
    printf "${BOLD}${BLUE}══════════════════════════════════════════${RESET}\n"
    printf "${BOLD}${BLUE}  %s${RESET}\n" "$1"
    printf "${BOLD}${BLUE}══════════════════════════════════════════${RESET}\n"
}
log_step()    { printf "${CYAN}  ▶  %s${RESET}\n" "$1"; }
log_ok()      { printf "${GREEN}  ✓  %s${RESET}\n" "$1"; }
log_warn()    { printf "${YELLOW}  ⚠  %s${RESET}\n" "$1"; }
log_err()     { printf "${RED}  ✗  %s${RESET}\n" "$1" >&2; }
log_info()    { printf "      %s\n" "$1"; }
log_output()  { printf "${YELLOW}      %s${RESET}\n" "$1"; }

# ── PRE-FLIGHT CHECKS ─────────────────────────────────────────────────────────
preflight_checks() {
    log_section "Pre-flight Checks"

    # Check if running as root (POSIX-compliant way)
    if [ "$(id -u)" -ne 0 ]; then
        log_err "Run as root: sudo ./suricata_setup.sh"
        exit 1
    fi
    log_ok "Running as root"

    # Require gateway to be configured first
    if ! sysctl -n net.ipv4.ip_forward | grep -q "^1$"; then
        log_err "IP forwarding is not enabled. Run gateway_setup.sh first."
        exit 1
    fi
    log_ok "IP forwarding is enabled (gateway_setup.sh prerequisite met)"

    if ip link show "$LAN_IFACE" >/dev/null 2>&1; then
        log_ok "LAN interface $LAN_IFACE present"
    else
        log_err "LAN interface $LAN_IFACE not found"
        exit 1
    fi

    if ip link show "$WAN_IFACE" >/dev/null 2>&1; then
        log_ok "WAN interface $WAN_IFACE present"
    else
        log_warn "WAN interface $WAN_IFACE not found - NAT rule will still be applied"
    fi
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
    NFQ_LINE=$(suricata --build-info 2>&1 | grep -i "NFQueue support" || echo "")
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
    chown root:root "$SURICATA_LOG_DIR"
    chmod 750 "$SURICATA_LOG_DIR"
    log_ok "Log directory: $SURICATA_LOG_DIR  (750, root:root)"
}

# ── STEP 3: CONFIGURE suricata.yaml ───────────────────────────────────────────
configure_yaml() {
    log_section "Step 3 - suricata.yaml Configuration"

    # ── 3a: Backup ───────────────────────────────────────────────────────────
    log_step "Backing up original configuration..."
    if [ ! -f "$SURICATA_YAML_BAK" ]; then
        cp "$SURICATA_YAML" "$SURICATA_YAML_BAK"
        log_ok "Backup saved to $SURICATA_YAML_BAK"
    else
        log_ok "Backup already exists at $SURICATA_YAML_BAK - skipping"
    fi

    # ── 3b: HOME_NET ─────────────────────────────────────────────────────────
    log_step "Setting HOME_NET to [$LAN_SUBNET]..."
    if grep -q "HOME_NET:" "$SURICATA_YAML"; then
        sed -i "s|^\s*HOME_NET:.*|HOME_NET: \"[$LAN_SUBNET]\"|" "$SURICATA_YAML"
        log_ok "HOME_NET set to \"[$LAN_SUBNET]\""
    else
        log_err "HOME_NET key not found in $SURICATA_YAML"
        exit 1
    fi

    # ── 3c: NFQ mode ─────────────────────────────────────────────────────────
    log_step "Configuring NFQ mode block..."
    python3 - "$SURICATA_YAML" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    text = f.read()

# Replace the nfq: block
nfq_block = (
    "nfq:\n"
    "  mode: accept\n"
    "  repeat-mark: 1\n"
    "  repeat-mask: 1\n"
    "  bypass: yes\n"
)
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
    log_ok "NFQ block configured"

    # ── 3d: Disable AF_PACKET ───────────────────────────────────────────────
    log_step "Disabling AF_PACKET default interface entry..."
    python3 - "$SURICATA_YAML" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

in_afpacket = False
out = []
for line in lines:
    if re.match(r'^af-packet:', line):
        in_afpacket = True
    elif re.match(r'^\S', line) and not re.match(r'^af-packet:', line):
        in_afpacket = False

    if in_afpacket and re.match(r'\s+-\s+interface:\s+default', line):
        line = line.replace('- interface:', '#- interface:')
    out.append(line)

with open(path, 'w') as f:
    f.writelines(out)
print("  af-packet default interface commented out")
PYEOF
    log_ok "AF_PACKET interface disabled"

    # ── 3e: Add local.rules ────────────────────────────────────────────────
    log_step "Ensuring local.rules is in rule-files list..."
    if grep -q "local\.rules" "$SURICATA_YAML"; then
        log_ok "local.rules already present in rule-files"
    else
        python3 - "$SURICATA_YAML" << 'PYEOF'
import sys, re

path = sys.argv[1]
with open(path) as f:
    text = f.read()

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

    # ── 3f: Validate ────────────────────────────────────────────────────────
    log_step "Validating Suricata configuration..."
    if suricata -T -c "$SURICATA_YAML" -v 2>&1 | grep -q "successfully loaded"; then
        log_ok "Configuration validated"
    else
        log_err "Configuration validation FAILED"
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
    if [ ! -f "$LOCAL_RULES" ]; then
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
        log_ok "local.rules created"
    else
        log_ok "local.rules already exists"
    fi

    chmod 644 "$LOCAL_RULES"
    log_ok "Permissions set: 644"
}

# ── STEP 5: IPTABLES NFQUEUE RULES ───────────────────────────────────────────
configure_iptables_nfqueue() {
    log_section "Step 5 - iptables NFQUEUE Traffic Routing"

    log_step "Flushing existing tables..."
    iptables -F
    iptables -t nat -F
    log_ok "Tables flushed"

    log_step "Restoring NAT MASQUERADE rule..."
    iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE
    log_ok "NAT MASQUERADE configured"

    log_step "Adding ESTABLISHED/RELATED bypass..."
    iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
    log_ok "Bypass rule added"

    log_step "Adding NFQUEUE redirect..."
    iptables -A FORWARD -j NFQUEUE --queue-num "$NFQUEUE_NUM"
    log_ok "NFQUEUE redirect added"

    log_step "Saving iptables rules..."
    netfilter-persistent save
    log_ok "Rules saved"
}

# ── STEP 6: SYSTEMD OVERRIDE ─────────────────────────────────────────────────
configure_systemd() {
    log_section "Step 6 - Systemd Service Override"

    log_step "Creating override directory..."
    mkdir -p "$SYSTEMD_OVERRIDE_DIR"
    log_ok "Directory created"

    log_step "Writing override.conf..."
    cat > "$SYSTEMD_OVERRIDE" << EOF
# Generated by suricata_setup.sh - $(date '+%Y-%m-%d %H:%M:%S')
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q ${NFQUEUE_NUM} \\
    -c ${SURICATA_YAML} \\
    --pidfile /run/suricata.pid
EOF
    log_ok "Override written"

    log_step "Reloading systemd..."
    systemctl daemon-reload
    log_ok "Systemd reloaded"
}

# ── STEP 7: START AND VERIFY SURICATA ────────────────────────────────────────
start_suricata() {
    log_section "Step 7 - Start and Verify Suricata"

    log_step "Starting Suricata service..."
    systemctl start suricata
    log_ok "Start command issued"

    log_step "Waiting for Suricata to initialize..."
    sleep 8

    if systemctl is-active --quiet suricata; then
        log_ok "Suricata service is active"
    else
        log_err "Suricata failed to start"
        journalctl -u suricata -n 30 --no-pager
        exit 1
    fi
}

# ── NEXT STEPS ────────────────────────────────────────────────────────────────
print_next_steps() {
    log_section "Setup Complete - Next Steps"
    echo "
  ${BOLD}Suricata is running in inline NFQueue IPS mode.${RESET}

  ${BOLD}Verify functionality:${RESET}
    From a client: ${CYAN}ping -c 4 8.8.8.8${RESET}
    Check counters: ${CYAN}sudo iptables -L FORWARD -n -v${RESET}

  ${BOLD}Monitor alerts:${RESET}
    ${CYAN}sudo tail -f ${SURICATA_LOG_DIR}/fast.log${RESET}

  ${BOLD}Add rules:${RESET}
    Edit: ${CYAN}sudo vi $LOCAL_RULES${RESET}
    Reload: ${CYAN}sudo kill -USR2 \$(cat /run/suricata.pid)${RESET}

  ${BOLD}Diagnostics:${RESET}
    ${CYAN}sudo systemctl status suricata${RESET}
    ${CYAN}sudo journalctl -u suricata -f${RESET}
"
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo ""
    printf "${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║   Suricata IPS Setup Script                              ║"
    echo "  ║   NFQueue Inline Mode                                    ║"
    echo "  ║   Orange Pi 5 / Ubuntu 24.04                             ║"
    echo "  ║   Mosudi I.O, FH Technikum Wien - IT Security Lab 2026   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    printf "${RESET}\n"
    echo "  LAN:     ${BOLD}${LAN_IFACE}${RESET}  ($LAN_SUBNET)"
    echo "  WAN:     ${BOLD}${WAN_IFACE}${RESET}"
    echo "  NFQueue: ${BOLD}queue ${NFQUEUE_NUM}${RESET}"
    echo ""

    preflight_checks
    install_suricata
    configure_log_dir
    configure_yaml
    create_rules_file
    configure_iptables_nfqueue
    configure_systemd
    start_suricata
    print_next_steps
}

main "$@"