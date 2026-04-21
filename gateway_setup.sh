#!/usr/bin/env bash
# =============================================================================
# Gateway System Setup Script
# SBC: Single Board Computer — 
# Raspberry Pi, Orange Pi / Ubuntu 24.04 LTS / Debian 12
# FH Technikum Wien — IT Security Lab 2026
#
# Usage:
#   chmod +x gateway_setup.sh
#   sudo ./gateway_setup.sh
#
# What this script does:
#   1. System update & core package installation
#   2. Netplan static LAN / DHCP WAN configuration
#   3. IP forwarding (runtime + persistent)
#   4. iptables NAT + FORWARD rules + persistence
#   5. ISC DHCP server configuration and startup
#
# Customise the variables in the CONFIGURATION block below before running.
# =============================================================================

set -euo pipefail          # exit on error, undefined var, or pipe failure
IFS=$'\n\t'

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# Edit these values to match your environment before running the script.

LAN_IFACE="eth0"                    # LAN-facing interface (wired)
WAN_IFACE="wlan0"                   # WAN-facing interface (wireless uplink)

LAN_IP="10.10.10.1"                 # Static IP assigned to LAN interface
LAN_CIDR="10.10.10.1/24"            # With prefix length
LAN_SUBNET="10.10.10.0/24"          # Subnet in CIDR notation (for NAT rule)
LAN_NETMASK="255.255.255.0"         # Subnet mask (for DHCP config)
LAN_NETWORK="10.10.10.0"            # Network address (for DHCP config)

DHCP_RANGE_START="10.10.10.100"     # First IP in DHCP pool
DHCP_RANGE_END="10.10.10.200"       # Last IP in DHCP pool
DHCP_LEASE_DEFAULT=600              # Default lease time (seconds)
DHCP_LEASE_MAX=7200                 # Maximum lease time (seconds)

DNS_PRIMARY="9.9.9.9"               # Quad9 - primary DNS for clients: Security/malware-blocking focused
DNS_SECONDARY="1.1.1.1"             # Cloudflare — secondary DNS for clients
#DNS_TERTIARY="8.8.8.8"              # Google — tertiary DNS for clients

WIFI_SSID="Mio4" #"SSID_NAME"               # Wi-Fi network name for WAN uplink
WIFI_PASSWORD="ceffxpnfax"            # Wi-Fi password (WPA2-PSK)

NETPLAN_FILE="/etc/netplan/001-gateway.yaml"
SYSCTL_FILE="/etc/sysctl.d/99-gateway.conf"
DHCP_DEFAULTS="/etc/default/isc-dhcp-server"
DHCP_CONF="/etc/dhcp/dhcpd.conf"

# ── COLOUR OUTPUT ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log_section() { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; \
                echo -e "${BOLD}${BLUE}  $1${RESET}"; \
                echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; }
log_step()    { echo -e "${CYAN}  ▶  $1${RESET}"; }
log_ok()      { echo -e "${GREEN}  ✓  $1${RESET}"; }
log_warn()    { echo -e "${YELLOW}  ⚠  $1${RESET}"; }
log_err()     { echo -e "${RED}  ✗  $1${RESET}" >&2; }
log_cmd()     { echo -e "${YELLOW}      $ $1${RESET}"; }
log_info()    { echo -e "      $1"; }

# ── PRE-FLIGHT CHECKS ─────────────────────────────────────────────────────────
preflight_checks() {
    log_section "Pre-flight Checks"

    # Must run as root
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root.  Use: sudo ./gateway_setup.sh"
        exit 1
    fi
    log_ok "Running as root"

    # Confirm configuration is not still at placeholder values
    if [[ "$WIFI_SSID" == "SSID_NAME" || "$WIFI_PASSWORD" == "PASSWORD" ]]; then
        log_warn "WIFI_SSID / WIFI_PASSWORD are still set to placeholder values."
        log_warn "Edit the CONFIGURATION block at the top of this script before running."
        read -rp "      Continue anyway? [y/N]: " CONFIRM
        [[ "${CONFIRM,,}" == "y" ]] || { log_err "Aborted."; exit 1; }
    fi

    # Check for the expected network interfaces
    if ! ip link show "$LAN_IFACE" &>/dev/null; then
        log_err "LAN interface '$LAN_IFACE' not found.  Check LAN_IFACE in the config block."
        ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/://'
        exit 1
    fi
    log_ok "LAN interface $LAN_IFACE found"

    if ! ip link show "$WAN_IFACE" &>/dev/null; then
        log_warn "WAN interface '$WAN_IFACE' not found — it may appear after Netplan applies Wi-Fi config."
        log_warn "Continuing; NAT rule will be set regardless."
    else
        log_ok "WAN interface $WAN_IFACE found"
    fi

    # OS check
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        log_ok "OS: $PRETTY_NAME"
    fi

    log_ok "Pre-flight checks complete"
}

# ── STEP 1: SYSTEM UPDATE & PACKAGES ─────────────────────────────────────────
install_packages() {
    log_section "Step 1 — System Update & Package Installation"

    log_step "Updating package lists..."
    apt-get update -q
    log_ok "Package lists updated"

    log_step "Upgrading installed packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q
    log_ok "System upgraded"

    log_step "Removing unused packages..."
    apt-get autoremove -y -q
    log_ok "Autoremove complete"

    log_step "Installing core networking packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        vim \
        iproute2 \
        net-tools \
        iptables \
        iptables-persistent \
        netfilter-persistent \
        isc-dhcp-server \
        systemd-resolved
    log_ok "All packages installed"
}

# ── STEP 2: NETPLAN CONFIGURATION ─────────────────────────────────────────────
configure_netplan() {
    log_section "Step 2 — Netplan Network Configuration"

    # Remove conflicting netplan files so there is exactly one active config
    log_step "Removing any existing conflicting Netplan files..."
    for f in /etc/netplan/*.yaml; do
        if [[ "$f" != "$NETPLAN_FILE" ]]; then
            log_info "  Archiving: $f  →  ${f}.disabled"
            mv "$f" "${f}.disabled" 2>/dev/null || true
        fi
    done

    log_step "Writing Netplan configuration to $NETPLAN_FILE..."
    cat > "$NETPLAN_FILE" << EOF
# Generated by gateway_setup.sh — $(date '+%Y-%m-%d %H:%M:%S')
# LAN: $LAN_IFACE  WAN: $WAN_IFACE
network:
  version: 2
  renderer: networkd

  ethernets:
    ${LAN_IFACE}:
      dhcp4: no
      addresses:
        - ${LAN_CIDR}

  wifis:
    ${WAN_IFACE}:
      dhcp4: yes
      access-points:
        "${WIFI_SSID}":
          password: "${WIFI_PASSWORD}"
EOF

    # Netplan requires owner-read-only permissions on config files
    chmod 600 "$NETPLAN_FILE"
    log_ok "Netplan file written and permissions set (600)"

    log_step "Applying Netplan configuration..."
    netplan apply
    log_ok "Netplan applied"

    # Short wait for interfaces to come up
    sleep 3

    log_step "Verifying interface addresses..."
    LAN_ASSIGNED=$(ip -4 addr show "$LAN_IFACE" | awk '/inet / {print $2}' || true)
    if [[ "$LAN_ASSIGNED" == "${LAN_CIDR}" ]]; then
        log_ok "$LAN_IFACE assigned $LAN_ASSIGNED"
    else
        log_warn "$LAN_IFACE shows '$LAN_ASSIGNED' (expected ${LAN_CIDR}).  Check Netplan config."
    fi

    log_step "Current routing table:"
    ip route | while IFS= read -r line; do log_info "$line"; done
}

# ── STEP 3: IP FORWARDING ─────────────────────────────────────────────────────
enable_ip_forwarding() {
    log_section "Step 3 — IP Forwarding"

    log_step "Writing persistent sysctl rule to $SYSCTL_FILE..."
    echo "net.ipv4.ip_forward=1" > "$SYSCTL_FILE"
    log_ok "Sysctl file written"

    log_step "Applying sysctl settings..."
    sysctl -p "$SYSCTL_FILE"

    # Confirm
    FWD=$(sysctl -n net.ipv4.ip_forward)
    if [[ "$FWD" == "1" ]]; then
        log_ok "IP forwarding enabled (net.ipv4.ip_forward = 1)"
    else
        log_err "IP forwarding NOT enabled — check $SYSCTL_FILE"
        exit 1
    fi
}

# ── STEP 4: IPTABLES RULES ───────────────────────────────────────────────────
configure_iptables() {
    log_section "Step 4 — iptables NAT + Forwarding Rules"

    log_step "Flushing existing filter and nat rules (clean baseline)..."
    iptables -F
    iptables -t nat -F
    log_ok "Tables flushed"

    log_step "Setting default FORWARD policy to DROP (secure baseline)..."
    iptables -P FORWARD DROP
    log_ok "FORWARD policy: DROP"

    log_step "Adding NAT MASQUERADE rule for LAN subnet → WAN..."
    iptables -t nat -A POSTROUTING \
        -s "$LAN_SUBNET" \
        -o "$WAN_IFACE" \
        -j MASQUERADE
    log_ok "NAT MASQUERADE: $LAN_SUBNET → $WAN_IFACE"

    log_step "Adding FORWARD rule: LAN ($LAN_IFACE) → WAN ($WAN_IFACE)..."
    iptables -A FORWARD \
        -i "$LAN_IFACE" \
        -o "$WAN_IFACE" \
        -j ACCEPT
    log_ok "FORWARD ACCEPT: $LAN_IFACE → $WAN_IFACE"

    log_step "Adding FORWARD rule: WAN → LAN (ESTABLISHED/RELATED return traffic)..."
    iptables -A FORWARD \
        -i "$WAN_IFACE" \
        -o "$LAN_IFACE" \
        -m state --state ESTABLISHED,RELATED \
        -j ACCEPT
    log_ok "FORWARD ACCEPT: $WAN_IFACE → $LAN_IFACE (ESTABLISHED,RELATED)"

    log_step "Saving rules for persistence across reboots..."
    netfilter-persistent save
    log_ok "Rules saved to /etc/iptables/rules.v4"

    log_step "Current filter table (FORWARD chain):"
    iptables -L FORWARD -n -v --line-numbers | while IFS= read -r line; do log_info "$line"; done

    echo ""
    log_step "Current NAT table (POSTROUTING chain):"
    iptables -t nat -L POSTROUTING -n -v | while IFS= read -r line; do log_info "$line"; done
}

# ── STEP 5: DHCP SERVER ───────────────────────────────────────────────────────
configure_dhcp() {
    log_section "Step 5 — ISC DHCP Server Configuration"

    # Back up any existing dhcpd.conf
    if [[ -f "$DHCP_CONF" ]]; then
        BACKUP="${DHCP_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$DHCP_CONF" "$BACKUP"
        log_info "Existing dhcpd.conf backed up to $BACKUP"
    fi

    log_step "Configuring DHCP listening interface in $DHCP_DEFAULTS..."
    # Use sed to replace INTERFACESv4 line; handle both quoted and unquoted forms
    if grep -q 'INTERFACESv4' "$DHCP_DEFAULTS"; then
        sed -i "s|^INTERFACESv4=.*|INTERFACESv4=\"${LAN_IFACE}\"|" "$DHCP_DEFAULTS"
    else
        echo "INTERFACESv4=\"${LAN_IFACE}\"" >> "$DHCP_DEFAULTS"
    fi
    # Ensure IPv6 is not active (avoid startup errors if no IPv6 scope defined)
    if grep -q 'INTERFACESv6' "$DHCP_DEFAULTS"; then
        sed -i 's|^INTERFACESv6=.*|INTERFACESv6=""|' "$DHCP_DEFAULTS"
    else
        echo 'INTERFACESv6=""' >> "$DHCP_DEFAULTS"
    fi
    log_ok "DHCP listening interface set to $LAN_IFACE"

    log_step "Writing DHCP scope configuration to $DHCP_CONF..."
    cat > "$DHCP_CONF" << EOF
# Generated by gateway_setup.sh — $(date '+%Y-%m-%d %H:%M:%S')
# DHCP server for LAN interface: ${LAN_IFACE}

default-lease-time ${DHCP_LEASE_DEFAULT};
max-lease-time ${DHCP_LEASE_MAX};
authoritative;

subnet ${LAN_NETWORK} netmask ${LAN_NETMASK} {
    range ${DHCP_RANGE_START} ${DHCP_RANGE_END};
    option routers ${LAN_IP};
    option domain-name-servers ${DNS_PRIMARY}, ${DNS_SECONDARY};
    option broadcast-address $(echo "$LAN_IP" | awk -F. '{print $1"."$2"."$3".255"}');
}

# Add static host reservations below this line:
# host example-device {
#     hardware ethernet AA:BB:CC:DD:EE:FF;
#     fixed-address 10.10.10.10;
# }
EOF
    log_ok "DHCP configuration written"

    log_step "Enabling and starting isc-dhcp-server..."
    systemctl enable isc-dhcp-server
    systemctl restart isc-dhcp-server

    # Allow a moment for the service to settle
    sleep 2

    # Check service status
    if systemctl is-active --quiet isc-dhcp-server; then
        log_ok "isc-dhcp-server is active and running"
    else
        log_err "isc-dhcp-server failed to start.  Check logs with: journalctl -u isc-dhcp-server -n 30"
        journalctl -u isc-dhcp-server -n 20 --no-pager >&2
        exit 1
    fi

    log_step "DHCP server status:"
    systemctl status isc-dhcp-server --no-pager -l | while IFS= read -r line; do log_info "$line"; done
}

# ── VERIFICATION SUMMARY ──────────────────────────────────────────────────────
verify_all() {
    log_section "Verification Summary"

    local PASS=0
    local FAIL=0

    check() {
        local LABEL="$1"
        local RESULT="$2"
        local EXPECTED="$3"
        if [[ "$RESULT" == "$EXPECTED" ]]; then
            log_ok "$LABEL"
            ((PASS++)) || true
        else
            log_warn "$LABEL  (got: '$RESULT', expected: '$EXPECTED')"
            ((FAIL++)) || true
        fi
    }

    # IP forwarding
    check "IP forwarding enabled" \
        "$(sysctl -n net.ipv4.ip_forward)" "1"

    # LAN IP assigned
    check "LAN IP $LAN_CIDR on $LAN_IFACE" \
        "$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | awk '/inet / {print $2}' | head -1)" \
        "$LAN_CIDR"

    # NAT rule present
    NAT_COUNT=$(iptables -t nat -L POSTROUTING -n | grep -c "MASQUERADE" || true)
    check "NAT MASQUERADE rule present" "$NAT_COUNT" "1"

    # FORWARD policy
    check "FORWARD default policy DROP" \
        "$(iptables -L FORWARD | head -1 | awk '{print $4}' | tr -d ')')" "DROP"

    # DHCP service running
    check "isc-dhcp-server running" \
        "$(systemctl is-active isc-dhcp-server)" "active"

    # IP forwarding persisted
    check "Sysctl file exists ($SYSCTL_FILE)" \
        "$(test -f "$SYSCTL_FILE" && echo yes || echo no)" "yes"

    # iptables rules persisted
    check "iptables rules file exists (/etc/iptables/rules.v4)" \
        "$(test -f /etc/iptables/rules.v4 && echo yes || echo no)" "yes"

    echo ""
    echo -e "  Results: ${GREEN}${PASS} passed${RESET}  /  ${RED}${FAIL} failed${RESET}"
}

# ── PRINT NEXT STEPS ─────────────────────────────────────────────────────────
print_next_steps() {
    log_section "Setup Complete — Next Steps"
    echo -e "
  ${BOLD}Gateway is configured.  Connect a client to ${LAN_IFACE} and verify:${RESET}

  On client (e.g. Kali Linux):
    ${CYAN}sudo dhclient -v eth0${RESET}           # Request DHCP lease
    ${CYAN}ip addr show eth0${RESET}               # Confirm address in ${DHCP_RANGE_START}–${DHCP_RANGE_END}
    ${CYAN}ip route${RESET}                        # Confirm default via ${LAN_IP}
    ${CYAN}ping -c 4 ${LAN_IP}${RESET}             # Reach the gateway
    ${CYAN}ping -c 4 8.8.8.8${RESET}              # Reach internet through NAT
    ${CYAN}curl -s https://ifconfig.me${RESET}     # Confirm external IP

  On Orange Pi (monitor DHCP leases):
    ${CYAN}sudo journalctl -u isc-dhcp-server -f${RESET}

  ${BOLD}To add a static DHCP reservation:${RESET}
    Edit ${DHCP_CONF} and add:
      host <hostname> {
          hardware ethernet <MAC_ADDRESS>;
          fixed-address <DESIRED_IP>;
      }
    Then: ${CYAN}sudo systemctl restart isc-dhcp-server${RESET}

  ${BOLD}Useful diagnostics:${RESET}
    ${CYAN}ip addr && ip route${RESET}             # Interface and routing state
    ${CYAN}sudo iptables -L -n -v${RESET}          # Filter rules
    ${CYAN}sudo iptables -t nat -L -n -v${RESET}   # NAT rules
    ${CYAN}sudo systemctl status isc-dhcp-server${RESET}
    ${CYAN}sysctl net.ipv4.ip_forward${RESET}

  ${BOLD}When ready to install Suricata IPS, run the IPS setup script.${RESET}
"
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "\n${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║   Gateway Setup Script                       ║"
    echo "  ║    Raspberry Pi / Orange Pi  /               ║"
            ║   Ubuntu 24.04 / Debian 12                   ║"
    echo "  ║   FH Technikum Wien — IT Security Lab 2026   ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  LAN:  ${BOLD}${LAN_IFACE}${RESET}  →  ${LAN_CIDR}"
    echo -e "  WAN:  ${BOLD}${WAN_IFACE}${RESET}  →  DHCP (SSID: ${WIFI_SSID})"
    echo -e "  DHCP: ${DHCP_RANGE_START} – ${DHCP_RANGE_END}"
    echo -e "  DNS:  ${DNS_PRIMARY}, ${DNS_SECONDARY}"
    echo ""

    preflight_checks
    install_packages
    configure_netplan
    enable_ip_forwarding
    configure_iptables
    configure_dhcp
    verify_all
    print_next_steps
}

main "$@"
